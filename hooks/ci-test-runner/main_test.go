package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	// env returns a valid base configuration. m changes it; "" unsets a key.
	env := func(m map[string]string) func(string) string {
		base := map[string]string{
			"CI_TEST_RUNNER_SECRET": "s",
			"ADO_ORG":               "example-org",
			"ADO_PROJECT":           "example-project",
			"ADO_PAT":               "pat",
			"TEST_PIPELINES":        `{"smoke": {"pipeline_id": 42}}`,
		}
		for k, v := range m {
			base[k] = v
		}
		return func(k string) string { return base[k] }
	}

	tests := []struct {
		env     map[string]string
		check   func(t *testing.T, c config)
		name    string
		wantErr string
	}{
		{
			name: "defaults",
			env:  nil,
			check: func(t *testing.T, c config) {
				if c.ListenAddr != ":8080" || c.PipelineSourceBranch != "" || c.ADOAuth != authPAT || c.MaxRunningJobs != 0 {
					t.Errorf("config = %+v", c)
				}
				if c.PollInterval != 15*time.Second || c.TestTimeout != 60*time.Minute ||
					c.JobRetention != 24*time.Hour || c.ShutdownTimeout != 30*time.Second {
					t.Errorf("durations = %s %s %s %s", c.PollInterval, c.TestTimeout, c.JobRetention, c.ShutdownTimeout)
				}
				if c.WaitLogInterval != time.Minute || c.MaxLogBytes != defaultMaxLogBytes || c.AllowUnsigned ||
					c.PollErrorWindow != 10*time.Minute || c.MaxPollBackoff != 2*time.Minute {
					t.Errorf("config = %+v", c)
				}
				if len(c.Suites) != 1 || c.Suites["smoke"].PipelineID != 42 {
					t.Errorf("suites = %+v", c.Suites)
				}
			},
		},
		{
			name: "custom values",
			env: map[string]string{
				"LISTEN_ADDR":              ":9000",
				"PIPELINE_SOURCE_BRANCH":   "refs/heads/release/1.0",
				"POLL_INTERVAL_SECONDS":    "5",
				"TEST_TIMEOUT_MINUTES":     "30",
				"JOB_RETENTION_HOURS":      "2",
				"SHUTDOWN_TIMEOUT_SECONDS": "0",
				"TEST_PIPELINES":           `{"smoke": {"pipeline_id": 42}, "full": {"pipeline_id": 43, "source_branch": "refs/heads/tests"}}`,
			},
			check: func(t *testing.T, c config) {
				if c.ListenAddr != ":9000" || c.PipelineSourceBranch != "refs/heads/release/1.0" {
					t.Errorf("config = %+v", c)
				}
				if c.PollInterval != 5*time.Second || c.TestTimeout != 30*time.Minute ||
					c.JobRetention != 2*time.Hour || c.ShutdownTimeout != 0 {
					t.Errorf("durations = %s %s %s %s", c.PollInterval, c.TestTimeout, c.JobRetention, c.ShutdownTimeout)
				}
				if f := c.Suites["full"]; f.PipelineID != 43 || f.SourceBranch != "refs/heads/tests" || f.TemplateParameters != nil {
					t.Errorf("suites = %+v", c.Suites)
				}
				if got := strings.Join(c.suiteNames(), ","); got != "full,smoke" {
					t.Errorf("suiteNames = %q", got)
				}
			},
		},
		{
			name: "invalid numbers fall back",
			env:  map[string]string{"POLL_INTERVAL_SECONDS": "0", "TEST_TIMEOUT_MINUTES": "x", "JOB_RETENTION_HOURS": "-1"},
			check: func(t *testing.T, c config) {
				if c.PollInterval != 15*time.Second || c.TestTimeout != 60*time.Minute || c.JobRetention != 24*time.Hour {
					t.Errorf("durations = %s %s %s", c.PollInterval, c.TestTimeout, c.JobRetention)
				}
			},
		},
		{name: "no secret", env: map[string]string{"CI_TEST_RUNNER_SECRET": ""}, wantErr: "CI_TEST_RUNNER_SECRET"},
		{
			name: "no secret with allow unsigned",
			env:  map[string]string{"CI_TEST_RUNNER_SECRET": "", "ALLOW_UNSIGNED": "true"},
			check: func(t *testing.T, c config) {
				if !c.AllowUnsigned || c.Secret != "" {
					t.Errorf("config = %+v", c)
				}
			},
		},
		{name: "no org", env: map[string]string{"ADO_ORG": ""}, wantErr: "ADO_ORG"},
		{name: "no project", env: map[string]string{"ADO_PROJECT": ""}, wantErr: "ADO_PROJECT"},
		{name: "no pipelines", env: map[string]string{"TEST_PIPELINES": ""}, wantErr: "TEST_PIPELINES is not set"},
		{name: "invalid json", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipeline_id": 42}`}, wantErr: "not a valid JSON"},
		{name: "array", env: map[string]string{"TEST_PIPELINES": `[{"pipeline_id": 42}]`}, wantErr: "not a valid JSON"},
		{name: "empty object", env: map[string]string{"TEST_PIPELINES": `{}`}, wantErr: "at least one suite"},
		{name: "null", env: map[string]string{"TEST_PIPELINES": `null`}, wantErr: "at least one suite"},
		{name: "trailing data", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipeline_id": 42}} x`}, wantErr: "data after"},
		{name: "unknown field", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipelineId": 42}}`}, wantErr: "not a valid JSON"},
		{name: "pipeline id as string", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipeline_id": "42"}}`}, wantErr: "not a valid JSON"},
		{name: "no pipeline id", env: map[string]string{"TEST_PIPELINES": `{"smoke": {}}`}, wantErr: "positive pipeline_id"},
		{name: "negative pipeline id", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipeline_id": -1}}`}, wantErr: "positive pipeline_id"},
		{name: "upper-case suite name", env: map[string]string{"TEST_PIPELINES": `{"Smoke": {"pipeline_id": 42}}`}, wantErr: "suite name"},
		{name: "long suite name", env: map[string]string{"TEST_PIPELINES": `{"` + strings.Repeat("a", 33) + `": {"pipeline_id": 42}}`}, wantErr: "suite name"},
		{name: "suite name with leading dash", env: map[string]string{"TEST_PIPELINES": `{"-smoke": {"pipeline_id": 42}}`}, wantErr: "suite name"},
		{name: "bad suite source branch", env: map[string]string{"TEST_PIPELINES": `{"smoke": {"pipeline_id": 42, "source_branch": "main; rm"}}`}, wantErr: "source_branch"},
		{name: "bad pipeline source branch", env: map[string]string{"PIPELINE_SOURCE_BRANCH": "refs/heads/../x"}, wantErr: "PIPELINE_SOURCE_BRANCH"},
		{
			name: "workload identity when client id is set",
			env:  map[string]string{"AZURE_CLIENT_ID": "client", "ADO_PAT": ""},
			check: func(t *testing.T, c config) {
				if c.ADOAuth != authWorkloadIdentity {
					t.Errorf("ADOAuth = %q", c.ADOAuth)
				}
			},
		},
		{
			name: "explicit pat wins over workload identity",
			env:  map[string]string{"AZURE_CLIENT_ID": "client", "ADO_AUTH": "pat"},
			check: func(t *testing.T, c config) {
				if c.ADOAuth != authPAT {
					t.Errorf("ADOAuth = %q", c.ADOAuth)
				}
			},
		},
		{name: "unknown auth mode", env: map[string]string{"ADO_AUTH": "basic"}, wantErr: "ADO_AUTH must be"},
		{name: "no credentials", env: map[string]string{"ADO_PAT": ""}, wantErr: "no Azure DevOps credentials"},
		{name: "pat mode without pat", env: map[string]string{"ADO_AUTH": "pat", "ADO_PAT": ""}, wantErr: "ADO_PAT is not set"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadConfig(env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, cfg)
		})
	}
}

func TestValidators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fn    func(string) bool
		name  string
		value string
		want  bool
	}{
		{validLabel, "label", "demo", true},
		{validLabel, "label with dash", "stack-demo-alice", true},
		{validLabel, "label 63", strings.Repeat("a", 63), true},
		{validLabel, "label 64", strings.Repeat("a", 64), false},
		{validLabel, "label upper", "Demo", false},
		{validLabel, "label trailing dash", "demo-", false},
		{validLabel, "label leading dash", "-demo", false},
		{validLabel, "label dot", "de.mo", false},
		{validLabel, "label empty", "", false},
		{validLabel, "label space", "de mo", false},
		{validBranch, "branch", "feature/login", true},
		{validBranch, "branch dots", "release/1.2.3", true},
		{validBranch, "branch dot dot", "a/../b", false},
		{validBranch, "branch leading dash", "-x", false},
		{validBranch, "branch leading slash", "/x", false},
		{validBranch, "branch shell", "x;rm", false},
		{validBranch, "branch dollar", "$(x)", false},
		{validBranch, "branch space", "a b", false},
		{validBranch, "branch long", strings.Repeat("a", 251), false},
		{validRef, "ref", "refs/heads/main", true},
		{validRef, "ref tag", "refs/tags/v1.0.0", true},
		{validRef, "ref no prefix", "main", false},
		{validRef, "ref double slash", "refs/heads//main", false},
		{validRef, "ref trailing slash", "refs/heads/", false},
		{validRef, "ref dot dot", "refs/heads/../x", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.fn(tt.value); got != tt.want {
				t.Errorf("%s(%q) = %v, want %v", tt.name, tt.value, got, tt.want)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()
	body := []byte(`{"kind":"ActionRequest"}`)
	good := sign("s3cret", body)

	tests := []struct {
		name          string
		secret        string
		sig           string
		allowUnsigned bool
		want          bool
	}{
		{"valid", "s3cret", good, false, true},
		{"wrong secret", "other", good, false, false},
		{"missing", "s3cret", "", false, false},
		{"missing with allow unsigned", "s3cret", "", true, false},
		{"no prefix", "s3cret", strings.TrimPrefix(good, "sha256="), false, false},
		{"upper-case hex", "s3cret", "sha256=" + strings.ToUpper(strings.TrimPrefix(good, "sha256=")), false, false},
		{"no secret fails closed", "", "", false, false},
		{"no secret with allow unsigned", "", "", true, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := verifySignature(tt.secret, tt.allowUnsigned, body, tt.sig); got != tt.want {
				t.Errorf("verifySignature = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	rr := e.getURI(t, "/healthz", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if e.cred.count(adoScope) != 0 {
		t.Error("/healthz made an external call")
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()

	t.Run("ready", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, nil)
		rr := e.getURI(t, "/readyz", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if e.cred.count(adoScope) != 1 {
			t.Errorf("token calls = %d", e.cred.count(adoScope))
		}
	})

	t.Run("credential fails", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, nil)
		e.cred.setErr(errFake)
		rr := e.getURI(t, "/readyz", "")
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "no Azure DevOps token") {
			t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		// The detail goes to the pod log only.
		if strings.Contains(rr.Body.String(), errFake.Error()) {
			t.Errorf("body %s has the error detail", rr.Body.String())
		}
	})

	t.Run("no ADO auth", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, func(c *config) { c.ADOAuth = "" })
		rr := e.getURI(t, "/readyz", "")
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// POST /action
// ---------------------------------------------------------------------------

func TestAction_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	if rr := e.getURI(t, "/action", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /action status = %d", rr.Code)
	}
}

func TestAction_Signature(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.Secret = "s3cret" })
	inst := testInstance()
	body := actionBody(&inst, map[string]any{"suite": "smoke"})
	other := actionBody(&InstanceRef{ID: "i2", Name: "x", Namespace: "y", Branch: "b", Status: "running"}, map[string]any{"suite": "smoke"})

	tests := []struct {
		name string
		sig  string
		want int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"bad", "sha256=bad", http.StatusUnauthorized},
		{"wrong secret", sign("other", body), http.StatusUnauthorized},
		{"signature of another body", sign("s3cret", other), http.StatusUnauthorized},
		{"valid", sign("s3cret", body), http.StatusAccepted},
	}
	for _, tt := range tests {
		rr := e.post(t, body, tt.sig)
		if rr.Code != tt.want {
			t.Errorf("%s: status = %d, want %d, body = %s", tt.name, rr.Code, tt.want, rr.Body.String())
		}
	}
	if n, _, _ := e.ado.counts(); n != 1 {
		t.Errorf("queued = %d, want 1", n)
	}
}

func TestAction_BodyTooLarge(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	rr := e.post(t, []byte(strings.Repeat(" ", int(maxRequestBodySize)+1)), "")
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestAction_Timestamp(t *testing.T) {
	t.Parallel()
	inst := testInstance()
	tests := []struct {
		ts        time.Time
		name      string
		requestID string
		secret    string
		want      int
	}{
		{name: "now", ts: time.Now(), requestID: "r", secret: "s3cret", want: http.StatusAccepted},
		{name: "4 minutes old", ts: time.Now().Add(-4 * time.Minute), requestID: "r", secret: "s3cret", want: http.StatusAccepted},
		{name: "6 minutes old", ts: time.Now().Add(-6 * time.Minute), requestID: "r", secret: "s3cret", want: http.StatusUnauthorized},
		{name: "6 minutes in the future", ts: time.Now().Add(6 * time.Minute), requestID: "r", secret: "s3cret", want: http.StatusUnauthorized},
		{name: "no timestamp with a secret", requestID: "r", secret: "s3cret", want: http.StatusUnauthorized},
		{name: "no request_id with a secret", ts: time.Now(), secret: "s3cret", want: http.StatusUnauthorized},
		{name: "no timestamp and no request_id without a secret", want: http.StatusAccepted},
		{name: "long request_id", ts: time.Now(), requestID: strings.Repeat("r", 129), secret: "s3cret", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, func(c *config) { c.Secret = tt.secret })
			req := map[string]any{"kind": "ActionRequest", "instance": inst, "parameters": map[string]any{"suite": "smoke"}}
			if !tt.ts.IsZero() {
				req["timestamp"] = tt.ts
			}
			if tt.requestID != "" {
				req["request_id"] = tt.requestID
			}
			body, _ := json.Marshal(req)
			if rr := e.post(t, body, sign(tt.secret, body)); rr.Code != tt.want {
				t.Errorf("status = %d, want %d, body = %s", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

func TestAction_ReplayRefused(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.Secret = "s3cret" })
	inst := testInstance()
	body := actionBody(&inst, map[string]any{"suite": "smoke"})
	if rr := e.post(t, body, sign("s3cret", body)); rr.Code != http.StatusAccepted {
		t.Fatalf("first: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	rr := e.post(t, body, sign("s3cret", body))
	if rr.Code != http.StatusConflict || errorText(t, rr) != "request_id was already received" {
		t.Errorf("replay: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if n, _, _ := e.ado.counts(); n != 1 {
		t.Errorf("queued = %d, want 1", n)
	}
}

func TestReplayCache(t *testing.T) {
	t.Parallel()
	c := newReplayCache()
	now := time.Now()
	if c.seenBefore("a", now) {
		t.Error("new id seen before")
	}
	if !c.seenBefore("a", now.Add(9*time.Minute)) {
		t.Error("id not remembered for 9 minutes")
	}
	if c.seenBefore("a", now.Add(11*time.Minute)) {
		t.Error("id remembered after 10 minutes")
	}
	// The purge removes old entries.
	c.seenBefore("b", now)
	c.seenBefore("c", now.Add(30*time.Minute))
	if _, ok := c.seen["b"]; ok {
		t.Error("old entry not purged")
	}
}

func TestAction_BadRequests(t *testing.T) {
	t.Parallel()
	with := func(fn func(*InstanceRef)) *InstanceRef {
		inst := testInstance()
		fn(&inst)
		return &inst
	}
	smoke := map[string]any{"suite": "smoke"}
	tests := []struct {
		inst    *InstanceRef
		params  map[string]any
		name    string
		raw     string
		wantMsg string
		want    int
	}{
		{name: "invalid json", raw: `{"instance":`, want: http.StatusBadRequest, wantMsg: "invalid json"},
		{name: "invalid timestamp", raw: `{"timestamp":"yesterday"}`, want: http.StatusBadRequest, wantMsg: "invalid json"},
		{name: "no instance", inst: nil, params: smoke, want: http.StatusBadRequest, wantMsg: "no instance"},
		{name: "no instance id", inst: with(func(i *InstanceRef) { i.ID = "" }), params: smoke, want: http.StatusBadRequest, wantMsg: "no instance"},
		{name: "no parameters", inst: with(func(*InstanceRef) {}), params: nil, want: http.StatusBadRequest, wantMsg: "Select a test suite (parameter suite). Suites: full, smoke"},
		{name: "empty suite", inst: with(func(*InstanceRef) {}), params: map[string]any{"suite": " "}, want: http.StatusBadRequest, wantMsg: "Select a test suite"},
		{name: "suite not a string", inst: with(func(*InstanceRef) {}), params: map[string]any{"suite": 1}, want: http.StatusBadRequest, wantMsg: "must be a string"},
		{name: "unknown suite", inst: with(func(*InstanceRef) {}), params: map[string]any{"suite": "nightly"}, want: http.StatusBadRequest, wantMsg: `Unknown suite "nightly". Suites: full, smoke`},
		{name: "long unknown suite is cut", inst: with(func(*InstanceRef) {}), params: map[string]any{"suite": strings.Repeat("x", 100)}, want: http.StatusBadRequest, wantMsg: strings.Repeat("x", 40) + `..."`},
		{name: "invalid name", inst: with(func(i *InstanceRef) { i.Name = "Demo;rm" }), params: smoke, want: http.StatusBadRequest, wantMsg: "stack name"},
		{name: "long name", inst: with(func(i *InstanceRef) { i.Name = strings.Repeat("a", 64) }), params: smoke, want: http.StatusBadRequest, wantMsg: "stack name"},
		{name: "invalid namespace", inst: with(func(i *InstanceRef) { i.Namespace = "stack_demo" }), params: smoke, want: http.StatusBadRequest, wantMsg: "namespace"},
		{name: "invalid branch", inst: with(func(i *InstanceRef) { i.Branch = "x$(id)" }), params: smoke, want: http.StatusBadRequest, wantMsg: "branch is not allowed"},
		{name: "branch with dot dot", inst: with(func(i *InstanceRef) { i.Branch = "a/../b" }), params: smoke, want: http.StatusBadRequest, wantMsg: "branch is not allowed"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			body := []byte(tt.raw)
			if tt.raw == "" {
				body = actionBody(tt.inst, tt.params)
			}
			rr := e.post(t, body, "")
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", rr.Code, tt.want, rr.Body.String())
			}
			if msg := errorText(t, rr); !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", msg, tt.wantMsg)
			}
			if n, _, _ := e.ado.counts(); n != 0 {
				t.Errorf("queued = %d, want 0", n)
			}
		})
	}
}

func TestAction_NotDeployed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status string
		want   string
	}{
		{"draft", "Deploy the stack first (status: draft)"},
		{"stopped", "Deploy the stack first (status: stopped)"},
		{"stopping", "Deploy the stack first (status: stopping)"},
		{"cleaning", "Deploy the stack first (status: cleaning)"},
		{"error", "Deploy the stack first (status: error)"},
		{"queued", "Wait until the stack is running (status: queued)"},
		{"deploying", "Wait until the stack is running (status: deploying)"},
		{"stabilizing", "Wait until the stack is running (status: stabilizing)"},
		{"", "Deploy the stack first (status: unknown)"},
		{"<b>x</b>", "Deploy the stack first (status: unknown)"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			inst := testInstance()
			inst.Status = tt.status
			rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
			if rr.Code != http.StatusConflict || errorText(t, rr) != tt.want {
				t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			if n, _, _ := e.ado.counts(); n != 0 {
				t.Errorf("queued = %d, want 0", n)
			}
		})
	}
}

func TestAction_PartialIsAccepted(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	inst := testInstance()
	inst.Status = "partial"
	if rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), ""); rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestAction_QueueRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wantParams map[string]string
		name       string
		suite      string
		branch     string
		wantSource string
		wantDef    int
	}{
		{
			name: "default source branch", suite: "smoke", branch: "feature/login",
			wantDef: 42, wantSource: "refs/heads/main",
			wantParams: map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "branch": "feature/login", "suite": "smoke"},
		},
		{
			name: "suite source branch", suite: "full", branch: "refs/heads/feature/login",
			wantDef: 43, wantSource: "refs/heads/release",
			wantParams: map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "branch": "feature/login", "suite": "full"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			inst := testInstance()
			inst.Branch = tt.branch
			rr := e.post(t, actionBody(&inst, map[string]any{"suite": tt.suite, "extra": "ignored"}), "")
			if rr.Code != http.StatusAccepted {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			resp := decodeAction(t, rr)
			if !regexp.MustCompile(`^job-[0-9a-f]{32}$`).MatchString(resp.JobID) {
				t.Errorf("job_id = %q", resp.JobID)
			}
			if resp.Status != "started" || resp.BuildID != 101 || resp.BuildURL != e.ado.webURL(101) || resp.Suite != tt.suite || resp.Message != "" {
				t.Errorf("response = %+v", resp)
			}

			queued := e.ado.queuedList()
			if len(queued) != 1 {
				t.Fatalf("queued = %d", len(queued))
			}
			q := queued[0]
			if q.Definition.ID != tt.wantDef || q.SourceBranch != tt.wantSource {
				t.Errorf("definition = %d, sourceBranch = %q", q.Definition.ID, q.SourceBranch)
			}
			if len(q.TemplateParameters) != len(tt.wantParams) {
				t.Errorf("templateParameters = %v", q.TemplateParameters)
			}
			for k, v := range tt.wantParams {
				if q.TemplateParameters[k] != v {
					t.Errorf("templateParameters[%s] = %q, want %q", k, q.TemplateParameters[k], v)
				}
			}

			lines := e.logLines(t, resp.JobID)
			want := "Queued build 20261020.1 of pipeline " + map[string]string{"smoke": "42", "full": "43"}[tt.suite] +
				" (suite " + tt.suite + "): " + e.ado.webURL(101)
			if len(lines) == 0 || lines[0] != want {
				t.Errorf("first line = %q, want %q", lines, want)
			}
		})
	}
}

func TestAction_OneJobPerInstance(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 }) // the build waits for an agent

	first := e.run(t, testInstance(), "smoke")
	inst := testInstance()
	body := actionBody(&inst, map[string]any{"suite": "full"})
	rr := e.post(t, body, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("second request: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	second := decodeAction(t, rr)
	want := actionResponse{JobID: first.JobID, Status: "running", Suite: "smoke", BuildID: first.BuildID, BuildURL: first.BuildURL, Message: "A test run for this stack is in progress. This is its log."}
	if second != want {
		t.Errorf("second = %+v, want %+v", second, want)
	}
	if n, _, _ := e.ado.counts(); n != 1 {
		t.Errorf("queued = %d, want 1", n)
	}

	// Another instance gets its own job.
	other := testInstance()
	other.ID, other.Name = "i2", "other"
	if o := e.run(t, other, "smoke"); o.JobID == first.JobID || o.Status != "started" {
		t.Errorf("other instance: %+v", o)
	}

	// After the job ends, the instance can run tests again.
	e.ado.set(func(f *fakeADO) { f.builds[first.BuildID].queueLeft = 0 })
	if s := e.waitDone(t, first.JobID); s != jobSucceeded {
		t.Fatalf("status = %s", s)
	}
	third := e.run(t, testInstance(), "smoke")
	if third.JobID == first.JobID || third.Status != "started" {
		t.Errorf("third = %+v", third)
	}
	if n, _, _ := e.ado.counts(); n != 3 {
		t.Errorf("queued = %d, want 3", n)
	}
}

func TestAction_ConcurrentRequestsQueueOnce(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1; f.queueDelay = 50 * time.Millisecond })

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	resps := make([]actionResponse, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst := testInstance()
			rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
			codes[i] = rr.Code
			json.Unmarshal(rr.Body.Bytes(), &resps[i])
		}()
	}
	wg.Wait()

	accepted := 0
	for i := range n {
		switch codes[i] {
		case http.StatusAccepted:
			accepted++
		case http.StatusOK:
		default:
			t.Errorf("request %d: status = %d", i, codes[i])
		}
		if resps[i].JobID != resps[0].JobID {
			t.Errorf("request %d: job_id = %q, want %q", i, resps[i].JobID, resps[0].JobID)
		}
	}
	if accepted != 1 {
		t.Errorf("accepted = %d, want 1", accepted)
	}
	if q, _, _ := e.ado.counts(); q != 1 {
		t.Errorf("queued = %d, want 1", q)
	}
}

func TestAction_QueueFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		setup   func(e *testEnv)
		mutate  func(c *config)
		name    string
		wantMsg string
	}{
		{
			name:    "ADO error status",
			setup:   func(e *testEnv) { e.ado.set(func(f *fakeADO) { f.queueStatus = http.StatusInternalServerError }) },
			wantMsg: "Cannot queue the test pipeline: Azure DevOps returned status 500",
		},
		{
			name:    "credential fails",
			setup:   func(e *testEnv) { e.cred.setErr(errFake) },
			wantMsg: "Cannot queue the test pipeline: cannot get an Azure DevOps token",
		},
		{
			name:    "credentials refused",
			mutate:  func(c *config) { c.ADOAuth = authPAT; c.ADOPAT = "wrong-pat" },
			wantMsg: "Cannot queue the test pipeline: Azure DevOps refused the credentials",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, tt.mutate)
			if tt.setup != nil {
				tt.setup(e)
			}
			inst := testInstance()
			rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			if msg := errorText(t, rr); msg != tt.wantMsg {
				t.Errorf("error = %q, want %q", msg, tt.wantMsg)
			}
			for _, leak := range []string{"secret-token", "http", "wrong-pat", "entra:"} {
				if strings.Contains(rr.Body.String(), leak) {
					t.Errorf("body %q contains %q", rr.Body.String(), leak)
				}
			}
			if e.h.store.running("i1") != nil {
				t.Error("a failed queue left a running job")
			}
		})
	}
}

func TestAction_StoreFull(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 })
	e.h.store.max = 1
	e.run(t, testInstance(), "smoke")

	other := testInstance()
	other.ID = "i2"
	rr := e.post(t, actionBody(&other, map[string]any{"suite": "smoke"}), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if n, _, _ := e.ado.counts(); n != 1 {
		t.Errorf("queued = %d, want 1", n)
	}
}

func TestAction_FirstQueueFailsSecondQueuesOwnBuild(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	// The first queue call is slow and fails; the second request waits for
	// the lock meanwhile.
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1; f.failQueues = 1; f.queueDelay = 50 * time.Millisecond })

	inst := testInstance()
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "").Code
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[http.StatusBadGateway] != 1 || got[http.StatusAccepted] != 1 {
		t.Errorf("status codes = %v, want one 502 and one 202", got)
	}
	if n := len(e.ado.queuedList()); n != 1 {
		t.Errorf("queued builds = %d, want 1", n)
	}
	if e.h.store.running("i1") == nil {
		t.Error("no running job")
	}
	if e.h.store.reserved != 0 {
		t.Errorf("reserved = %d after the requests", e.h.store.reserved)
	}
}

func TestAction_LockWaitUsesTheRequestDeadline(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.h.requestTimeout = 200 * time.Millisecond
	// Every queue call takes longer than the deadline.
	e.ado.set(func(f *fakeADO) { f.queueDelay = time.Second })

	inst := testInstance()
	first := make(chan int, 1)
	go func() { first <- e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "").Code }()
	time.Sleep(20 * time.Millisecond) // the first request holds the lock

	start := time.Now()
	rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
	waited := time.Since(start)
	// The second request gets the lock at about 180ms of its 200ms, so it
	// ends with 503 (lock wait) or 502 (its queue call hits the deadline).
	if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusBadGateway {
		t.Errorf("second: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	// With a new budget after the lock, the second request would take about
	// 380ms.
	if waited > 320*time.Millisecond {
		t.Errorf("second request took %s; the deadline is 200ms from its arrival", waited)
	}
	if code := <-first; code != http.StatusBadGateway {
		t.Errorf("first: status = %d, want 502 (deadline)", code)
	}
}

func TestKeyedMutex_ContextEndsWait(t *testing.T) {
	t.Parallel()
	k := newKeyedMutex()
	unlock, err := k.lock(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := k.lock(ctx, "a"); err == nil {
		t.Fatal("second lock succeeded while the first is held")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the wait took %s", d)
	}
	// Another key does not wait.
	unlockB, err := k.lock(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	unlockB()
	unlock()
	unlock2, err := k.lock(t.Context(), "a")
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.locks) != 0 {
		t.Errorf("locks = %d, want 0", len(k.locks))
	}
}

func TestAction_AfterStop(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.h.stop(time.Second)
	inst := testInstance()
	rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(errorText(t, rr), "stopping") {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if n, _, _ := e.ado.counts(); n != 0 {
		t.Errorf("queued = %d, want 0", n)
	}
}

func TestAction_StopDuringQueueEndsJob(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueDelay = 100 * time.Millisecond })
	inst := testInstance()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "") }()
	time.Sleep(30 * time.Millisecond) // the request is in the queue call
	e.h.stop(time.Second)

	rr := <-done
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	resp := decodeAction(t, rr)
	j := e.h.store.get(resp.JobID)
	if s, _ := j.state(); s != jobUnknown {
		t.Errorf("status = %s, want %s", s, jobUnknown)
	}
	lines := e.logLines(t, resp.JobID)
	if want := "The test runner stopped before it could follow the build. The build continues: " + resp.BuildURL; lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
}

func TestAction_CapRaceAcrossInstances(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1; f.queueDelay = 20 * time.Millisecond })
	e.h.store.max = 3

	const n = 10
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst := testInstance()
			inst.ID = "i" + strconv.Itoa(i)
			inst.Name = "demo" + strconv.Itoa(i)
			codes[i] = e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "").Code
		}()
	}
	wg.Wait()
	got := map[int]int{}
	for _, c := range codes {
		got[c]++
	}
	if got[http.StatusAccepted] != 3 || got[http.StatusServiceUnavailable] != n-3 {
		t.Errorf("status codes = %v, want 3 x 202 and %d x 503", got, n-3)
	}
	if q, _, _ := e.ado.counts(); q != 3 {
		t.Errorf("queued = %d, want 3", q)
	}
	e.h.store.mu.Lock()
	jobs, reserved := len(e.h.store.jobs), e.h.store.reserved
	e.h.store.mu.Unlock()
	if jobs != 3 || reserved != 0 {
		t.Errorf("jobs = %d, reserved = %d", jobs, reserved)
	}
}

// TestRealSocket_BackendLogURL sends the requests over a real socket, as the
// k8s-stack-manager backend does: the log URL is built like jobLogURL
// (backend/internal/hooks/action_joblog.go), and the signature is the HMAC
// of u.RequestURI().
func TestRealSocket_BackendLogURL(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.Secret = "s3cret" })
	srv := httptest.NewServer(e.mux)
	t.Cleanup(srv.Close)

	// An instance ID with characters that the query encoding changes.
	inst := testInstance()
	inst.ID = "id with space+plus/slash"
	body := actionBody(&inst, map[string]any{"suite": "smoke"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/action", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign("s3cret", body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var started actionResponse
	json.NewDecoder(resp.Body).Decode(&started)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /action: status = %d", resp.StatusCode)
	}
	e.waitDone(t, started.JobID)

	logURL := func(instanceID string, offset int) *url.URL {
		base, _ := url.Parse(srv.URL + "/action")
		u := &url.URL{
			Scheme: base.Scheme,
			User:   base.User,
			Host:   base.Host,
			Path:   strings.Replace("/jobs/{job_id}/log", "{job_id}", started.JobID, 1),
		}
		q := url.Values{}
		q.Set("offset", strconv.Itoa(offset))
		if instanceID != "" {
			q.Set("instance_id", instanceID)
		}
		q.Set("ts", strconv.FormatInt(time.Now().Unix(), 10))
		u.RawQuery = q.Encode()
		return u
	}
	get := func(u *url.URL) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
		req.Header.Set(signatureHeader, sign("s3cret", []byte(u.RequestURI())))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, text := get(logURL(inst.ID, 0))
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Job-Status") != jobSucceeded {
		t.Fatalf("status = %d, X-Job-Status = %q, body = %s", resp.StatusCode, resp.Header.Get("X-Job-Status"), text)
	}
	if !strings.Contains(text, "Build finished: succeeded") || resp.Header.Get("X-Log-Offset") != strconv.Itoa(len(text)) {
		t.Errorf("X-Log-Offset = %q, body = %q", resp.Header.Get("X-Log-Offset"), text)
	}
	if resp, _ := get(logURL("another", 0)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another instance: status = %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GET /jobs/{job_id}/log
// ---------------------------------------------------------------------------

func TestJobLog_Signature(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.Secret = "s3cret" })
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 })
	job := e.run(t, testInstance(), "smoke")
	now := time.Now().Unix()

	signed := func(uri string) (string, string) { return uri, sign("s3cret", []byte(uri)) }
	good := logURI(job.JobID, "i1", 0, now)
	// The same query in another order: the signature covers the URI as sent.
	reordered := "/jobs/" + job.JobID + "/log?ts=" + strings.Split(good, "ts=")[1] + "&instance_id=i1&offset=0"

	tests := []struct {
		name string
		uri  string
		sig  string
		want int
	}{
		{"valid", good, sign("s3cret", []byte(good)), http.StatusOK},
		{"missing signature", good, "", http.StatusUnauthorized},
		{"wrong secret", good, sign("other", []byte(good)), http.StatusUnauthorized},
		{"signature of the path only", good, sign("s3cret", []byte("/jobs/"+job.JobID+"/log")), http.StatusUnauthorized},
		{"signature of another order", reordered, sign("s3cret", []byte(good)), http.StatusUnauthorized},
		{"other order, own signature", reordered, sign("s3cret", []byte(reordered)), http.StatusOK},
	}
	for _, tt := range tests {
		if rr := e.getURI(t, tt.uri, tt.sig); rr.Code != tt.want {
			t.Errorf("%s: status = %d, want %d, body = %s", tt.name, rr.Code, tt.want, rr.Body.String())
		}
	}

	tsTests := []struct {
		name string
		uri  string
		want int
	}{
		{"ts 4 minutes old", logURI(job.JobID, "i1", 0, now-240), http.StatusOK},
		{"ts 6 minutes old", logURI(job.JobID, "i1", 0, now-360), http.StatusUnauthorized},
		{"ts 6 minutes in the future", logURI(job.JobID, "i1", 0, now+360), http.StatusUnauthorized},
		{"no ts", "/jobs/" + job.JobID + "/log?instance_id=i1&offset=0", http.StatusUnauthorized},
		{"ts not a number", "/jobs/" + job.JobID + "/log?instance_id=i1&offset=0&ts=abc", http.StatusUnauthorized},
	}
	for _, tt := range tsTests {
		uri, sig := signed(tt.uri)
		if rr := e.getURI(t, uri, sig); rr.Code != tt.want {
			t.Errorf("%s: status = %d, want %d, body = %s", tt.name, rr.Code, tt.want, rr.Body.String())
		}
	}
}

func TestJobLog_OffsetsAndHeaders(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 })
	job := e.run(t, testInstance(), "smoke")
	full := e.logText(job.JobID)
	if full == "" {
		t.Fatal("empty log")
	}

	tests := []struct {
		name       string
		wantBody   string
		wantOffset string
		offset     int
	}{
		{name: "from the start", offset: 0, wantBody: full, wantOffset: itoa(len(full))},
		{name: "from the middle", offset: 10, wantBody: full[10:], wantOffset: itoa(len(full))},
		{name: "at the end", offset: len(full), wantBody: "", wantOffset: itoa(len(full))},
		{name: "past the end", offset: len(full) + 100, wantBody: "", wantOffset: itoa(len(full) + 100)},
	}
	for _, tt := range tests {
		rr := e.getLog(t, job.JobID, "i1", tt.offset)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body = %s", tt.name, rr.Code, rr.Body.String())
		}
		if rr.Body.String() != tt.wantBody {
			t.Errorf("%s: body = %q, want %q", tt.name, rr.Body.String(), tt.wantBody)
		}
		if got := rr.Header().Get("X-Log-Offset"); got != tt.wantOffset {
			t.Errorf("%s: X-Log-Offset = %q, want %q", tt.name, got, tt.wantOffset)
		}
		if got := rr.Header().Get("X-Job-Status"); got != jobRunning {
			t.Errorf("%s: X-Job-Status = %q", tt.name, got)
		}
		if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
			t.Errorf("%s: Content-Type = %q", tt.name, got)
		}
	}

	for _, bad := range []string{"-1", "abc", "1.5"} {
		uri := "/jobs/" + job.JobID + "/log?instance_id=i1&offset=" + bad + "&ts=" + itoa(int(time.Now().Unix()))
		if rr := e.getURI(t, uri, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("offset %q: status = %d", bad, rr.Code)
		}
	}

	// The final status comes with the final lines.
	e.ado.set(func(f *fakeADO) { f.builds[job.BuildID].queueLeft = 0 })
	e.waitDone(t, job.JobID)
	rr := e.getLog(t, job.JobID, "i1", len(full))
	if got := rr.Header().Get("X-Job-Status"); got != jobSucceeded {
		t.Errorf("X-Job-Status = %q", got)
	}
	if !strings.Contains(rr.Body.String(), "Build finished: succeeded") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestJobLog_NotFound(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 })
	job := e.run(t, testInstance(), "smoke")

	tests := []struct {
		name     string
		jobID    string
		instance string
	}{
		{"unknown job", "job-00000000000000000000000000000000", "i1"},
		{"another instance", job.JobID, "i2"},
		{"no instance id", job.JobID, ""},
		{"invalid job id", ".hidden", "i1"},
	}
	for _, tt := range tests {
		if rr := e.getLog(t, tt.jobID, tt.instance, 0); rr.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, body = %s", tt.name, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, logURI(job.JobID, "i1", 0, time.Now().Unix()), nil)
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST log: status = %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

func TestServeGracefulShutdown(t *testing.T) {
	t.Parallel()
	stopped := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // a request that does not end by itself
		close(stopped)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serve(ctx, srv, ln, 50*time.Millisecond) }()

	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel() // SIGTERM

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request was not stopped after the shutdown timeout")
	}
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve = %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("serve did not return")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
