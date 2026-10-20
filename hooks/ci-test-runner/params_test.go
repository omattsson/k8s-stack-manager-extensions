package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// oneSuiteConfig is a pipeline that declares only stackName and an optional
// workers parameter (1, 2 or 3), on its own default branch.
func oneSuiteConfig(c *config) {
	c.PipelineSourceBranch = ""
	c.Suites = map[string]suiteConfig{
		"e2e": {
			PipelineID: 42,
			TemplateParameters: map[string]paramMapping{
				"stackName": {From: fromInstanceName},
				"workers":   {From: fromParameter, Parameter: "workers", Values: []string{"1", "2", "3"}},
			},
		},
	}
}

// declare makes the fake refuse undeclared template parameters of pipeline 42.
func declare(e *testEnv, names ...string) {
	e.ado.set(func(f *fakeADO) { f.declared[42] = names })
}

func (f *fakeADO) rawBodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.queuedRaw))
	for _, b := range f.queuedRaw {
		data, _ := json.Marshal(b)
		out = append(out, string(data))
	}
	return out
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

func TestParseTestPipelines_TemplateParameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name: "pipeline with stackName and workers",
			json: `{"e2e": {"pipeline_id": 42, "template_parameters": {
				"stackName": {"from": "instance.name"},
				"workers": {"from": "parameter", "parameter": "workers", "values": ["1", "2", "3"]}}}}`,
		},
		{
			name: "all sources",
			json: `{"e2e": {"pipeline_id": 42, "template_parameters": {
				"a": {"from": "instance.name"}, "b": {"from": "instance.namespace"}, "c": {"from": "instance.branch"},
				"d": {"from": "suite"}, "e": {"from": "parameter", "parameter": "x.y-z", "required": true},
				"f": {"from": "value", "value": "true"}}}}`,
		},
		{name: "empty map", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {}}}`},
		{name: "unknown from", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"a": {"from": "instance.owner"}}}}`, wantErr: "unknown from"},
		{name: "no from", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"a": {}}}}`, wantErr: "unknown from"},
		{name: "parameter name with a dash", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"stack-name": {"from": "instance.name"}}}}`, wantErr: "template parameter name"},
		{name: "parameter name with a digit first", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"1a": {"from": "instance.name"}}}}`, wantErr: "template parameter name"},
		{name: "missing parameter", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter"}}}}`, wantErr: "needs parameter"},
		{name: "bad action parameter name", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "a b"}}}}`, wantErr: "needs parameter"},
		{name: "unknown field", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "w", "default": "2"}}}}`, wantErr: "not a valid JSON"},
		{name: "empty values", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "w", "values": []}}}}`, wantErr: "values must not be empty"},
		{name: "unsafe value", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "w", "values": ["a b"]}}}}`, wantErr: "must match"},
		{name: "value with a leading dash", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "w", "values": ["-1"]}}}}`, wantErr: "must match"},
		{name: "parameter on instance.name", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"s": {"from": "instance.name", "parameter": "x"}}}}`, wantErr: "takes no parameter"},
		{name: "required on suite", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"s": {"from": "suite", "required": true}}}}`, wantErr: "takes no parameter"},
		{name: "value without value", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"v": {"from": "value"}}}}`, wantErr: "needs a value"},
		{name: "value with a control character", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"v": {"from": "value", "value": "a\nb"}}}}`, wantErr: "needs a value"},
		{name: "value with values", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"v": {"from": "value", "value": "x", "values": ["x"]}}}}`, wantErr: "takes no parameter"},
		{name: "parameter with value", json: `{"e2e": {"pipeline_id": 42, "template_parameters": {"w": {"from": "parameter", "parameter": "w", "value": "x"}}}}`, wantErr: "takes no value"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseTestPipelines(tt.json)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Template parameter values
// ---------------------------------------------------------------------------

func TestTemplateParams(t *testing.T) {
	t.Parallel()
	inst := &InstanceRef{ID: "i1", Name: "demo", Namespace: "stack-demo-alice"}
	workers := map[string]paramMapping{
		"stackName": {From: fromInstanceName},
		"workers":   {From: fromParameter, Parameter: "workers", Values: []string{"1", "2", "3"}},
	}
	free := map[string]paramMapping{"tag": {From: fromParameter, Parameter: "tag"}}
	required := map[string]paramMapping{"tag": {From: fromParameter, Parameter: "tag", Required: true}}

	tests := []struct {
		mapping map[string]paramMapping
		params  map[string]any
		want    map[string]string
		name    string
		branch  string
		wantMsg string
	}{
		{name: "integer becomes a string", mapping: workers, params: map[string]any{"workers": json.Number("2")}, want: map[string]string{"stackName": "demo", "workers": "2"}},
		{name: "string", mapping: workers, params: map[string]any{"workers": "3"}, want: map[string]string{"stackName": "demo", "workers": "3"}},
		{name: "missing optional is not sent", mapping: workers, params: nil, want: map[string]string{"stackName": "demo"}},
		{name: "empty optional is not sent", mapping: workers, params: map[string]any{"workers": ""}, want: map[string]string{"stackName": "demo"}},
		{name: "null optional is not sent", mapping: workers, params: map[string]any{"workers": nil}, want: map[string]string{"stackName": "demo"}},
		{name: "value outside values", mapping: workers, params: map[string]any{"workers": json.Number("4")}, wantMsg: "The parameter workers must be one of: 1, 2, 3"},
		{name: "decimal number", mapping: workers, params: map[string]any{"workers": json.Number("2.5")}, wantMsg: "must be a string, an integer or a boolean"},
		{name: "object", mapping: workers, params: map[string]any{"workers": map[string]any{"a": 1}}, wantMsg: "must be a string, an integer or a boolean"},
		{name: "array", mapping: workers, params: map[string]any{"workers": []any{"2"}}, wantMsg: "must be a string, an integer or a boolean"},
		{name: "boolean becomes a string", mapping: free, params: map[string]any{"tag": true}, want: map[string]string{"tag": "true"}},
		{name: "free value", mapping: free, params: map[string]any{"tag": "v1.2_rc-1"}, want: map[string]string{"tag": "v1.2_rc-1"}},
		{name: "unsafe free value", mapping: free, params: map[string]any{"tag": "$(id)"}, wantMsg: "may have only letters, digits"},
		{name: "free value with a leading dash", mapping: free, params: map[string]any{"tag": "-x"}, wantMsg: "must not start with"},
		{name: "free value with a leading dot", mapping: free, params: map[string]any{"tag": ".x"}, wantMsg: "must not start with"},
		{name: "negative integer", mapping: free, params: map[string]any{"tag": json.Number("-1")}, wantMsg: "must not start with"},
		{name: "free value with a leading underscore", mapping: free, params: map[string]any{"tag": "_x"}, want: map[string]string{"tag": "_x"}},
		{name: "long free value", mapping: free, params: map[string]any{"tag": strings.Repeat("a", 65)}, wantMsg: "may have only letters, digits"},
		{name: "missing required", mapping: required, params: map[string]any{}, wantMsg: "Set the parameter tag"},
		{name: "undeclared action parameters are not sent", mapping: free, params: map[string]any{"tag": "x", "other": "y"}, want: map[string]string{"tag": "x"}},
		{
			name:    "default mapping",
			mapping: defaultTemplateParameters(), branch: "feature/x", params: map[string]any{"workers": "2"},
			want: map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "branch": "feature/x", "suite": "smoke"},
		},
		{
			name:    "default mapping without a branch",
			mapping: defaultTemplateParameters(),
			want:    map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "suite": "smoke"},
		},
		{name: "constant", mapping: map[string]paramMapping{"flag": {From: fromValue, Value: "false"}}, want: map[string]string{"flag": "false"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, msg := templateParams(tt.mapping, inst, tt.branch, "smoke", tt.params)
			if tt.wantMsg != "" {
				if !strings.Contains(msg, tt.wantMsg) {
					t.Errorf("msg = %q, want %q", msg, tt.wantMsg)
				}
				return
			}
			if msg != "" {
				t.Fatalf("msg = %q", msg)
			}
			if len(got) != len(tt.want) {
				t.Errorf("params = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("params[%s] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Queue body
// ---------------------------------------------------------------------------

func TestQueueBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mutate   func(*config)
		params   map[string]any
		name     string
		declared []string
		want     string
	}{
		{
			name: "one suite with workers", mutate: oneSuiteConfig, declared: []string{"stackName", "debug", "workers"},
			params: map[string]any{"workers": 2},
			want:   `{"definition":{"id":42},"templateParameters":{"stackName":"demo","workers":"2"}}`,
		},
		{
			name: "one suite without workers", mutate: oneSuiteConfig, declared: []string{"stackName", "workers"},
			params: map[string]any{},
			want:   `{"definition":{"id":42},"templateParameters":{"stackName":"demo"}}`,
		},
		{
			name: "one suite, suite given", mutate: oneSuiteConfig, declared: []string{"stackName", "workers"},
			params: map[string]any{"suite": "e2e", "workers": "1"},
			want:   `{"definition":{"id":42},"templateParameters":{"stackName":"demo","workers":"1"}}`,
		},
		{
			name: "default mapping and source branch",
			mutate: func(c *config) {
				c.PipelineSourceBranch = "refs/heads/main"
			},
			declared: []string{"stackName", "namespace", "branch", "suite"},
			params:   map[string]any{"suite": "smoke", "workers": "2"},
			want:     `{"definition":{"id":42},"sourceBranch":"refs/heads/main","templateParameters":{"branch":"feature/login","namespace":"stack-demo-alice","stackName":"demo","suite":"smoke"}}`,
		},
		{
			name:     "suite source branch wins",
			mutate:   func(c *config) { c.PipelineSourceBranch = "" },
			declared: []string{"stackName", "namespace", "branch", "suite"},
			params:   map[string]any{"suite": "full"},
			want:     `{"definition":{"id":43},"sourceBranch":"refs/heads/release","templateParameters":{"branch":"feature/login","namespace":"stack-demo-alice","stackName":"demo","suite":"full"}}`,
		},
		{
			name: "no source branch configured",
			mutate: func(c *config) {
				c.PipelineSourceBranch = ""
				c.Suites = map[string]suiteConfig{"smoke": {PipelineID: 42, TemplateParameters: map[string]paramMapping{}}}
			},
			params: map[string]any{},
			want:   `{"definition":{"id":42}}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, tt.mutate)
			if tt.declared != nil {
				declare(e, tt.declared...)
			}
			inst := testInstance()
			rr := e.post(t, actionBody(&inst, tt.params), "")
			if rr.Code != http.StatusAccepted {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			bodies := e.ado.rawBodies()
			if len(bodies) != 1 || bodies[0] != tt.want {
				t.Errorf("queue body = %v\nwant %s", bodies, tt.want)
			}
		})
	}
}

func TestQueue_UndeclaredParameterRefused(t *testing.T) {
	t.Parallel()
	// The default mapping sends four parameters; the pipeline declares two.
	e := newTestEnv(t, nil)
	declare(e, "stackName", "workers")
	inst := testInstance()
	rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
	if rr.Code != http.StatusBadGateway || errorText(t, rr) != "Cannot queue the test pipeline: Azure DevOps returned status 400" {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestAction_ParameterErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		params  map[string]any
		name    string
		wantMsg string
	}{
		{name: "workers outside values", params: map[string]any{"workers": "4"}, wantMsg: "The parameter workers must be one of: 1, 2, 3"},
		{name: "workers boolean", params: map[string]any{"workers": true}, wantMsg: "must be one of"},
		{name: "workers object", params: map[string]any{"workers": map[string]any{}}, wantMsg: "must be a string, an integer or a boolean"},
		{name: "workers decimal", params: map[string]any{"workers": 2.5}, wantMsg: "must be a string, an integer or a boolean"},
		{name: "unknown suite", params: map[string]any{"suite": "smoke"}, wantMsg: `Unknown suite "smoke". Suites: e2e`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, oneSuiteConfig)
			inst := testInstance()
			rr := e.post(t, actionBody(&inst, tt.params), "")
			if rr.Code != http.StatusBadRequest || !strings.Contains(errorText(t, rr), tt.wantMsg) {
				t.Errorf("status = %d, body = %s, want %q", rr.Code, rr.Body.String(), tt.wantMsg)
			}
			if n, _, _ := e.ado.counts(); n != 0 {
				t.Errorf("queued = %d", n)
			}
		})
	}
}

func TestAction_SuiteRequiredWithTwoSuites(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil) // smoke and full
	inst := testInstance()
	rr := e.post(t, actionBody(&inst, map[string]any{}), "")
	if rr.Code != http.StatusBadRequest || !strings.Contains(errorText(t, rr), "Select a test suite") {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Result of a report-only pipeline
// ---------------------------------------------------------------------------

func TestJob_PartiallySucceeded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		runs      []testRun
		name      string
		want      string
		wantLine  string
		failRuns  bool
		noWarning bool
	}{
		{name: "failed tests", runs: []testRun{{TotalTests: 10, PassedTests: 8, UnanalyzedTests: 2}}, want: jobFailed, noWarning: true},
		{name: "no failed tests", runs: []testRun{{TotalTests: 10, PassedTests: 9, NotApplicableTests: 1}}, want: jobSucceeded, wantLine: "Build finished with warnings. See the run page: "},
		{name: "no passed tests", runs: []testRun{{TotalTests: 10, NotApplicableTests: 10}}, want: jobFailed, noWarning: true},
		{name: "no test runs", runs: nil, want: jobFailed, noWarning: true},
		{name: "test runs not readable", failRuns: true, want: jobUnknown, wantLine: "The build finished with warnings or failed tests. See the run page: "},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			e.ado.set(func(f *fakeADO) {
				f.nextResult = "partiallySucceeded"
				f.failRuns = tt.failRuns
				if tt.runs != nil {
					f.runs["vstfs:///Build/Build/101"] = tt.runs
				}
			})
			job := e.run(t, testInstance(), "smoke")
			if s := e.waitDone(t, job.JobID); s != tt.want {
				t.Fatalf("status = %s, want %s\n%s", s, tt.want, e.logText(job.JobID))
			}
			lines := e.logLines(t, job.JobID)
			last := lines[len(lines)-1]
			if tt.wantLine != "" && last != tt.wantLine+e.ado.webURL(101) {
				t.Errorf("last line = %q", last)
			}
			if tt.noWarning && strings.Contains(e.logText(job.JobID), "See the run page") {
				t.Errorf("log:\n%s", e.logText(job.JobID))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Adoption of a running build
// ---------------------------------------------------------------------------

func TestAction_AdoptsRunningBuild(t *testing.T) {
	t.Parallel()
	tests := []struct {
		setup     func(f *fakeADO)
		name      string
		wantCode  int
		wantBuild int
	}{
		{
			name:     "match",
			setup:    func(f *fakeADO) { f.builds[500] = runningBuild(500, 42, "demo") },
			wantCode: http.StatusOK, wantBuild: 500,
		},
		{
			name: "match without template parameters in the list",
			setup: func(f *fakeADO) {
				f.builds[500] = runningBuild(500, 42, "demo")
				f.omitListTP = true
			},
			wantCode: http.StatusOK, wantBuild: 500,
		},
		{
			name:     "build of another stack",
			setup:    func(f *fakeADO) { f.builds[500] = runningBuild(500, 42, "other") },
			wantCode: http.StatusAccepted, wantBuild: 101,
		},
		{
			name:     "build of another pipeline",
			setup:    func(f *fakeADO) { f.builds[500] = runningBuild(500, 7, "demo") },
			wantCode: http.StatusAccepted, wantBuild: 101,
		},
		{
			name: "completed build",
			setup: func(f *fakeADO) {
				b := runningBuild(500, 42, "demo")
				b.status = "completed"
				f.builds[500] = b
			},
			wantCode: http.StatusAccepted, wantBuild: 101,
		},
		{
			name:     "list error queues (fail open)",
			setup:    func(f *fakeADO) { f.builds[500] = runningBuild(500, 42, "demo"); f.failList = true },
			wantCode: http.StatusAccepted, wantBuild: 101,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, oneSuiteConfig)
			e.ado.set(tt.setup)
			inst := testInstance()
			rr := e.post(t, actionBody(&inst, map[string]any{"workers": "2"}), "")
			if rr.Code != tt.wantCode {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			resp := decodeAction(t, rr)
			if resp.BuildID != tt.wantBuild || resp.BuildURL != e.ado.webURL(tt.wantBuild) {
				t.Errorf("response = %+v", resp)
			}
			queued, _, _ := e.ado.counts()
			if tt.wantCode == http.StatusOK {
				if queued != 0 || resp.Status != jobRunning ||
					resp.Message != "A test run for this stack is already in progress in Azure DevOps. This is its log." {
					t.Errorf("queued = %d, response = %+v", queued, resp)
				}
				lines := e.logLines(t, resp.JobID)
				want := "Found build 20261020.400 of pipeline 42 for this stack, started before this request: " + e.ado.webURL(500)
				if lines[0] != want {
					t.Errorf("first line = %q, want %q", lines[0], want)
				}
				// The job follows the adopted build to its end.
				e.ado.set(func(f *fakeADO) { f.builds[500].runLeft = 0 })
				if s := e.waitDone(t, resp.JobID); s != jobSucceeded {
					t.Errorf("status = %s", s)
				}
				// The job and the build are done: a second request queues.
				rr2 := e.post(t, actionBody(&inst, map[string]any{}), "")
				if rr2.Code != http.StatusAccepted {
					t.Errorf("second request: status = %d, body = %s", rr2.Code, rr2.Body.String())
				}
			} else if queued != 1 {
				t.Errorf("queued = %d, want 1", queued)
			}

			e.ado.mu.Lock()
			q := e.ado.listQueries
			e.ado.mu.Unlock()
			if len(q) == 0 || q[0].Get("definitions") != "42" || q[0].Get("statusFilter") != "inProgress,notStarted,postponed" {
				t.Errorf("list queries = %v", q)
			}
		})
	}
}

func runningBuild(id, def int, stack string) *fakeBuild {
	return &fakeBuild{id: id, definition: def, status: "inProgress", runLeft: -1, result: "succeeded",
		tp: map[string]string{"stackName": stack, "workers": "2"}}
}

func TestAction_AdoptedSuite(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil) // default mapping: suite is a template parameter
	e.ado.set(func(f *fakeADO) {
		f.builds[500] = &fakeBuild{id: 500, definition: 42, status: "inProgress", runLeft: -1,
			tp: map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "suite": "smoke"}}
	})
	inst := testInstance()
	rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
	if resp := decodeAction(t, rr); rr.Code != http.StatusOK || resp.Suite != "smoke" || resp.BuildID != 500 {
		t.Errorf("status = %d, response = %+v", rr.Code, resp)
	}
}

func TestAction_NoAdoptionWithoutStackParameter(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) {
		c.Suites = map[string]suiteConfig{"smoke": {PipelineID: 42, TemplateParameters: map[string]paramMapping{
			"ns": {From: fromInstanceNamespace},
		}}}
	})
	inst := testInstance()
	if rr := e.post(t, actionBody(&inst, nil), ""); rr.Code != http.StatusAccepted {
		t.Errorf("status = %d", rr.Code)
	}
	e.ado.mu.Lock()
	defer e.ado.mu.Unlock()
	if len(e.ado.listQueries) != 0 {
		t.Errorf("list calls = %d, want 0", len(e.ado.listQueries))
	}
}

// ---------------------------------------------------------------------------
// Running job cap
// ---------------------------------------------------------------------------

func TestAction_RunningCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		max     int
		wantMsg string
	}{
		{name: "cap 1", max: 1, wantMsg: "1 test run is in progress. Try again later."},
		{name: "cap 2", max: 2, wantMsg: "2 test runs are in progress. Try again later."},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, func(c *config) { c.MaxRunningJobs = tt.max })
			e.ado.set(func(f *fakeADO) { f.queueWaitPolls = -1 })
			for i := range tt.max {
				inst := testInstance()
				inst.ID, inst.Name = "i"+itoa(i), "demo"+itoa(i)
				e.run(t, inst, "smoke")
			}
			inst := testInstance()
			inst.ID, inst.Name = "next", "next"
			rr := e.post(t, actionBody(&inst, map[string]any{"suite": "smoke"}), "")
			if rr.Code != http.StatusTooManyRequests || errorText(t, rr) != tt.wantMsg {
				t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			// The stack of a running job still gets its job.
			first := testInstance()
			first.ID, first.Name = "i0", "demo0"
			if rr := e.post(t, actionBody(&first, map[string]any{"suite": "smoke"}), ""); rr.Code != http.StatusOK {
				t.Errorf("running stack: status = %d", rr.Code)
			}
			if n, _, _ := e.ado.counts(); n != tt.max {
				t.Errorf("queued = %d, want %d", n, tt.max)
			}
		})
	}
}

func TestAction_RunningCapCountsAdoptedJobs(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { oneSuiteConfig(c); c.MaxRunningJobs = 1 })
	e.ado.set(func(f *fakeADO) { f.builds[500] = runningBuild(500, 42, "demo") })
	inst := testInstance()
	if rr := e.post(t, actionBody(&inst, nil), ""); rr.Code != http.StatusOK {
		t.Fatalf("adopt: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	other := testInstance()
	other.ID, other.Name = "i2", "other"
	if rr := e.post(t, actionBody(&other, nil), ""); rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestLoadConfig_NewSettings(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"CI_TEST_RUNNER_SECRET": "s",
		"ADO_ORG":               "example-org",
		"ADO_PROJECT":           "example-project",
		"ADO_PAT":               "pat",
		"TEST_PIPELINES":        `{"e2e": {"pipeline_id": 42}}`,
	}
	tests := []struct {
		env     map[string]string
		name    string
		wantErr string
		timeout time.Duration
		maxRun  int
	}{
		{name: "timeout 120", env: map[string]string{"TEST_TIMEOUT_MINUTES": "120"}, timeout: 120 * time.Minute},
		{name: "timeout 240", env: map[string]string{"TEST_TIMEOUT_MINUTES": "240"}, timeout: 240 * time.Minute},
		{name: "timeout 241", env: map[string]string{"TEST_TIMEOUT_MINUTES": "241"}, wantErr: "at most 240"},
		{name: "max running jobs", env: map[string]string{"MAX_RUNNING_JOBS": "3"}, timeout: 60 * time.Minute, maxRun: 3},
		{name: "max running jobs negative", env: map[string]string{"MAX_RUNNING_JOBS": "-1"}, wantErr: "MAX_RUNNING_JOBS"},
		{name: "max running jobs not a number", env: map[string]string{"MAX_RUNNING_JOBS": "three"}, wantErr: "MAX_RUNNING_JOBS"},
		{name: "max running jobs zero", env: map[string]string{"MAX_RUNNING_JOBS": "0"}, timeout: 60 * time.Minute},
		{name: "empty source branch", env: map[string]string{"PIPELINE_SOURCE_BRANCH": ""}, timeout: 60 * time.Minute},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadConfig(func(k string) string {
				if v, ok := tt.env[k]; ok {
					return v
				}
				return base[k]
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.TestTimeout != tt.timeout || cfg.MaxRunningJobs != tt.maxRun || cfg.PipelineSourceBranch != "" {
				t.Errorf("timeout = %s, max running = %d, source branch = %q", cfg.TestTimeout, cfg.MaxRunningJobs, cfg.PipelineSourceBranch)
			}
		})
	}
}

func TestAction_AdoptedSuiteFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mutate    func(*config)
		tp        map[string]string
		name      string
		wantSuite string
	}{
		{
			name: "two suites, no suite key",
			tp:   map[string]string{"stackName": "demo", "namespace": "stack-demo-alice"},
		},
		{
			name: "two suites, suite not a valid name",
			tp:   map[string]string{"stackName": "demo", "namespace": "stack-demo-alice", "suite": "<b>x</b>"},
		},
		{
			name:   "one suite without a suite parameter",
			mutate: oneSuiteConfig, tp: map[string]string{"stackName": "demo"}, wantSuite: "e2e",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, tt.mutate)
			e.ado.set(func(f *fakeADO) {
				f.builds[500] = &fakeBuild{id: 500, definition: 42, status: "inProgress", runLeft: -1, tp: tt.tp}
			})
			inst := testInstance()
			params := map[string]any{"suite": "smoke"}
			if tt.mutate != nil {
				params = nil // one suite: suite is optional
			}
			rr := e.post(t, actionBody(&inst, params), "")
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "<nil>") {
				t.Errorf("body = %s", rr.Body.String())
			}
			if resp := decodeAction(t, rr); resp.Suite != tt.wantSuite || resp.BuildID != 500 {
				t.Errorf("response = %+v, want suite %q", resp, tt.wantSuite)
			}
		})
	}
}

func TestAction_AdoptionComparesTheNamespace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mutate   func(*config)
		params   map[string]any
		tp       map[string]string
		name     string
		wantCode int
	}{
		{
			name:   "namespace mapped and equal",
			params: map[string]any{"suite": "smoke"}, tp: map[string]string{"stackName": "demo", "namespace": "stack-demo-alice"},
			wantCode: http.StatusOK,
		},
		{
			name:   "namespace mapped and different (same name on another cluster)",
			params: map[string]any{"suite": "smoke"}, tp: map[string]string{"stackName": "demo", "namespace": "stack-demo-bob"},
			wantCode: http.StatusAccepted,
		},
		{
			name:   "namespace not mapped: the name decides",
			mutate: oneSuiteConfig, params: map[string]any{}, tp: map[string]string{"stackName": "demo"},
			wantCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, tt.mutate)
			e.ado.set(func(f *fakeADO) {
				f.builds[500] = &fakeBuild{id: 500, definition: 42, status: "inProgress", runLeft: -1, tp: tt.tp}
			})
			inst := testInstance()
			if rr := e.post(t, actionBody(&inst, tt.params), ""); rr.Code != tt.wantCode {
				t.Errorf("status = %d, want %d, body = %s", rr.Code, tt.wantCode, rr.Body.String())
			}
		})
	}
}

func TestAction_SlowLookupStillQueues(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, oneSuiteConfig)
	e.h.adoptTimeout = 50 * time.Millisecond
	e.ado.set(func(f *fakeADO) {
		f.builds[500] = runningBuild(500, 42, "demo")
		f.listDelay = time.Second
	})
	inst := testInstance()
	start := time.Now()
	rr := e.post(t, actionBody(&inst, nil), "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("the request took %s; the lookup limit is 50ms", d)
	}
	if resp := decodeAction(t, rr); resp.BuildID != 101 {
		t.Errorf("response = %+v", resp)
	}
}

func TestFindRunningBuild_Scan(t *testing.T) {
	t.Parallel()
	hidden := func(id int, stack string) *fakeBuild {
		b := runningBuild(id, 42, stack)
		b.hideTP = true
		return b
	}
	tests := []struct {
		setup     func(f *fakeADO)
		name      string
		wantBuild int
		wantReads int
	}{
		{
			name: "a failed read skips the build",
			setup: func(f *fakeADO) {
				f.builds[500] = hidden(500, "demo")
				f.missingIDs = map[int]bool{500: true}
				f.builds[501] = hidden(501, "demo")
			},
			wantBuild: 501, wantReads: 2,
		},
		{
			name: "entries with parameters count after the read limit",
			setup: func(f *fakeADO) {
				for id := 500; id < 521; id++ {
					f.builds[id] = hidden(id, "other")
				}
				f.builds[600] = runningBuild(600, 42, "demo")
			},
			wantBuild: 600, wantReads: maxBuildReads,
		},
		{
			name: "no read after the limit",
			setup: func(f *fakeADO) {
				for id := 500; id < 520; id++ {
					f.builds[id] = hidden(id, "other")
				}
				f.builds[530] = hidden(530, "demo")
			},
			wantBuild: 0, wantReads: maxBuildReads,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, oneSuiteConfig)
			e.ado.set(tt.setup)
			b, err := e.h.ci.findRunningBuild(t.Context(), 42, map[string]string{"stackName": "demo"})
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			if b != nil {
				got = b.ID
			}
			if got != tt.wantBuild {
				t.Errorf("build = %d, want %d", got, tt.wantBuild)
			}
			e.ado.mu.Lock()
			reads := len(e.ado.readIDs)
			e.ado.mu.Unlock()
			if reads != tt.wantReads {
				t.Errorf("build reads = %d, want %d", reads, tt.wantReads)
			}
		})
	}
}

func TestMatchesParams(t *testing.T) {
	t.Parallel()
	b := &buildInfo{TemplateParameters: map[string]any{"stackName": "demo", "workers": float64(2), "namespace": "ns"}}
	tests := []struct {
		match map[string]string
		name  string
		want  bool
	}{
		{name: "name", match: map[string]string{"stackName": "demo"}, want: true},
		{name: "name and namespace", match: map[string]string{"stackName": "demo", "namespace": "ns"}, want: true},
		{name: "other namespace", match: map[string]string{"stackName": "demo", "namespace": "x"}, want: false},
		{name: "not a string", match: map[string]string{"workers": "2"}, want: false},
		{name: "missing key", match: map[string]string{"suite": "smoke"}, want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesParams(b, tt.match); got != tt.want {
				t.Errorf("matchesParams = %v, want %v", got, tt.want)
			}
		})
	}
}
