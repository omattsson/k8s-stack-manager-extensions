package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

// TestSanitizeImageTag uses the same table as TestSanitizeImageTag in
// k8s-stack-manager (backend/internal/helm/values_generator_test.go), plus
// the length limit.
func TestSanitizeImageTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		branch string
		want   string
	}{
		{"master", "master"},
		{"main", "main"},
		{"feature/my-thing", "feature-my-thing"},
		{"feature/UPPER-Case", "feature-upper-case"},
		{"bugfix/fix_underscore", "bugfix-fix-underscore"},
		{"refs/heads/feature/test", "refs-heads-feature-test"},
		{"branch with spaces", "branch-with-spaces"},
		{"--leading-dashes", "leading-dashes"},
		{"..leading-dots", "leading-dots"},
		{"v1.2.3", "v1.2.3"},
		{"", "latest"},
		{"a/b/c/d/e", "a-b-c-d-e"},
		{strings.Repeat("a", 140), strings.Repeat("a", 128)},
		{"trailing-", "trailing-"},
		{"!!!", "latest"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.branch, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeImageTag(tt.branch); got != tt.want {
				t.Errorf("sanitizeImageTag(%q) = %q, want %q", tt.branch, got, tt.want)
			}
		})
	}
}

func TestParseADORepoURL(t *testing.T) {
	t.Parallel()
	want := adoRepo{Org: "myorg", Project: "My Project", Repo: "my-repo"}
	tests := []struct {
		name string
		url  string
		want adoRepo
		ok   bool
	}{
		{"dev.azure.com", "https://dev.azure.com/myorg/My%20Project/_git/my-repo", want, true},
		{"user at dev.azure.com", "https://myorg@dev.azure.com/myorg/My%20Project/_git/my-repo", want, true},
		{"trailing slash and .git", "https://dev.azure.com/myorg/My%20Project/_git/my-repo.git/", want, true},
		{"query and extra path", "https://dev.azure.com/myorg/My%20Project/_git/my-repo/branches?x=1", want, true},
		{"visualstudio.com", "https://myorg.visualstudio.com/My%20Project/_git/my-repo", want, true},
		{"visualstudio.com DefaultCollection", "https://myorg.visualstudio.com/DefaultCollection/My%20Project/_git/my-repo", want, true},
		{"ssh", "git@ssh.dev.azure.com:v3/myorg/My%20Project/my-repo", want, true},
		{"gitlab", "https://gitlab.com/group/repo.git", adoRepo{}, false},
		{"github", "https://github.com/org/repo", adoRepo{}, false},
		{"no _git", "https://dev.azure.com/myorg/proj/repo", adoRepo{}, false},
		{"empty", "", adoRepo{}, false},
		{"not a url", "::::", adoRepo{}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseADORepoURL(tt.url)
			if ok != tt.ok || got != tt.want {
				t.Errorf("parseADORepoURL(%q) = %+v, %v; want %+v, %v", tt.url, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event":"pre-deploy"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))

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

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	// env adds a webhook secret unless the map sets one.
	env := func(m map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := m[k]; ok {
				return v
			}
			if k == "CI_TRIGGER_WEBHOOK_SECRET" {
				return "s"
			}
			return ""
		}
	}

	t.Run("empty secret fails closed", func(t *testing.T) {
		t.Parallel()
		if _, err := loadConfig(env(map[string]string{"CI_TRIGGER_WEBHOOK_SECRET": ""})); err == nil {
			t.Error("loadConfig without secret succeeded")
		}
		cfg, err := loadConfig(env(map[string]string{"CI_TRIGGER_WEBHOOK_SECRET": "", "ALLOW_UNSIGNED": "true"}))
		if err != nil || !cfg.AllowUnsigned {
			t.Errorf("ALLOW_UNSIGNED=true: cfg.AllowUnsigned=%v err=%v", cfg.AllowUnsigned, err)
		}
	})

	t.Run("protected tags", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(nil))
		if err != nil {
			t.Fatal(err)
		}
		for tag, want := range map[string]bool{
			"latest": true, "latest-dev": true, "v1.2.3": true, "1.2.3-rc1": true, "1.2.3.4": true,
			"feature-x": false, "main": false, "latest-feature": false, "v1.2": false,
		} {
			if got := cfg.isProtected(tag); got != want {
				t.Errorf("isProtected(%q) = %v, want %v", tag, got, want)
			}
		}
		cfg, err = loadConfig(env(map[string]string{"PROTECTED_TAGS": "^stable$", "FALLBACK_TAG": "dev-base"}))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.isProtected("stable") || !cfg.isProtected("dev-base") || cfg.isProtected("latest") {
			t.Error("custom PROTECTED_TAGS not used")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(nil))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ShutdownTimeout != 30*time.Second || cfg.AllowUnsigned {
			t.Errorf("ShutdownTimeout = %s, AllowUnsigned = %v", cfg.ShutdownTimeout, cfg.AllowUnsigned)
		}
		if cfg.ListenAddr != ":8080" || cfg.FallbackTag != "latest-dev" || cfg.PipelineSourceBranch != "refs/heads/main" ||
			cfg.PollInterval != 15*time.Second || cfg.BuildTimeout != 25*time.Minute || cfg.CacheTTL != 5*time.Minute ||
			!cfg.DefaultBranches["main"] || !cfg.DefaultBranches["master"] || cfg.ImageRepoPrefix != "" {
			t.Errorf("unexpected defaults: %+v", cfg)
		}
		if cfg.RegistryAuth != "" || cfg.ADOAuth != "" {
			t.Errorf("auth = %q/%q, want none", cfg.RegistryAuth, cfg.ADOAuth)
		}
	})

	t.Run("workload identity when AZURE_CLIENT_ID is set", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(map[string]string{"AZURE_CLIENT_ID": "id", "ADO_PAT": "pat", "REGISTRY_URL": "https://x.azurecr.io/"}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RegistryAuth != authWorkloadIdentity || cfg.ADOAuth != authWorkloadIdentity {
			t.Errorf("auth = %q/%q", cfg.RegistryAuth, cfg.ADOAuth)
		}
		if cfg.RegistryURL != "x.azurecr.io" {
			t.Errorf("RegistryURL = %q", cfg.RegistryURL)
		}
	})

	t.Run("static modes", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(map[string]string{
			"REGISTRY_USERNAME": "u", "REGISTRY_PASSWORD": "p", "ADO_PAT": "pat",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RegistryAuth != authBasic || cfg.ADOAuth != authPAT {
			t.Errorf("auth = %q/%q", cfg.RegistryAuth, cfg.ADOAuth)
		}
	})

	t.Run("explicit mode wins", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(map[string]string{"AZURE_CLIENT_ID": "id", "ADO_AUTH": "pat", "ADO_PAT": "x"}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ADOAuth != authPAT || cfg.RegistryAuth != authWorkloadIdentity {
			t.Errorf("auth = %q/%q", cfg.RegistryAuth, cfg.ADOAuth)
		}
	})

	t.Run("lists", func(t *testing.T) {
		t.Parallel()
		cfg, err := loadConfig(env(map[string]string{
			"CHART_EXTRA_IMAGES": "pdf=gotenberg, pdf=helper ,api=worker",
			"DEFAULT_BRANCHES":   "develop, trunk",
			"IMAGE_REPO_PREFIX":  "dev/",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(cfg.reposFor("pdf"), ","); got != "dev/pdf,dev/gotenberg,dev/helper" {
			t.Errorf("reposFor(pdf) = %s", got)
		}
		if got := strings.Join(cfg.reposFor("web"), ","); got != "dev/web" {
			t.Errorf("reposFor(web) = %s", got)
		}
		if !cfg.DefaultBranches["develop"] || !cfg.DefaultBranches["trunk"] || cfg.DefaultBranches["main"] {
			t.Errorf("DefaultBranches = %v", cfg.DefaultBranches)
		}
	})

	for _, bad := range []map[string]string{
		{"CHART_EXTRA_IMAGES": "pdf"},
		{"CHART_EXTRA_IMAGES": "=x"},
		{"REGISTRY_AUTH": "token"},
		{"ADO_AUTH": "basic"},
		{"PROTECTED_TAGS": "("},
		{"FALLBACK_TAG": "bad tag"},
	} {
		bad := bad
		t.Run("invalid "+strings.Join(keys(bad), ","), func(t *testing.T) {
			t.Parallel()
			if _, err := loadConfig(env(bad)); err == nil {
				t.Errorf("loadConfig(%v) succeeded, want error", bad)
			}
		})
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestJWTExpiry(t *testing.T) {
	t.Parallel()
	// Header and signature are not checked. Payload: {"exp":2000000000}
	tok := "eyJhbGciOiJub25lIn0.eyJleHAiOjIwMDAwMDAwMDB9.sig"
	if got := jwtExpiry(tok); got.Unix() != 2000000000 {
		t.Errorf("jwtExpiry = %v", got)
	}
	if !jwtExpiry("opaque").IsZero() {
		t.Error("jwtExpiry(opaque) is not zero")
	}
}

// ---------------------------------------------------------------------------
// HTTP endpoints
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	healthHandler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()

	t.Run("ready", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, nil)
		rr := httptest.NewRecorder()
		e.h.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if e.cred.count(acrScope) != 1 || e.cred.count(adoScope) != 1 || e.acr.exchangeCount() != 1 {
			t.Errorf("token calls: acr=%d ado=%d exchange=%d", e.cred.count(acrScope), e.cred.count(adoScope), e.acr.exchangeCount())
		}
	})

	t.Run("credential fails", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, nil)
		e.cred.err = errFake
		rr := httptest.NewRecorder()
		e.h.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "registry") {
			t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("no ADO auth", func(t *testing.T) {
		t.Parallel()
		e := newTestEnv(t, func(c *config) { c.ADOAuth = "" })
		rr := httptest.NewRecorder()
		e.h.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "azure devops") {
			t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})
}

func TestHook_MethodAndSignature(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.Secret = "s3cret" })
	mux := e.h.routes()

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/hook", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rr.Code)
	}

	body := `{"event":"pre-deploy","instance":{"id":"1","name":"x","namespace":"y"}}`
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	req.Header.Set("X-StackManager-Signature", "sha256=bad")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("bad signature status = %d", rr.Code)
	}

	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(body))
	req = httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	req.Header.Set("X-StackManager-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if res := parseStream(t, rr.Body.String()); rr.Code != http.StatusOK || !res.resp.Allowed {
		t.Errorf("good signature: status = %d, resp = %+v", rr.Code, res.resp)
	}
}

// ---------------------------------------------------------------------------
// Hook flow
// ---------------------------------------------------------------------------

func TestHook_SkipsChartWithoutPipeline(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	res := e.post(t, envelope("feature/x",
		ChartRef{Name: "redis", Branch: "feature/x"},
		ChartRef{Name: "api", Branch: "v1.2.3", BuildPipelineID: "42", SourceRepoURL: "https://dev.azure.com/org/proj/_git/api"},
	))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.acr.putCount() != 0 || e.ado.queuedCount() != 0 || e.cred.count(acrScope) != 0 {
		t.Errorf("gate touched registry or ADO; logs:\n%s", res.logText())
	}
	if !strings.Contains(res.logText(), "no build_pipeline_id") || !strings.Contains(res.logText(), "release version") {
		t.Errorf("missing skip logs:\n%s", res.logText())
	}
}

func TestHook_AliasCreatedForMissingBranch(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", ociIndexType, `{"index":"fallback"}`)
	// A longer branch with the same prefix must not count as a match.
	e.ado.refs["org/proj/api"] = []string{"main", "feature/x-longer"}

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if got, want := e.acr.digest("dev/api", "feature-x"), e.acr.digest("dev/api", "latest-dev"); got != want {
		t.Errorf("alias digest = %s, want %s", got, want)
	}
	if ct := e.acr.contentType("dev/api", "feature-x"); ct != ociIndexType {
		t.Errorf("alias content type = %q", ct)
	}
	if !strings.Contains(res.logText(), "does not exist") || !strings.Contains(res.logText(), "alias of latest-dev") {
		t.Errorf("missing alias log:\n%s", res.logText())
	}
	if e.ado.queuedCount() != 0 {
		t.Error("gate queued a build for a missing branch")
	}
}

func TestHook_AliasSkippedWhenDigestEqual(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"fallback"}`)

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.acr.putCount() != 0 {
		t.Errorf("PUT count = %d, want 0", e.acr.putCount())
	}
	if !strings.Contains(res.logText(), "already points to latest-dev") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_DefaultBranchKeepsCIImage(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "main", dockerV2Type, `{"m":"ci-main"}`)
	e.ado.refs["org/proj/api"] = []string{"main"}

	res := e.post(t, envelope("", appChart("api", "main")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.acr.digest("dev/api", "main") != digestOf([]byte(`{"m":"ci-main"}`)) || e.acr.putCount() != 0 {
		t.Error("gate overwrote the CI image of the default branch")
	}
	if !strings.Contains(res.logText(), "keeping existing dev/api:main") || e.ado.queuedCount() != 0 {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_DefaultBranchAliasCreated(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)

	res := e.post(t, envelope("", appChart("api", "master")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.acr.digest("dev/api", "master") != e.acr.digest("dev/api", "latest-dev") {
		t.Error("master is not an alias of latest-dev")
	}
}

func TestHook_ExistingRealTagNotOverwritten(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"real"}`)
	// The branch is gone from the repo, but its image stays.
	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.acr.putCount() != 0 || e.acr.digest("dev/api", "feature-x") != digestOf([]byte(`{"m":"real"}`)) {
		t.Error("gate overwrote a real image")
	}
	if !strings.Contains(res.logText(), "keeping existing dev/api:feature-x") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_ProtectedTags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		branch    string
		push      bool
		wantAllow bool
		wantText  string
	}{
		{"latest exists", "latest", true, true, "protected tag"},
		{"latest missing", "latest", false, false, "protected tag"},
		{"fallback tag from branch", "Latest-Dev", true, true, "protected tag"},
		{"fallback tag missing", "Latest-Dev", false, false, "protected tag"},
		{"semver case-insensitive is skipped", "V1.2.3", false, true, "release version v1.2.3"},
		{"semver pre-release is skipped", "1.4.0-RC.1", false, true, "release version 1.4.0-rc.1"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			tag := sanitizeImageTag(tt.branch)
			if tt.push {
				e.acr.push("dev/api", tag, dockerV2Type, `{"m":"`+tag+`"}`)
			}
			e.ado.refs["org/proj/api"] = []string{tt.branch}
			chart := appChart("api", tt.branch)
			chart.ImageTag = ""

			res := e.post(t, envelope("", chart))
			if res.resp.Allowed != tt.wantAllow {
				t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
			}
			if text := res.resp.Message + res.logText(); !strings.Contains(text, tt.wantText) {
				t.Errorf("output does not contain %q:\n%s", tt.wantText, text)
			}
			if e.acr.putCount() != 0 || e.ado.queuedCount() != 0 {
				t.Errorf("puts = %d, queued = %d; want 0/0", e.acr.putCount(), e.ado.queuedCount())
			}
		})
	}
}

func TestHook_InvalidInputDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		chart    ChartRef
		wantText string
	}{
		{"bad repo", func() ChartRef { c := appChart("Bad Name", "feature/x"); return c }(), "not a valid repository"},
		{"bad tag", func() ChartRef { c := appChart("api", "feature/x"); c.ImageTag = "-bad"; return c }(), "not a valid tag"},
		{"dotdot branch", appChart("api", "feature/../x"), "is not allowed"},
		{"leading dash branch", appChart("api", "-x"), "is not allowed"},
		{"leading slash branch", appChart("api", "/x"), "is not allowed"},
		{"shell chars in branch", appChart("api", "a;rm -rf"), "is not allowed"},
		{"bad branch with non-ADO source", func() ChartRef {
			c := appChart("api", "$(id)")
			c.SourceRepoURL = ""
			return c
		}(), "is not allowed"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
			res := e.post(t, envelope("", tt.chart))
			if res.resp.Allowed || !strings.Contains(res.resp.Message, tt.wantText) {
				t.Errorf("resp = %+v", res.resp)
			}
			if e.cred.count(acrScope)+e.cred.count(adoScope) != 0 {
				t.Error("gate called the registry or ADO before the input check")
			}
		})
	}
}

func TestHook_OrgMismatchDenied(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	chart := appChart("api", "feature/x")
	chart.SourceRepoURL = "https://dev.azure.com/OtherOrg/proj/_git/api"
	res := e.post(t, envelope("", chart))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, `"OtherOrg" is not ADO_ORG`) {
		t.Errorf("resp = %+v", res.resp)
	}
	if e.cred.count(adoScope) != 0 {
		t.Error("gate called ADO for another organization")
	}

	// The org check ignores case, and the project may differ.
	e2 := newTestEnv(t, nil)
	e2.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	chart.SourceRepoURL = "https://dev.azure.com/ORG/other-project/_git/api"
	if res := e2.post(t, envelope("", chart)); !res.resp.Allowed {
		t.Errorf("same org, other project: resp = %+v", res.resp)
	}
}

func TestHook_TagEqualsFallbackNeverBuilds(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"latest-dev"}
	res := e.post(t, envelope("", appChart("api", "latest-dev")))
	if !res.resp.Allowed || e.ado.queuedCount() != 0 || e.acr.putCount() != 0 {
		t.Errorf("resp = %+v, queued = %d, puts = %d", res.resp, e.ado.queuedCount(), e.acr.putCount())
	}
}

func TestHook_BuildDidNotPushDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"fallback"}`) // alias
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	// The build succeeds but pushes nothing. The tag is still the alias.

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "did not push imageTag feature-x to dev/api") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_PollErrorsDeny(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.failBuildGets = true

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "5 times in a row") {
		t.Errorf("resp = %+v", res.resp)
	}
	if n := e.ado.getCount(); n != maxPollErrors {
		t.Errorf("build reads = %d, want %d", n, maxPollErrors)
	}
}

func TestHook_FirstFailureStopsOtherCharts(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	// "web" needs a build that never ends. "api" fails at once (no fallback).
	e.acr.push("dev/web", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/web"] = []string{"feature/x"}
	e.ado.queuePolls = 1 << 30

	start := time.Now()
	res := e.post(t, envelope("", appChart("web", "feature/x"), appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "api:") || strings.Contains(res.resp.Message, "web:") {
		t.Errorf("resp = %+v", res.resp)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("response took %s; the other chart did not stop", d)
	}
	n := e.ado.getCount()
	time.Sleep(50 * time.Millisecond)
	if e.ado.getCount() != n {
		t.Error("gate still polls after the response")
	}
}

func TestHook_ClientDisconnectStopsPolling(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.queuePolls = 1 << 30

	body, _ := json.Marshal(envelope("", appChart("api", "feature/x")))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(string(body))).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		e.h.hookHandler(httptest.NewRecorder(), req)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for e.ado.getCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after the client went away")
	}
	n := e.ado.getCount()
	time.Sleep(50 * time.Millisecond)
	if e.ado.getCount() != n {
		t.Error("gate still polls after the client went away")
	}
}

func TestHook_MissingFallbackDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "fallback dev/api:latest-dev does not exist") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_ExtraImagesAliased(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.ExtraImages = map[string][]string{"pdf": {"gotenberg"}} })
	e.acr.push("dev/pdf", "latest-dev", dockerV2Type, `{"m":"pdf"}`)
	e.acr.push("dev/gotenberg", "latest-dev", dockerV2Type, `{"m":"gotenberg"}`)

	res := e.post(t, envelope("", appChart("pdf", "feature/y")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	for _, repo := range []string{"dev/pdf", "dev/gotenberg"} {
		if e.acr.digest(repo, "feature-y") != e.acr.digest(repo, "latest-dev") {
			t.Errorf("%s:feature-y is not an alias", repo)
		}
	}
}

func TestHook_ExistingBranchImageAllows(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"branch-build"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	if e.ado.queuedCount() != 0 || e.acr.putCount() != 0 {
		t.Errorf("queued=%d puts=%d, want 0/0", e.ado.queuedCount(), e.acr.putCount())
	}

	// The second deploy uses the cache.
	res = e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed || !strings.Contains(res.logText(), "(cached)") {
		t.Errorf("second deploy: resp = %+v\n%s", res.resp, res.logText())
	}
}

func TestHook_StaleAliasTriggersBuild(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"fallback"}`) // old alias
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.onQueueSuccess = func(tag string) { e.acr.push("dev/api", tag, dockerV2Type, `{"m":"built"}`) }

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if e.ado.queuedCount() != 1 {
		t.Fatalf("queued = %d, want 1", e.ado.queuedCount())
	}
	q := e.ado.firstQueued()
	if q.Definition.ID != 42 || q.SourceBranch != "refs/heads/main" ||
		q.TemplateParameters["branch"] != "feature/x" || q.TemplateParameters["imageTag"] != "feature-x" {
		t.Errorf("queued build = %+v", q)
	}
	if e.acr.digest("dev/api", "feature-x") != digestOf([]byte(`{"m":"built"}`)) {
		t.Error("tag does not hold the built image")
	}
	for _, want := range []string{"is an alias of latest-dev", "Queued build #101", "https://ado.example/build/101", "succeeded"} {
		if !strings.Contains(res.logText(), want) {
			t.Errorf("logs do not contain %q:\n%s", want, res.logText())
		}
	}
}

func TestHook_MissingImageTagUsesSanitizer(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"Feature/Mixed_Case"}
	e.ado.onQueueSuccess = func(tag string) { e.acr.push("dev/api", tag, dockerV2Type, `{"m":"built"}`) }

	chart := appChart("api", "Feature/Mixed_Case")
	chart.ImageTag = ""
	res := e.post(t, envelope("", chart))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if got := e.ado.firstQueued().TemplateParameters["imageTag"]; got != "feature-mixed-case" {
		t.Errorf("imageTag = %q", got)
	}
}

func TestHook_ReusesRunningBuild(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.omitListTP = true // force a read of each build
	e.ado.addRunning(7, 42, "other-tag", nil)
	e.ado.addRunning(8, 42, "feature-x", func() { e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"built"}`) })

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if e.ado.queuedCount() != 0 {
		t.Errorf("queued = %d, want 0", e.ado.queuedCount())
	}
	if !strings.Contains(res.logText(), "Reusing running build #8") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_BuildFailureDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.push("dev/web", "latest-dev", dockerV2Type, `{"m":"fallback-web"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.nextResult = "failed"

	// "web" has no branch and is aliased. "api" fails. The deploy is denied.
	res := e.post(t, envelope("", appChart("api", "feature/x"), appChart("web", "feature/x")))
	if res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	for _, want := range []string{"api:", `result "failed"`, "https://ado.example/build/101"} {
		if !strings.Contains(res.resp.Message, want) {
			t.Errorf("message %q does not contain %q", res.resp.Message, want)
		}
	}
	if strings.Contains(res.resp.Message, "web:") {
		t.Errorf("message names the passing chart: %q", res.resp.Message)
	}
}

func TestHook_BuildTimeoutDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.BuildTimeout = 30 * time.Millisecond; c.PollInterval = time.Hour })
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "did not finish within") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_BuildSucceedsButImageMissingDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.ExtraImages = map[string][]string{"api": {"api-worker"}} })
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	// The pipeline pushes only the main image, not the extra one.
	e.ado.onQueueSuccess = func(tag string) { e.acr.push("dev/api", tag, dockerV2Type, `{"m":"built"}`) }

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "did not push imageTag feature-x to dev/api-worker") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_NonADOSourceAssumesBranchExists(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "feature-x", dockerV2Type, `{"m":"built"}`)
	chart := appChart("api", "feature/x")
	chart.SourceRepoURL = "https://gitlab.com/group/api.git"

	res := e.post(t, envelope("", chart))
	if !res.resp.Allowed || !strings.Contains(res.logText(), "assuming branch") {
		t.Errorf("resp = %+v\n%s", res.resp, res.logText())
	}
}

func TestHook_RefsErrorDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.cred.err = errFake // no ADO token
	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "check branch") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_MissingInstanceDenies(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	res := e.post(t, EventEnvelope{Event: "pre-deploy"})
	if res.resp.Allowed {
		t.Errorf("resp = %+v", res.resp)
	}
}

// ---------------------------------------------------------------------------
// Registry auth
// ---------------------------------------------------------------------------

func TestACR_WorkloadIdentityTokensCached(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "t", dockerV2Type, `{}`)
	reg := e.h.registry.(*acrClient)
	for i := 0; i < 3; i++ {
		if d, err := reg.headDigest(t.Context(), "dev/api", "t"); err != nil || d == "" {
			t.Fatalf("headDigest = %q, %v", d, err)
		}
	}
	if e.acr.exchangeCount() != 1 || e.cred.count(acrScope) != 1 {
		t.Errorf("exchanges = %d, entra calls = %d; want 1/1", e.acr.exchangeCount(), e.cred.count(acrScope))
	}
}

func TestACR_StaleTokenRetried(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "t", dockerV2Type, `{}`)
	reg := e.h.registry.(*acrClient)
	reg.tokens.put("repo:dev/api", "stale", time.Now().Add(time.Hour))
	if d, err := reg.headDigest(t.Context(), "dev/api", "t"); err != nil || d == "" {
		t.Fatalf("headDigest = %q, %v", d, err)
	}
	if v, _ := reg.tokens.get("repo:dev/api"); v != "acc|repository:dev/api:pull,push" {
		t.Errorf("cached token = %q, want the new token", v)
	}
}

func TestManifestPathEscapes(t *testing.T) {
	t.Parallel()
	if got := manifestPath("dev/a b", "x?y"); got != "/v2/dev/a%20b/manifests/x%3Fy" {
		t.Errorf("manifestPath = %q", got)
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	t.Parallel()
	stopped := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // a hook that waits for a build
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

func TestACR_BasicAuth(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.RegistryAuth = authBasic })
	e.acr.push("dev/api", "t", dockerV2Type, `{}`)
	reg := e.h.registry.(*acrClient)
	if d, err := reg.headDigest(t.Context(), "dev/api", "t"); err != nil || d == "" {
		t.Fatalf("headDigest = %q, %v", d, err)
	}
	if err := reg.ping(t.Context()); err != nil {
		t.Errorf("ping: %v", err)
	}
	if e.cred.count(acrScope) != 0 {
		t.Error("basic mode used the Entra credential")
	}
	reg.password = "wrong"
	reg.tokens.drop("repo:dev/api")
	if _, err := reg.headDigest(t.Context(), "dev/api", "t"); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("headDigest with wrong password: %v", err)
	}
}

func TestADO_PATAuthHeader(t *testing.T) {
	t.Parallel()
	a := newADOClient("o", "p", authPAT, "secret-pat", "refs/heads/main", nil)
	h, err := a.authHeader(t.Context())
	if err != nil || h != basicAuth("", "secret-pat") {
		t.Errorf("authHeader = %q, %v", h, err)
	}
}
