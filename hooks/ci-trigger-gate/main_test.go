package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func signBody(body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func makeEnvelope(branch string, charts []ChartRef) EventEnvelope {
	return EventEnvelope{
		APIVersion: "hooks.stackmanager/v1",
		Kind:       "EventEnvelope",
		Event:      "pre-deploy",
		RequestID:  "test-req-1",
		Instance: &InstanceRef{
			ID:        "inst-1",
			Name:      "test-instance",
			Namespace: "stack-test",
			Branch:    branch,
		},
		Deployment: &DeploymentRef{ID: "dep-1"},
		Charts:     charts,
	}
}

func postHook(t *testing.T, handler http.HandlerFunc, body []byte, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(string(body)))
	if sig != "" {
		req.Header.Set("X-StackManager-Signature", sig)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Mock CI provider
// ---------------------------------------------------------------------------

type mockCI struct {
	mu             sync.Mutex
	runningBuilds  map[string]string // pipelineID+branch → buildID
	triggeredCount int
	builds         map[string]struct{ status, result string }
}

func newMockCI() *mockCI {
	return &mockCI{
		runningBuilds: make(map[string]string),
		builds:        make(map[string]struct{ status, result string }),
	}
}

func (m *mockCI) findRunningBuild(_ context.Context, pipelineID, branch string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.runningBuilds[pipelineID+"/"+branch]
	if !ok {
		return "", nil
	}
	return id, nil
}

func (m *mockCI) triggerBuild(_ context.Context, pipelineID, branch, imageTag string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triggeredCount++
	id := fmt.Sprintf("build-%d", m.triggeredCount)
	if _, exists := m.builds[id]; !exists {
		m.builds[id] = struct{ status, result string }{"completed", "succeeded"}
	}
	return id, nil
}

func (m *mockCI) getBuildStatus(_ context.Context, buildID string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.builds[buildID]
	if !ok {
		return "", "", fmt.Errorf("build %s not found", buildID)
	}
	return b.status, b.result, nil
}

func (m *mockCI) setBuildResult(buildID, status, result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.builds[buildID] = struct{ status, result string }{status, result}
}

// ---------------------------------------------------------------------------
// Mock registry
// ---------------------------------------------------------------------------

type mockRegistry struct {
	mu     sync.Mutex
	images map[string]bool // "repo:tag" → exists
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{images: make(map[string]bool)}
}

func (m *mockRegistry) setImage(repo, tag string, exists bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.images[repo+":"+tag] = exists
}

func (m *mockRegistry) imageExists(_ context.Context, repo, tag string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.images[repo+":"+tag], nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHealthHandler(t *testing.T) {
	origReg := registryURL
	origPAT := adoPAT
	defer func() { registryURL = origReg; adoPAT = origPAT }()

	t.Run("configured", func(t *testing.T) {
		registryURL = "myacr.azurecr.io"
		adoPAT = "test-pat"
		rr := httptest.NewRecorder()
		healthHandler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
			t.Fatalf("unexpected body: %s", rr.Body.String())
		}
	})

	t.Run("missing config", func(t *testing.T) {
		registryURL = ""
		adoPAT = ""
		rr := httptest.NewRecorder()
		healthHandler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rr.Code)
		}
	})
}

func TestVerifySignature(t *testing.T) {
	origSecret := secret
	defer func() { secret = origSecret }()

	body := []byte(`{"event":"pre-deploy"}`)

	t.Run("empty secret allows all", func(t *testing.T) {
		secret = ""
		if !verifySignature(body, "") {
			t.Fatal("empty secret should allow")
		}
		if !verifySignature(body, "garbage") {
			t.Fatal("empty secret should allow any sig")
		}
	})

	t.Run("valid signature", func(t *testing.T) {
		secret = "test-secret"
		sig := signBody(body, "test-secret")
		if !verifySignature(body, sig) {
			t.Fatal("valid sig should pass")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		secret = "test-secret"
		if verifySignature(body, "sha256=0000000000000000000000000000000000000000000000000000000000000000") {
			t.Fatal("invalid sig should fail")
		}
	})

	t.Run("missing signature with secret set", func(t *testing.T) {
		secret = "test-secret"
		if verifySignature(body, "") {
			t.Fatal("missing sig with secret set should fail")
		}
	})
}

func TestSanitizeBranch(t *testing.T) {
	cases := []struct {
		input, expected string
	}{
		{"feature/foo-bar", "feature-foo-bar"},
		{"Feature/FOO_BAR", "feature-foobar"},
		{"main", "main"},
		{"v1.2.3", "v1.2.3"},
		{"feature/special!@#chars", "feature-specialchars"},
		{strings.Repeat("a", 200), strings.Repeat("a", 128)},
		{"---leading", "leading"},
		{".dotted.", "dotted"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeBranch(tc.input)
			if got != tc.expected {
				t.Errorf("sanitizeBranch(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestShouldSkipChart(t *testing.T) {
	cases := []struct {
		name   string
		chart  ChartRef
		branch string
		skip   bool
	}{
		{"no pipeline ID", ChartRef{Name: "redis"}, "feature/x", true},
		{"semver branch", ChartRef{Name: "app", BuildPipelineID: "42"}, "v1.2.3", true},
		{"main branch", ChartRef{Name: "app", BuildPipelineID: "42"}, "main", true},
		{"master branch", ChartRef{Name: "app", BuildPipelineID: "42"}, "master", true},
		{"feature branch", ChartRef{Name: "app", BuildPipelineID: "42"}, "feature/foo", false},
		{"prefixed semver", ChartRef{Name: "app", BuildPipelineID: "42"}, "v2.0.0-rc1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipChart(tc.chart, tc.branch)
			if got != tc.skip {
				t.Errorf("shouldSkipChart(%v, %q) = %v, want %v", tc.chart, tc.branch, got, tc.skip)
			}
		})
	}
}

func TestHandleHook_InvalidMethod(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	h := &handler{
		registry: newMockRegistry(),
		ci:       newMockCI(),
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	req := httptest.NewRequest(http.MethodGet, "/hook", nil)
	rr := httptest.NewRecorder()
	h.hookHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandleHook_BadSignature(t *testing.T) {
	origSecret := secret
	secret = "real-secret"
	defer func() { secret = origSecret }()

	h := &handler{
		registry: newMockRegistry(),
		ci:       newMockCI(),
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	body, _ := json.Marshal(makeEnvelope("feature/x", nil))
	rr := postHook(t, h.hookHandler, body, "sha256=bad")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleHook_NoChartsWithPipeline(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	h := &handler{
		registry: newMockRegistry(),
		ci:       newMockCI(),
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{
		{Name: "redis", Version: "7.0.0"},
		{Name: "nginx", Version: "1.25.0"},
	}
	body, _ := json.Marshal(makeEnvelope("feature/x", charts))
	rr := postHook(t, h.hookHandler, body, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	if err := json.Unmarshal([]byte(lastLine), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %+v", resp)
	}
}

func TestHandleHook_ImageExists(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	reg := newMockRegistry()
	reg.setImage("app-api", "feature-foo", true)

	h := &handler{
		registry: reg,
		ci:       newMockCI(),
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{{Name: "app-api", BuildPipelineID: "42"}}
	body, _ := json.Marshal(makeEnvelope("feature/foo", charts))
	rr := postHook(t, h.hookHandler, body, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	if err := json.Unmarshal([]byte(lastLine), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %+v", resp)
	}

	// Should have LOG lines about checking + finding
	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "LOG: ") {
		t.Fatal("expected LOG lines in response")
	}
	if !strings.Contains(bodyStr, "found in registry") {
		t.Fatal("expected 'found in registry' in LOG")
	}
}

func TestHandleHook_ImageMissing_BuildSucceeds(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	reg := newMockRegistry()
	ci := newMockCI()

	h := &handler{
		registry: reg,
		ci:       ci,
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{{Name: "app-api", BuildPipelineID: "42"}}
	body, _ := json.Marshal(makeEnvelope("feature/bar", charts))
	rr := postHook(t, h.hookHandler, body, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	if err := json.Unmarshal([]byte(lastLine), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %+v", resp)
	}

	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "Triggering build") {
		t.Fatal("expected 'Triggering build' in LOG")
	}
	if !strings.Contains(bodyStr, "completed successfully") {
		t.Fatal("expected 'completed successfully' in LOG")
	}

	// Verify image is now cached
	if !h.cache.isVerified("app-api", "feature-bar") {
		t.Fatal("expected image to be cached after successful build")
	}
}

func TestHandleHook_BuildFails(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	reg := newMockRegistry()
	ci := newMockCI()
	// Override triggerBuild to return a build that fails
	ci.builds["build-1"] = struct{ status, result string }{"completed", "failed"}

	h := &handler{
		registry: reg,
		ci:       ci,
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{{Name: "app-api", BuildPipelineID: "42"}}
	body, _ := json.Marshal(makeEnvelope("feature/fail", charts))
	rr := postHook(t, h.hookHandler, body, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	if err := json.Unmarshal([]byte(lastLine), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected allowed=false, got %+v", resp)
	}
	if !strings.Contains(resp.Message, "failed") {
		t.Fatalf("expected failure message, got: %s", resp.Message)
	}
}

func TestHandleHook_AttachesToRunningBuild(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	reg := newMockRegistry()
	ci := newMockCI()
	ci.runningBuilds["42/feature/attach"] = "existing-99"
	ci.builds["existing-99"] = struct{ status, result string }{"completed", "succeeded"}

	h := &handler{
		registry: reg,
		ci:       ci,
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{{Name: "app-api", BuildPipelineID: "42"}}
	body, _ := json.Marshal(makeEnvelope("feature/attach", charts))
	rr := postHook(t, h.hookHandler, body, "")

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	json.Unmarshal([]byte(lastLine), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %+v", resp)
	}

	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "Found running build") {
		t.Fatal("expected 'Found running build' in LOG")
	}
	if ci.triggeredCount != 0 {
		t.Fatal("should not have triggered a new build")
	}
}

func TestImageCache(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newImageCache(5 * time.Minute)
	c.now = func() time.Time { return now }

	if c.isVerified("app", "v1") {
		t.Fatal("empty cache should not be verified")
	}

	c.markVerified("app", "v1")
	if !c.isVerified("app", "v1") {
		t.Fatal("should be verified after marking")
	}

	// Advance past TTL
	now = now.Add(6 * time.Minute)
	if c.isVerified("app", "v1") {
		t.Fatal("should not be verified after TTL expiry")
	}
}

func TestACRTokenExchange(t *testing.T) {
	tokenRequested := false
	manifestChecks := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/token"):
			tokenRequested = true
			json.NewEncoder(w).Encode(map[string]string{"access_token": "test-token"})

		case strings.Contains(r.URL.Path, "/v2/"):
			manifestChecks++
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	reg := &acrRegistry{
		url:      host,
		username: "user",
		password: "pass",
		client:   srv.Client(),
	}
	// Override to use http instead of https for test server
	origExists := reg.imageExists
	_ = origExists

	// Use a custom registry that overrides the URL scheme for testing
	exists, err := testACRImageExists(srv, reg, "myapp", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Fatal("expected image to exist after token exchange")
	}
	if !tokenRequested {
		t.Fatal("expected token exchange to be requested")
	}
}

// testACRImageExists tests the ACR flow using an httptest server.
func testACRImageExists(srv *httptest.Server, reg *acrRegistry, repo, tag string) (bool, error) {
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", srv.URL, repo, tag)
	accept := "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

	exists, needToken, err := reg.headManifest(context.Background(), manifestURL, accept, reg.basicAuth())
	if err != nil {
		return false, err
	}
	if !needToken {
		return exists, nil
	}

	// Token exchange — use test server URL instead of https
	tokenURL := fmt.Sprintf("%s/oauth2/token?service=%s&scope=repository:%s:pull", srv.URL, reg.url, repo)
	req, _ := http.NewRequest(http.MethodGet, tokenURL, nil)
	req.Header.Set("Authorization", reg.basicAuth())
	resp, err := reg.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tok)

	exists, _, err = reg.headManifest(context.Background(), manifestURL, accept, "Bearer "+tok.AccessToken)
	return exists, err
}

func TestHandleHook_MultipleCharts(t *testing.T) {
	origSecret := secret
	secret = ""
	defer func() { secret = origSecret }()

	reg := newMockRegistry()
	reg.setImage("app-api", "feature-multi", true)
	// app-worker not in registry → will trigger build
	ci := newMockCI()

	h := &handler{
		registry: reg,
		ci:       ci,
		cache:    newImageCache(5 * time.Minute),
		poll:     50 * time.Millisecond,
	}

	charts := []ChartRef{
		{Name: "redis"},                                            // no pipeline, skipped
		{Name: "app-api", BuildPipelineID: "42"},                   // exists in registry
		{Name: "app-worker", BuildPipelineID: "43"},                // will trigger build
	}
	body, _ := json.Marshal(makeEnvelope("feature/multi", charts))
	rr := postHook(t, h.hookHandler, body, "")

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	lastLine := lines[len(lines)-1]
	var resp HookResponse
	json.Unmarshal([]byte(lastLine), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %+v", resp)
	}

	if ci.triggeredCount != 1 {
		t.Fatalf("expected 1 build triggered, got %d", ci.triggeredCount)
	}

	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "found in registry") {
		t.Fatal("expected app-api found in registry")
	}
	if !strings.Contains(bodyStr, "Triggering build") {
		t.Fatal("expected app-worker build triggered")
	}
}

func newTestADOProvider(t *testing.T, handler http.Handler) *adoProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &adoProvider{
		pat:             "test-pat",
		client:          srv.Client(),
		baseURLOverride: srv.URL,
	}
}

func TestADOProvider_FindRunningBuild(t *testing.T) {
	p := newTestADOProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("missing auth header")
		}
		if !strings.Contains(r.URL.RawQuery, "definitions=42") {
			t.Errorf("expected definitions=42 in query, got %s", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.RawQuery, "branchName=refs") {
			t.Errorf("expected branchName in query, got %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": 123}},
		})
	}))

	id, err := p.findRunningBuild(context.Background(), "42", "feature/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "123" {
		t.Fatalf("expected build ID 123, got %s", id)
	}
}

func TestADOProvider_FindRunningBuild_NoneRunning(t *testing.T) {
	p := newTestADOProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
	}))

	id, err := p.findRunningBuild(context.Background(), "42", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "" {
		t.Fatalf("expected empty ID, got %s", id)
	}
}

func TestADOProvider_TriggerBuild(t *testing.T) {
	var receivedBody map[string]any

	p := newTestADOProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type, got %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": 456})
	}))

	id, err := p.triggerBuild(context.Background(), "42", "feature/bar", "feature-bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "456" {
		t.Fatalf("expected build ID 456, got %s", id)
	}

	def, ok := receivedBody["definition"].(map[string]any)
	if !ok {
		t.Fatal("missing definition in request body")
	}
	if defID, _ := def["id"].(float64); defID != 42 {
		t.Fatalf("expected definition.id=42, got %v", defID)
	}
	if sb, _ := receivedBody["sourceBranch"].(string); sb != "refs/heads/main" {
		t.Fatalf("expected sourceBranch=refs/heads/main, got %s", sb)
	}
	tp, _ := receivedBody["templateParameters"].(map[string]any)
	if tp == nil {
		t.Fatal("missing templateParameters in request body")
	}
	if tp["branch"] != "feature/bar" {
		t.Fatalf("expected templateParameters.branch=feature/bar, got %v", tp["branch"])
	}
	if tp["imageTag"] != "feature-bar" {
		t.Fatalf("expected templateParameters.imageTag=feature-bar, got %v", tp["imageTag"])
	}
}

func TestADOProvider_TriggerBuild_InvalidPipelineID(t *testing.T) {
	p := newTestADOProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not have made a request")
	}))

	_, err := p.triggerBuild(context.Background(), "not-a-number", "main", "main")
	if err == nil {
		t.Fatal("expected error for non-numeric pipeline ID")
	}
}

func TestADOProvider_GetBuildStatus(t *testing.T) {
	p := newTestADOProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/789") {
			t.Errorf("expected path to end with /789, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "completed",
			"result": "succeeded",
		})
	}))

	status, result, err := p.getBuildStatus(context.Background(), "789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "completed" || result != "succeeded" {
		t.Fatalf("expected completed/succeeded, got %s/%s", status, result)
	}
}

