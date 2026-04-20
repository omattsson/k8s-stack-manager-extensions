package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestHealthHandler_TrivyPresent(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not in PATH, skipping")
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	rw := httptest.NewRecorder()
	healthHandler(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rw.Code)
	}
}

func TestHealthHandler_TrivyMissing(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err == nil {
		t.Skip("trivy is present, skipping missing-trivy test")
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	rw := httptest.NewRecorder()
	healthHandler(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rw.Code)
	}
	var resp map[string]string
	json.Unmarshal(rw.Body.Bytes(), &resp)
	if resp["status"] != "error" {
		t.Errorf("expected status=error, got %q", resp["status"])
	}
}

func TestVerifySignature(t *testing.T) {
	body := []byte("test-body")
	secret = "testsecret"
	defer func() { secret = "" }()

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !verifySignature(body, validSig) {
		t.Error("valid signature should verify")
	}
	if verifySignature(body, "sha256=deadbeef") {
		t.Error("invalid signature should not verify")
	}
}

func TestVerifySignature_EmptySecret(t *testing.T) {
	secret = ""
	if !verifySignature([]byte("anything"), "") {
		t.Error("empty secret should skip verification")
	}
}

func TestHookHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/hook", nil)
	rw := httptest.NewRecorder()
	hookHandler(rw, req)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}

func TestHookHandler_InvalidSignature(t *testing.T) {
	secret = "testsecret"
	defer func() { secret = "" }()

	body := []byte(`{"event":"pre-deploy"}`)
	req := httptest.NewRequest("POST", "/hook", strings.NewReader(string(body)))
	req.Header.Set("X-StackManager-Signature", "sha256=wrong")
	rw := httptest.NewRecorder()
	hookHandler(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestHookHandler_InvalidJSON(t *testing.T) {
	secret = ""
	req := httptest.NewRequest("POST", "/hook", strings.NewReader("not json"))
	rw := httptest.NewRecorder()
	hookHandler(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestHookHandler_NoImages(t *testing.T) {
	secret = ""
	envelope := EventEnvelope{
		Event:     "pre-deploy",
		RequestID: "req-test",
		Instance:  &InstanceRef{Name: "demo", Namespace: "ns"},
	}
	body, _ := json.Marshal(envelope)
	req := httptest.NewRequest("POST", "/hook", strings.NewReader(string(body)))
	rw := httptest.NewRecorder()
	hookHandler(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.Code)
	}
	respBody, _ := io.ReadAll(rw.Body)
	var resp HookResponse
	json.Unmarshal(respBody, &resp)
	if !resp.Allowed {
		t.Error("expected allowed=true when no images found")
	}
}

func TestExtractImages_FromMetadata(t *testing.T) {
	env := &EventEnvelope{
		Metadata: map[string]string{"images": "nginx:1.25, redis:7"},
	}
	images := extractImages(env)
	if len(images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(images))
	}
	if images[0] != "nginx:1.25" || images[1] != "redis:7" {
		t.Errorf("unexpected images: %v", images)
	}
}

func TestExtractImages_FromValues(t *testing.T) {
	env := &EventEnvelope{
		Charts: []ChartRef{{Name: "web"}},
		Values: map[string]any{
			"web": map[string]any{
				"image": map[string]any{
					"repository": "myrepo/app",
					"tag":        "v1.0",
				},
			},
		},
	}
	images := extractImages(env)
	if len(images) != 1 || images[0] != "myrepo/app:v1.0" {
		t.Errorf("expected [myrepo/app:v1.0], got %v", images)
	}
}

func TestExtractImages_DefaultsToLatest(t *testing.T) {
	env := &EventEnvelope{
		Charts: []ChartRef{{Name: "web"}},
		Values: map[string]any{
			"web": map[string]any{
				"image": map[string]any{
					"repository": "myrepo/app",
				},
			},
		},
	}
	images := extractImages(env)
	if len(images) != 1 || images[0] != "myrepo/app:latest" {
		t.Errorf("expected [myrepo/app:latest], got %v", images)
	}
}
