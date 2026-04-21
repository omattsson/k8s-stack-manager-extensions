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

func TestHealthHandler_KubectlPresent(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not in PATH, skipping")
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	rw := httptest.NewRecorder()
	healthHandler(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rw.Code)
	}
}

func TestHealthHandler_KubectlMissing(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err == nil {
		t.Skip("kubectl is present, skipping missing-kubectl test")
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	rw := httptest.NewRecorder()
	healthHandler(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rw.Code)
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
	defer func() { secret = "" }()
	if !verifySignature([]byte("anything"), "") {
		t.Error("empty secret should skip verification")
	}
}

func TestActionHandler_InvalidMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/action", nil)
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}

func TestActionHandler_InvalidSignature(t *testing.T) {
	secret = "testsecret"
	defer func() { secret = "" }()

	body := []byte(`{"foo":"bar"}`)
	req := httptest.NewRequest("POST", "/action", strings.NewReader(string(body)))
	req.Header.Set("X-StackManager-Signature", "sha256=deadbeef")
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestActionHandler_InvalidJSON(t *testing.T) {
	secret = ""
	defer func() { secret = "" }()

	req := httptest.NewRequest("POST", "/action", strings.NewReader("not json"))
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestActionHandler_MissingInstance(t *testing.T) {
	secret = ""
	defer func() { secret = "" }()

	ar := ActionRequest{
		Action:    "collect-debug-bundle",
		RequestID: "req-test",
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/action", strings.NewReader(string(body)))
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
	respBody, _ := io.ReadAll(rw.Body)
	if !strings.Contains(string(respBody), "instance required") {
		t.Errorf("expected 'instance required' in body, got %s", respBody)
	}
}

func TestActionHandler_MissingNamespace(t *testing.T) {
	secret = ""
	defer func() { secret = "" }()

	ar := ActionRequest{
		Action:    "collect-debug-bundle",
		RequestID: "req-test",
		Instance:  &InstanceRef{Name: "demo"},
	}
	body, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/action", strings.NewReader(string(body)))
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
	respBody, _ := io.ReadAll(rw.Body)
	if !strings.Contains(string(respBody), "namespace required") {
		t.Errorf("expected 'namespace required' in body, got %s", respBody)
	}
}

func TestActionHandler_NamespaceValidation(t *testing.T) {
	secret = ""
	defer func() { secret = "" }()

	cases := []struct {
		name      string
		namespace string
		wantCode  int
	}{
		{"valid", "stack-demo-alice", http.StatusOK},
		{"uppercase rejected", "Stack-Demo", http.StatusBadRequest},
		{"semicolon rejected", "ns;rm -rf /", http.StatusBadRequest},
		{"space rejected", "ns foo", http.StatusBadRequest},
		{"dot rejected", "ns.foo", http.StatusBadRequest},
		{"slash rejected", "ns/../etc", http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ar := ActionRequest{
				Action:    "collect-debug-bundle",
				RequestID: "req-test",
				Instance:  &InstanceRef{Name: "demo", Namespace: tc.namespace},
			}
			body, _ := json.Marshal(ar)
			req := httptest.NewRequest("POST", "/action", strings.NewReader(string(body)))
			rw := httptest.NewRecorder()
			actionHandler(rw, req)

			if tc.wantCode == http.StatusOK {
				// Valid namespace will try collectBundle which calls kubectl;
				// without kubectl it may 500, but it should NOT be 400
				if rw.Code == http.StatusBadRequest {
					t.Errorf("namespace %q should pass validation but got 400", tc.namespace)
				}
			} else {
				if rw.Code != http.StatusBadRequest {
					t.Errorf("namespace %q: expected 400, got %d", tc.namespace, rw.Code)
				}
			}
		})
	}
}

func TestDownloadHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/download/test.tar.gz", nil)
	rw := httptest.NewRecorder()
	downloadHandler(rw, req)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}

func TestDownloadHandler_PathTraversal(t *testing.T) {
	req := httptest.NewRequest("GET", "/download/../../etc/passwd", nil)
	rw := httptest.NewRecorder()
	downloadHandler(rw, req)
	if rw.Code != http.StatusNotFound {
		t.Errorf("expected 404 for path traversal, got %d", rw.Code)
	}
}

func TestDownloadHandler_NonTarGz(t *testing.T) {
	req := httptest.NewRequest("GET", "/download/secrets.json", nil)
	rw := httptest.NewRecorder()
	downloadHandler(rw, req)
	if rw.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-.tar.gz file, got %d", rw.Code)
	}
}

func TestDownloadHandler_NotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/download/nonexistent.tar.gz", nil)
	rw := httptest.NewRecorder()
	downloadHandler(rw, req)
	if rw.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rw.Code)
	}
}
