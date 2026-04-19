package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rw := httptest.NewRecorder()
	healthHandler(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rw.Code)
	}
}

func TestVerifySignature(t *testing.T) {
	body := []byte("test-body")
	secret = "testsecret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !verifySignature(body, expected) {
		t.Error("valid signature should verify")
	}
	if verifySignature(body, "sha256=deadbeef") {
		t.Error("invalid signature should not verify")
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
	body := []byte(`{"foo":"bar"}`)
	req := httptest.NewRequest("POST", "/action", nil)
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.Header.Set("X-StackManager-Signature", "sha256=deadbeef")
	rw := httptest.NewRecorder()
	actionHandler(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

// More tests for valid action requests, error cases, and downloadHandler can be added similarly.

// Add more tests for signature verification and main logic as needed.
