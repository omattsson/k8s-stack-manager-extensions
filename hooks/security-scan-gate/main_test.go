package main

import (
	"net/http"
	"net/http/httptest"
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

// Add more tests for signature verification and gate logic as needed.
