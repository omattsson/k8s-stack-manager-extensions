package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthAndReadiness(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	unsynced := &server{store: &store{cfg: cfg}, metrics: newMetrics()}
	synced, _ := newTestStore(t, cfg)
	ready := &server{store: synced, metrics: newMetrics()}
	stopping := &server{store: synced, metrics: newMetrics()}
	stopping.stopping.Store(true)

	tests := []struct {
		name string
		srv  *server
		path string
		want int
	}{
		{"healthz always", unsynced, "/healthz", 200},
		{"readyz before sync", unsynced, "/readyz", 503},
		{"readyz after sync", ready, "/readyz", 200},
		{"readyz while stopping", stopping, "/readyz", 503},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			tt.srv.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	m := newMetrics()
	m.isLeader = func() bool { return true }
	m.authResult(resultOK)
	m.authResult(resultOK)
	m.authResult(resultDenied)
	m.actionResult("show", 200)
	m.secretCreated()
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		`stack_access_auth_requests_total{result="ok"} 2`,
		`stack_access_auth_requests_total{result="denied"} 1`,
		`stack_access_action_requests_total{action="show",code="200"} 1`,
		`stack_access_secrets_created_total 1`,
		`stack_access_leader 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics miss %q:\n%s", want, body)
		}
	}
}

func TestSetupLogging(t *testing.T) {
	for _, l := range []string{"", "debug", "INFO", "warn", "error"} {
		if err := setupLogging(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
	if err := setupLogging("loud"); err == nil {
		t.Error("an unknown level must fail")
	}
	_ = setupLogging("info")
}
