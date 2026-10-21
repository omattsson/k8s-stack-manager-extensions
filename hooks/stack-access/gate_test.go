package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestGate(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st, _ := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", "demo-password-123456789", true),
		stackNamespace("stack-off-bob", "off"),
		accessSecret("stack-off-bob", "off", "off-password-1234567890", false),
		stackNamespace("stack-new-carol", "new"),
	)
	g := &gate{store: st, metrics: newMetrics(), cfg: cfg}

	tests := []struct {
		name      string
		host      string
		xff       []string
		user      string
		pass      string
		want      int
		wantRealm string
	}{
		{name: "bypass range without credentials", host: "demo.example.com", xff: []string{"203.0.113.9"}, want: 200},
		{name: "other IP without credentials", host: "demo.example.com", xff: []string{"198.51.100.7"}, want: 401, wantRealm: "demo"},
		{name: "right credentials", host: "demo.example.com", xff: []string{"198.51.100.7"}, user: "demo", pass: "demo-password-123456789", want: 200},
		{name: "host with port and upper case", host: "Demo.Example.dev:443", xff: []string{"198.51.100.7"}, user: "demo", pass: "demo-password-123456789", want: 200},
		{name: "wrong password", host: "demo.example.com", xff: []string{"198.51.100.7"}, user: "demo", pass: "nope", want: 401},
		{name: "wrong user", host: "demo.example.com", xff: []string{"198.51.100.7"}, user: "admin", pass: "demo-password-123456789", want: 401},
		{name: "credentials of another stack", host: "demo.example.com", xff: []string{"198.51.100.7"}, user: "off", pass: "off-password-1234567890", want: 401},
		{name: "password turned off", host: "off.example.com", xff: []string{"198.51.100.7"}, want: 200},
		{name: "no secret yet fails closed", host: "new.example.com", xff: []string{"198.51.100.7"}, want: 401},
		{name: "unknown stack", host: "ghost.example.com", xff: []string{"198.51.100.7"}, want: 401},
		{name: "no host", host: "", xff: []string{"198.51.100.7"}, want: 401},
		{name: "spoofed bypass address before the real one", host: "demo.example.com", xff: []string{"203.0.113.9, 198.51.100.7"}, want: 401},
		{name: "spoofed bypass header line before the real one", host: "demo.example.com", xff: []string{"203.0.113.9", "198.51.100.7"}, want: 401},
		{name: "no forwarded address", host: "demo.example.com", want: 401},
		{name: "invalid forwarded address", host: "demo.example.com", xff: []string{"not-an-ip"}, want: 401},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			if tt.host != "" {
				r.Header.Set("X-Forwarded-Host", tt.host)
			}
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			r.Header.Set("X-Forwarded-Uri", "/page?token=secret")
			if tt.user != "" || tt.pass != "" {
				r.SetBasicAuth(tt.user, tt.pass)
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if tt.want == 401 {
				h := w.Header().Get("WWW-Authenticate")
				if !strings.HasPrefix(h, `Basic realm="`) {
					t.Errorf("WWW-Authenticate = %q", h)
				}
				if tt.wantRealm != "" && !strings.Contains(h, `realm="`+tt.wantRealm+`"`) {
					t.Errorf("WWW-Authenticate = %q, want realm %q", h, tt.wantRealm)
				}
			}
		})
	}
}

func TestGateNotSynced(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st := &store{cfg: cfg} // never synced
	g := &gate{store: st, metrics: newMetrics(), cfg: cfg}
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.Header.Set("X-Forwarded-Host", "demo.example.com")
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestGateAmbiguousInstance(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st, _ := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", "demo-password-123456789", true),
		stackNamespace("stack-demo-bob", "demo"),
		accessSecret("stack-demo-bob", "demo", "other-password-12345678", true),
	)
	g := &gate{store: st, metrics: newMetrics(), cfg: cfg}
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.Header.Set("X-Forwarded-Host", "demo.example.com")
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	r.SetBasicAuth("demo", "demo-password-123456789")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for two namespaces with one name", w.Code)
	}
}

func TestForwardedPathDropsQuery(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.Header.Set("X-Forwarded-Uri", "/login?token=abc#frag")
	if got := forwardedPath(r); got != "/login" {
		t.Fatalf("forwardedPath = %q", got)
	}
}

func TestGateEdgeCases(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	broken := accessSecret("stack-broken-frank", "broken", "", true)
	st, _ := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
		stackNamespace("stack-broken-frank", "broken"),
		broken,
		stackNamespace("stack-old-gina", "OldName"),
		accessSecret("stack-old-gina", "OldName", "old-password-1234567890", true),
	)
	g := &gate{store: st, metrics: newMetrics(), cfg: cfg}
	tests := []struct {
		name string
		host string
		xff  string
		user string
		pass string
		want int
	}{
		{name: "IPv4-mapped IPv6 address in the bypass range", host: "demo.example.com", xff: "::ffff:203.0.113.9", want: 200},
		{name: "host with a trailing dot", host: "demo.example.com.", xff: "198.51.100.7", user: "demo", pass: demoPassword, want: 200},
		{name: "secret without a password fails closed", host: "broken.example.com", xff: "198.51.100.7", user: "broken", pass: "", want: 401},
		{name: "upper-case instance label matches the lower-case host", host: "oldname.example.com", xff: "198.51.100.7", user: "OldName", pass: "old-password-1234567890", want: 200},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.Header.Set("X-Forwarded-Host", tt.host)
			r.Header.Set("X-Forwarded-For", tt.xff)
			if tt.user != "" {
				r.SetBasicAuth(tt.user, tt.pass)
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestGateSharedCredentials(t *testing.T) {
	t.Parallel()
	const sharedPass = "shared-password-1234567"
	objs := []runtime.Object{
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
		stackNamespace("stack-other-bob", "other"),
		accessSecret("stack-other-bob", "other", "other-password-12345678", true),
		stackNamespace("stack-new-carol", "new"),
		stackNamespace("stack-twin-a", "twin"),
		stackNamespace("stack-twin-b", "twin"),
	}
	withShared := testConfig(t, map[string]string{"SHARED_CREDENTIALS": "ci:" + sharedPass})
	st, _ := newTestStore(t, withShared, objs...)
	g := &gate{store: st, metrics: newMetrics(), cfg: withShared}

	withoutShared := testConfig(t, nil)
	st2, _ := newTestStore(t, withoutShared, objs...)
	g2 := &gate{store: st2, metrics: newMetrics(), cfg: withoutShared}

	// The parallel subtests end before the cleanup of the parent runs.
	t.Cleanup(func() {
		g.metrics.mu.Lock()
		defer g.metrics.mu.Unlock()
		if g.metrics.auth[resultShared] != 3 {
			t.Errorf("shared results = %d, want 3", g.metrics.auth[resultShared])
		}
	})

	tests := []struct {
		name string
		g    *gate
		host string
		user string
		pass string
		want int
	}{
		{name: "shared on one stack", g: g, host: "demo.example.com", user: "ci", pass: sharedPass, want: 200},
		{name: "shared on another stack", g: g, host: "other.example.com", user: "ci", pass: sharedPass, want: 200},
		{name: "shared on a stack without a secret yet", g: g, host: "new.example.com", user: "ci", pass: sharedPass, want: 200},
		{name: "own credentials still work", g: g, host: "demo.example.com", user: "demo", pass: demoPassword, want: 200},
		{name: "shared with a wrong password", g: g, host: "demo.example.com", user: "ci", pass: "nope", want: 401},
		{name: "shared password with a wrong user", g: g, host: "demo.example.com", user: "admin", pass: sharedPass, want: 401},
		{name: "shared on two namespaces with one name", g: g, host: "twin.example.com", user: "ci", pass: sharedPass, want: 401},
		{name: "shared on an unknown host", g: g, host: "ghost.example.com", user: "ci", pass: sharedPass, want: 401},
		{name: "shared not configured", g: g2, host: "demo.example.com", user: "ci", pass: sharedPass, want: 401},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.Header.Set("X-Forwarded-Host", tt.host)
			r.Header.Set("X-Forwarded-For", "198.51.100.7")
			r.SetBasicAuth(tt.user, tt.pass)
			w := httptest.NewRecorder()
			tt.g.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}
