package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

const demoPassword = "demo-password-123456789"

var requestSeq atomic.Int64

func actionBody(t *testing.T, ns, name string, params map[string]any, ts time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"apiVersion": "hooks.k8sstackmanager.io/v1",
		"kind":       "ActionRequest",
		"action":     "stack-access",
		"timestamp":  ts.UTC().Format(time.RFC3339Nano),
		"request_id": fmt.Sprintf("req-%d", requestSeq.Add(1)),
		"instance":   map[string]any{"id": "i-1", "name": name, "namespace": ns},
		"parameters": params,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postAction(t *testing.T, h http.Handler, op string, body []byte, signature string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("POST /actions/{op}", h)
	r := httptest.NewRequest(http.MethodPost, "/actions/"+op, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if signature != "" {
		r.Header.Set(signatureHeader, signature)
	}
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// leaderActions returns actions on a replica that leads.
func leaderActions(t *testing.T) (*actions, *store, func() map[string][]byte, *k8stesting.Fake) {
	t.Helper()
	cfg := testConfig(t, nil)
	st, client := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
		stackNamespace("stack-new-carol", "new"),
	)
	el := newElector(nil, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !el.startTerm(ctx) {
		t.Fatal("startTerm failed")
	}
	a := newActions(client, st, el, cfg, newMetrics())
	data := func() map[string][]byte {
		sec, err := client.CoreV1().Secrets("stack-demo-alice").Get(context.Background(), "stack-basic-auth", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return sec.Data
	}
	return a, st, data, &client.Fake
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", w.Body.String())
	}
	return m
}

func TestActionShow(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)
	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	w := postAction(t, a, "show", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	if m["username"] != "demo" || m["password"] != demoPassword || m["enabled"] != true || m["url"] != "https://demo.example.com" {
		t.Fatalf("unexpected result: %v", m)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("show must not be cached")
	}
}

func TestActionRequestChecks(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)
	good := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	tests := []struct {
		name string
		op   string
		body []byte
		sig  string
		want int
	}{
		{name: "no signature", op: "show", body: good, sig: "", want: 401},
		{name: "wrong signature", op: "show", body: good, sig: "sha256=00", want: 401},
		{name: "old request", op: "show", body: actionBody(t, "stack-demo-alice", "demo", nil, time.Now().Add(-10*time.Minute)), want: 401},
		{name: "no timestamp", op: "show", body: []byte(`{"kind":"ActionRequest","instance":{"name":"demo","namespace":"stack-demo-alice"}}`), want: 401},
		{name: "not an action request", op: "show", body: []byte(`{"kind":"Event"}`), want: 400},
		{name: "unknown action", op: "delete", body: good, want: 404},
		{name: "name does not match the namespace", op: "show", body: actionBody(t, "stack-demo-alice", "other", nil, time.Now()), want: 404},
		{name: "namespace is not a stack", op: "show", body: actionBody(t, "kube-system", "demo", nil, time.Now()), want: 404},
		{name: "set without enabled", op: "set", body: actionBody(t, "stack-demo-alice", "demo", nil, time.Now()), want: 400},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sig := tt.sig
			if sig == "" && tt.name != "no signature" {
				sig = sign(tt.body)
			}
			w := postAction(t, a, tt.op, tt.body, sig, nil)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d, body %s", w.Code, tt.want, w.Body.String())
			}
			if strings.Contains(w.Body.String(), demoPassword) {
				t.Fatal("an error answer holds the password")
			}
		})
	}
}

func TestActionRotate(t *testing.T) {
	t.Parallel()
	a, _, data, _ := leaderActions(t)
	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	w := postAction(t, a, "rotate", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	pw, _ := m["password"].(string)
	if pw == "" || pw == demoPassword || len(pw) != 24 {
		t.Fatalf("password not rotated: %q", pw)
	}
	if got := string(data()[keyPassword]); got != pw {
		t.Fatalf("stored password %q, answered %q", got, pw)
	}
}

func TestActionSet(t *testing.T) {
	t.Parallel()
	a, _, data, _ := leaderActions(t)
	for _, enabled := range []any{false, "true"} {
		body := actionBody(t, "stack-demo-alice", "demo", map[string]any{"enabled": enabled}, time.Now())
		w := postAction(t, a, "set", body, sign(body), nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
		}
		m := decode(t, w)
		if _, ok := m["password"]; ok {
			t.Fatal("set must not return the password")
		}
		want := "false"
		if enabled == "true" {
			want = "true"
		}
		if got := string(data()[keyEnabled]); got != want {
			t.Fatalf("enabled = %q, want %q", got, want)
		}
		if got := string(data()[keyPassword]); got != demoPassword {
			t.Fatal("set changed the password")
		}
	}
}

func TestActionRotateCreatesMissingSecret(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)
	body := actionBody(t, "stack-new-carol", "new", nil, time.Now())
	w := postAction(t, a, "rotate", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	sec, err := a.client.CoreV1().Secrets("stack-new-carol").Get(context.Background(), "stack-basic-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Data[keyUsername]) != "new" || sec.Labels[managedByLabel] != managedByValue {
		t.Fatalf("unexpected secret: %v %v", sec.Labels, string(sec.Data[keyUsername]))
	}
}

func TestActionWriteRetriesOnConflict(t *testing.T) {
	t.Parallel()
	a, _, data, fakeClient := leaderActions(t)
	var calls atomic.Int32
	fakeClient.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		if calls.Add(1) == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "stack-basic-auth", nil)
		}
		return false, nil, nil
	})
	body := actionBody(t, "stack-demo-alice", "demo", map[string]any{"enabled": false}, time.Now())
	w := postAction(t, a, "set", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("update calls = %d, want 2", calls.Load())
	}
	if string(data()[keyEnabled]) != "false" {
		t.Fatal("the retry did not write")
	}
}

func TestActionWriteFailureHidesDetails(t *testing.T) {
	t.Parallel()
	a, _, _, fakeClient := leaderActions(t)
	fakeClient.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "stack-basic-auth", nil)
	})
	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	w := postAction(t, a, "rotate", body, sign(body), nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "forbidden") || strings.Contains(w.Body.String(), demoPassword) {
		t.Fatalf("error leaks details: %s", w.Body.String())
	}
}

// TestFollowerForwardsWrites runs a leader on an HTTP server and checks that a
// follower sends a write action to it, and serves show itself.
func TestFollowerForwardsWrites(t *testing.T) {
	t.Parallel()
	leader, _, data, _ := leaderActions(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var forwarded atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("POST /actions/{op}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(forwardedHeader) != "" {
			forwarded.Add(1)
		}
		leader.ServeHTTP(w, r)
	}))
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	cfg := testConfig(t, map[string]string{"LISTEN_ADDR": ":" + port})
	cfg.PodName, cfg.PodIP = "follower", "127.0.0.2"
	el := newElector(nil, cfg)
	id := "leader-pod@127.0.0.1"
	el.leaderID.Store(&id)
	follower := newActions(leader.client, leader.store, el, cfg, newMetrics())

	body := actionBody(t, "stack-demo-alice", "demo", map[string]any{"enabled": false}, time.Now())
	w := postAction(t, follower, "set", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if forwarded.Load() != 1 {
		t.Fatalf("forwarded = %d, want 1", forwarded.Load())
	}
	if string(data()[keyEnabled]) != "false" {
		t.Fatal("the leader did not write")
	}

	body = actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	w = postAction(t, follower, "show", body, sign(body), nil)
	if w.Code != http.StatusOK || forwarded.Load() != 1 {
		t.Fatalf("show: status = %d, forwarded = %d; show must run on the follower", w.Code, forwarded.Load())
	}
}

func TestFollowerWithoutLeader(t *testing.T) {
	t.Parallel()
	leader, _, _, _ := leaderActions(t)
	cfg := testConfig(t, nil)
	el := newElector(nil, cfg) // no term, no known leader
	follower := newActions(leader.client, leader.store, el, cfg, newMetrics())

	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	if w := postAction(t, follower, "rotate", body, sign(body), nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no leader: status = %d, want 503", w.Code)
	}

	id := "leader-pod@127.0.0.1"
	el.leaderID.Store(&id)
	w := postAction(t, follower, "rotate", body, sign(body), map[string]string{forwardedHeader: "other"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("second hop: status = %d, want 503", w.Code)
	}
}

func TestActionMoreRequestChecks(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)

	future := actionBody(t, "stack-demo-alice", "demo", nil, time.Now().Add(10*time.Minute))
	if w := postAction(t, a, "show", future, sign(future), nil); w.Code != http.StatusUnauthorized {
		t.Errorf("future timestamp: status = %d, want 401", w.Code)
	}

	big := bytes.Repeat([]byte("x"), maxBodyBytes+1)
	if w := postAction(t, a, "show", big, sign(big), nil); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: status = %d, want 413", w.Code)
	}
}

func TestUnknownActionsShareOneMetricLabel(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)
	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	for _, op := range []string{"a1", "a2", "a3"} {
		postAction(t, a, op, body, sign(body), nil)
	}
	a.metrics.mu.Lock()
	defer a.metrics.mu.Unlock()
	if len(a.metrics.actions) != 1 || a.metrics.actions[actionKey{action: "unknown", code: 404}] != 3 {
		t.Fatalf("metric labels = %v", a.metrics.actions)
	}
}

func TestActionReplayIsRefused(t *testing.T) {
	t.Parallel()
	a, _, _, _ := leaderActions(t)
	body := actionBody(t, "stack-demo-alice", "demo", nil, time.Now())
	if w := postAction(t, a, "rotate", body, sign(body), nil); w.Code != http.StatusOK {
		t.Fatalf("first: status = %d", w.Code)
	}
	w := postAction(t, a, "rotate", body, sign(body), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("replay: status = %d, want 409", w.Code)
	}
	if strings.Contains(w.Body.String(), "password") && strings.Contains(w.Body.String(), "\"password\"") {
		t.Fatal("a refusal holds a password field")
	}
}

func TestSeenRequestsExpire(t *testing.T) {
	t.Parallel()
	s := newSeenRequests()
	now := time.Now()
	if !s.add("r1", now) || s.add("r1", now.Add(time.Minute)) {
		t.Fatal("second add within the TTL must fail")
	}
	if !s.add("r1", now.Add(seenTTL+time.Second)) {
		t.Fatal("add after the TTL must pass")
	}
}

func TestUnsignedMode(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, map[string]string{"STACK_ACCESS_SECRET": "", "ALLOW_UNSIGNED": "true"})
	st, client := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
	)
	a := newActions(client, st, newElector(nil, cfg), cfg, newMetrics())
	body := []byte(`{"kind":"ActionRequest","instance":{"name":"demo","namespace":"stack-demo-alice"}}`)
	if w := postAction(t, a, "show", body, "", nil); w.Code != http.StatusOK {
		t.Fatalf("unsigned show: status = %d, body %s", w.Code, w.Body.String())
	}
}

func TestRotateTakesTheCurrentStackName(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st, client := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "renamed"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
	)
	el := newElector(nil, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	el.startTerm(ctx)
	a := newActions(client, st, el, cfg, newMetrics())
	body := actionBody(t, "stack-demo-alice", "renamed", nil, time.Now())
	w := postAction(t, a, "rotate", body, sign(body), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if m := decode(t, w); m["username"] != "renamed" || m["url"] != "https://renamed.example.com" {
		t.Fatalf("result = %v", m)
	}
}
