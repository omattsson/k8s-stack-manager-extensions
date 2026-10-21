package main

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

type actionKey struct {
	action string
	code   int
}

// metrics holds the counters in the Prometheus text format. The hooks of this
// repository use the standard library where they can, so there is no client
// library.
type metrics struct {
	mu      sync.Mutex
	auth    map[string]uint64
	actions map[actionKey]uint64
	secrets atomic.Uint64
	// isLeader reports the leader state at scrape time.
	isLeader func() bool
}

func newMetrics() *metrics {
	return &metrics{auth: map[string]uint64{}, actions: map[actionKey]uint64{}}
}

func (m *metrics) authResult(result string) {
	m.mu.Lock()
	m.auth[result]++
	m.mu.Unlock()
}

func (m *metrics) actionResult(action string, code int) {
	m.mu.Lock()
	m.actions[actionKey{action: action, code: code}]++
	m.mu.Unlock()
}

func (m *metrics) secretCreated() { m.secrets.Add(1) }

func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	auth := make(map[string]uint64, len(m.auth))
	for k, v := range m.auth {
		auth[k] = v
	}
	actions := make([]actionKey, 0, len(m.actions))
	counts := make(map[actionKey]uint64, len(m.actions))
	for k, v := range m.actions {
		actions = append(actions, k)
		counts[k] = v
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP stack_access_auth_requests_total Auth checks by result.")
	fmt.Fprintln(w, "# TYPE stack_access_auth_requests_total counter")
	for _, k := range sortedKeys(auth) {
		fmt.Fprintf(w, "stack_access_auth_requests_total{result=%q} %d\n", k, auth[k])
	}
	fmt.Fprintln(w, "# HELP stack_access_action_requests_total Action requests by action and status code.")
	fmt.Fprintln(w, "# TYPE stack_access_action_requests_total counter")
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].action != actions[j].action {
			return actions[i].action < actions[j].action
		}
		return actions[i].code < actions[j].code
	})
	for _, k := range actions {
		fmt.Fprintf(w, "stack_access_action_requests_total{action=%q,code=\"%d\"} %d\n", k.action, k.code, counts[k])
	}
	fmt.Fprintln(w, "# HELP stack_access_secrets_created_total Access secrets created by this replica.")
	fmt.Fprintln(w, "# TYPE stack_access_secrets_created_total counter")
	fmt.Fprintf(w, "stack_access_secrets_created_total %d\n", m.secrets.Load())
	fmt.Fprintln(w, "# HELP stack_access_leader 1 when this replica is the leader.")
	fmt.Fprintln(w, "# TYPE stack_access_leader gauge")
	leader := 0
	if m.isLeader != nil && m.isLeader() {
		leader = 1
	}
	fmt.Fprintf(w, "stack_access_leader %d\n", leader)
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
