package main

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const testSecret = "test-hmac-secret"

// testConfig returns a valid config. env overrides the defaults.
func testConfig(t *testing.T, env map[string]string) config {
	t.Helper()
	base := map[string]string{
		"STACK_ACCESS_SECRET":     testSecret,
		"LEADER_ELECTION_ENABLED": "false",
		"BYPASS_CIDRS":            "203.0.113.0/24",
		"URL_TEMPLATE":            "https://{instance}.example.com",
	}
	for k, v := range env {
		base[k] = v
	}
	cfg, err := loadConfig(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func stackNamespace(name, instance string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			"managed-by":                         "k8s-stack-manager",
			"k8s-stack-manager.io/instance-name": instance,
		},
	}}
}

func accessSecret(namespace, user, password string, enabled bool) *corev1.Secret {
	e := "true"
	if !enabled {
		e = "false"
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stack-basic-auth", Namespace: namespace},
		Data: map[string][]byte{
			keyUsername: []byte(user),
			keyPassword: []byte(password),
			keyEnabled:  []byte(e),
		},
	}
}

// newTestStore starts a store on a fake clientset and waits for the sync.
func newTestStore(t *testing.T, cfg config, objs ...runtime.Object) (*store, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset(objs...)
	st, err := newStore(client, cfg)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !st.run(ctx) {
		t.Fatal("store did not sync")
	}
	return st, client
}

// eventually polls cond for up to 5 seconds.
func eventually(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", msg)
}
