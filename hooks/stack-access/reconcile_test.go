package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

func TestReconcileCreatesMissingSecrets(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	noLabel := stackNamespace("stack-nolabel", "")
	delete(noLabel.Labels, "k8s-stack-manager.io/instance-name")
	terminating := stackNamespace("stack-gone-dave", "gone")
	terminating.Status.Phase = corev1.NamespaceTerminating
	st, client := newTestStore(t, cfg,
		stackNamespace("stack-demo-alice", "demo"),
		accessSecret("stack-demo-alice", "demo", demoPassword, true),
		stackNamespace("stack-new-carol", "new"),
		noLabel,
		terminating,
	)
	m := newMetrics()
	r := newReconciler(client, st, cfg, m)
	r.reconcileAll(context.Background())

	sec, err := client.CoreV1().Secrets("stack-new-carol").Get(context.Background(), "stack-basic-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if string(sec.Data[keyUsername]) != "new" || len(sec.Data[keyPassword]) != 24 || string(sec.Data[keyEnabled]) != "true" {
		t.Fatalf("unexpected secret data for user %q", sec.Data[keyUsername])
	}
	if sec.Labels[managedByLabel] != managedByValue {
		t.Fatalf("labels = %v", sec.Labels)
	}

	old, _ := client.CoreV1().Secrets("stack-demo-alice").Get(context.Background(), "stack-basic-auth", metav1.GetOptions{})
	if string(old.Data[keyPassword]) != demoPassword {
		t.Fatal("an existing secret was changed")
	}
	for _, ns := range []string{"stack-nolabel", "stack-gone-dave"} {
		if _, err := client.CoreV1().Secrets(ns).Get(context.Background(), "stack-basic-auth", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("%s: secret created, err = %v", ns, err)
		}
	}
	if m.secrets.Load() != 1 {
		t.Fatalf("secrets created = %d, want 1", m.secrets.Load())
	}
}

func TestReconcileDefaultDisabled(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, map[string]string{"DEFAULT_ENABLED": "false"})
	st, client := newTestStore(t, cfg, stackNamespace("stack-new-carol", "new"))
	newReconciler(client, st, cfg, newMetrics()).reconcileAll(context.Background())
	sec, err := client.CoreV1().Secrets("stack-new-carol").Get(context.Background(), "stack-basic-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Data[keyEnabled]) != "false" {
		t.Fatalf("enabled = %q, want false", sec.Data[keyEnabled])
	}
}

func TestReconcileAlreadyExists(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st, client := newTestStore(t, cfg, stackNamespace("stack-new-carol", "new"))
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "stack-basic-auth")
	})
	r := newReconciler(client, st, cfg, newMetrics())
	if err := r.ensure(context.Background(), stackNamespace("stack-new-carol", "new")); err != nil {
		t.Fatalf("AlreadyExists must not be an error: %v", err)
	}
}

func TestReconcileRunReactsToNewNamespace(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, nil)
	st, client := newTestStore(t, cfg)
	r := newReconciler(client, st, cfg, newMetrics())
	if err := st.onNamespaceChange(r.notify); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	if _, err := client.CoreV1().Namespaces().Create(ctx, stackNamespace("stack-late-erin", "late"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "secret for the new namespace", func() bool {
		_, err := client.CoreV1().Secrets("stack-late-erin").Get(ctx, "stack-basic-auth", metav1.GetOptions{})
		return err == nil
	})
}

func TestNotifyNeverBlocks(t *testing.T) {
	t.Parallel()
	r := &reconciler{trigger: make(chan struct{}, 1)}
	for i := 0; i < 5; i++ {
		r.notify()
	}
	if len(r.trigger) != 1 {
		t.Fatalf("trigger length = %d", len(r.trigger))
	}
}
