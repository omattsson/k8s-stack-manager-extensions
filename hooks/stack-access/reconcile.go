package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// reconciler makes the access Secret for each stack namespace without one.
// Only the leader runs it.
type reconciler struct {
	client  kubernetes.Interface
	store   *store
	metrics *metrics
	trigger chan struct{}
	cfg     config
}

func newReconciler(client kubernetes.Interface, st *store, cfg config, m *metrics) *reconciler {
	return &reconciler{client: client, store: st, cfg: cfg, metrics: m, trigger: make(chan struct{}, 1)}
}

// notify asks for a pass. It never blocks. On a follower the request waits
// until the replica leads, which starts with a full pass anyway.
func (r *reconciler) notify() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// run is the leader loop: one pass at the start of the term, then one pass for
// each change and each resync interval.
func (r *reconciler) run(ctx context.Context) {
	if !r.store.waitSynced(ctx) {
		return
	}
	r.reconcileAll(ctx)
	t := time.NewTicker(r.cfg.ResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
			r.reconcileAll(ctx)
		case <-t.C:
			r.reconcileAll(ctx)
		}
	}
}

func (r *reconciler) reconcileAll(ctx context.Context) {
	for _, ns := range r.store.listNamespaces() {
		if ctx.Err() != nil {
			return
		}
		if err := r.ensure(ctx, ns); err != nil {
			slog.Warn("Cannot create the access secret", "namespace", ns.Name, "error", err)
		}
	}
}

// ensure creates the access Secret when the namespace has none.
func (r *reconciler) ensure(ctx context.Context, ns *corev1.Namespace) error {
	if ns.DeletionTimestamp != nil || ns.Status.Phase == corev1.NamespaceTerminating {
		return nil
	}
	instance := ns.Labels[r.cfg.InstanceLabel]
	if instance == "" {
		return nil
	}
	if _, err := r.store.secret(ns.Name); err == nil {
		return nil
	} else if !errors.Is(err, errNoSecret) {
		return err
	}
	sec, err := newAccessSecret(r.cfg, ns.Name, instance)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = r.client.CoreV1().Secrets(ns.Name).Create(cctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// The cache was behind.
		return nil
	}
	if err != nil {
		return err
	}
	r.metrics.secretCreated()
	slog.Info("Access secret created", "namespace", ns.Name, "instance", instance, "enabled", r.cfg.DefaultEnabled)
	return nil
}
