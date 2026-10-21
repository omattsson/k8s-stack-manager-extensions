// Command stack-access puts HTTP basic auth in front of each stack.
//
// Every replica answers the Traefik forwardAuth check (GET /auth) and the
// show action from an informer cache. One replica, the leader of a
// Kubernetes Lease, does all writes: it creates the access Secret of each new
// stack namespace, and it runs the rotate and set actions. The other replicas
// forward write actions to the leader.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// server holds the HTTP handlers.
type server struct {
	store    *store
	gate     *gate
	actions  *actions
	metrics  *metrics
	stopping atomic.Bool
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/auth", s.gate)
	mux.Handle("POST /actions/{op}", s.actions)
	mux.Handle("GET /metrics", s.metrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.stopping.Load() || !s.store.synced.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func main() {
	if err := run(); err != nil {
		slog.Error("stack-access stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if err := setupLogging(os.Getenv("LOG_LEVEL")); err != nil {
		return err
	}
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.Secret == "" {
		slog.Warn("WARNING: STACK_ACCESS_SECRET is not set and ALLOW_UNSIGNED=true: anyone who can reach the service can read the stack passwords")
	}
	client, err := newClient()
	if err != nil {
		return err
	}

	m := newMetrics()
	st, err := newStore(client, cfg)
	if err != nil {
		return err
	}
	el := newElector(client, cfg)
	m.isLeader = el.isLeader
	rec := newReconciler(client, st, cfg, m)
	if err := st.onNamespaceChange(rec.notify); err != nil {
		return err
	}
	if err := st.onSecretDelete(rec.notify); err != nil {
		return err
	}
	srv := &server{
		store:   st,
		gate:    &gate{store: st, metrics: m, cfg: cfg},
		actions: newActions(client, st, el, cfg, m),
		metrics: m,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The informers and the election get their own contexts: they stop after
	// the HTTP server, so in-flight requests still have a cache and a leader.
	informerCtx, stopInformers := context.WithCancel(context.Background())
	defer stopInformers()
	go func() {
		if st.run(informerCtx) {
			slog.Info("Cache synced")
		}
	}()

	electionCtx, stopElection := context.WithCancel(context.Background())
	defer stopElection()
	electionErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		electionErr <- el.run(electionCtx, rec.run)
	}()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("stack-access listening", "addr", cfg.ListenAddr, "identity", cfg.identity(), "bypass_ranges", len(cfg.BypassCIDRs))
		serveErr <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			stopElection()
			wg.Wait()
			return fmt.Errorf("HTTP server: %w", err)
		}
	case err := <-electionErr:
		// Only an invalid configuration ends the election early. Without a
		// leader nothing creates Secrets for new stacks, so stop.
		_ = httpSrv.Close()
		return err
	}

	// Fail readiness first, so the Service stops sending requests before the
	// server closes.
	slog.Info("Shutting down")
	srv.stopping.Store(true)
	time.Sleep(cfg.ShutdownDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP shutdown", "error", err)
	}
	// Ending the election releases the Lease (ReleaseOnCancel).
	stopElection()
	wg.Wait()
	return nil
}

// newClient uses the in-cluster config, or KUBECONFIG outside a pod (local
// development).
func newClient() (kubernetes.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		path := os.Getenv("KUBECONFIG")
		if path == "" {
			return nil, fmt.Errorf("not in a pod and KUBECONFIG is not set: %w", err)
		}
		if restCfg, err = clientcmd.BuildConfigFromFlags("", path); err != nil {
			return nil, fmt.Errorf("load KUBECONFIG: %w", err)
		}
	}
	restCfg.UserAgent = "stack-access"
	return kubernetes.NewForConfig(restCfg)
}

func setupLogging(level string) error {
	var l slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		l = slog.LevelInfo
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		return fmt.Errorf("LOG_LEVEL %q is not debug, info, warn or error", level)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
	return nil
}
