package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// elector runs the leader election. Only the leader writes access Secrets:
// the reconcile loop and the write actions.
type elector struct {
	client kubernetes.Interface
	// le is the elector of the current campaign. Its observed record names
	// the leader that the followers forward to.
	le atomic.Pointer[leaderelection.LeaderElector]
	// leaderID is the leader when no campaign runs (tests, no election).
	leaderID atomic.Pointer[string]
	// term is the context of the current leadership term. This replica leads
	// while it is not done. A watchdog ends it when the Lease was not renewed
	// within the renew deadline, which is shorter than the lease duration, so
	// the term ends before another replica can take the Lease.
	term atomic.Pointer[context.Context]
	cfg  config
}

func newElector(client kubernetes.Interface, cfg config) *elector {
	return &elector{client: client, cfg: cfg}
}

func (e *elector) isLeader() bool {
	_, ok := e.termContext()
	return ok
}

// termContext returns the context of the current term while this replica
// leads. Writes use it, so they stop when the term ends.
func (e *elector) termContext() (context.Context, bool) {
	p := e.term.Load()
	if p == nil || (*p).Err() != nil {
		return nil, false
	}
	return *p, true
}

// startTerm records ctx as the current term. It returns false when ctx is
// already done (client-go starts OnStartedLeading in a goroutine, which can
// run after the term ended) or when another term is still alive.
func (e *elector) startTerm(ctx context.Context) bool {
	for {
		cur := e.term.Load()
		if ctx.Err() != nil || (cur != nil && (*cur).Err() == nil) {
			return false
		}
		if e.term.CompareAndSwap(cur, &ctx) {
			return true
		}
	}
}

func (e *elector) currentLeaderID() string {
	if le := e.le.Load(); le != nil {
		return le.GetLeader()
	}
	if p := e.leaderID.Load(); p != nil {
		return *p
	}
	return ""
}

// leaderAddr returns host:port of the leader when another replica leads.
func (e *elector) leaderAddr() (string, bool) {
	id := e.currentLeaderID()
	if id == "" || id == e.cfg.identity() {
		return "", false
	}
	i := strings.LastIndex(id, "@")
	if i < 0 {
		return "", false
	}
	ip, err := netip.ParseAddr(id[i+1:])
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(ip.String(), e.cfg.ListenPort), true
}

// run blocks until ctx ends. For each leadership term it calls lead with the
// term context. Without leader election this process leads for its whole
// life (one replica). It returns an error only for an invalid configuration.
func (e *elector) run(ctx context.Context, lead func(context.Context)) error {
	if !e.cfg.LeaderElection {
		slog.Info("Leader election is disabled: this replica does all writes")
		if e.startTerm(ctx) {
			lead(ctx)
		}
		return nil
	}
	slog.Info("Leader election started", "lease", e.cfg.LeaseName, "namespace", e.cfg.PodNamespace, "identity", e.cfg.identity())
	for ctx.Err() == nil {
		// campaignCtx ends this campaign. The watchdog cancels it with the
		// term, so client-go stops renewing and releases the Lease. Otherwise
		// a late successful renew would leave this replica holding the Lease
		// without a term: nobody would write.
		campaignCtx, endCampaign := context.WithCancel(ctx)
		lock := newRenewTrackingLock(&resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Name: e.cfg.LeaseName, Namespace: e.cfg.PodNamespace},
			Client:     e.client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: e.cfg.identity()},
		})
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: e.cfg.LeaseDuration,
			RenewDeadline: e.cfg.RenewDeadline,
			RetryPeriod:   e.cfg.RetryPeriod,
			// On shutdown the next replica takes over after one retry period.
			ReleaseOnCancel: true,
			Name:            e.cfg.LeaseName,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					termCtx, endTerm := context.WithCancel(leaderCtx)
					defer endTerm()
					if !e.startTerm(termCtx) {
						return
					}
					slog.Info("Leadership acquired", "identity", e.cfg.identity())
					go e.watchRenewals(termCtx, lock, func() {
						endTerm()
						endCampaign()
					})
					lead(termCtx)
				},
				OnStoppedLeading: func() {
					slog.Info("Not the leader", "identity", e.cfg.identity())
				},
				OnNewLeader: func(id string) {
					if id != e.cfg.identity() {
						slog.Info("Another replica is the leader", "leader", id)
					}
				},
			},
		})
		if err != nil {
			endCampaign()
			return fmt.Errorf("leader election config: %w", err)
		}
		e.le.Store(le)
		le.Run(campaignCtx)
		endCampaign()
		select {
		case <-ctx.Done():
		case <-time.After(e.cfg.RetryPeriod):
		}
	}
	slog.Info("Leader election stopped", "identity", e.cfg.identity())
	return nil
}

// watchRenewals ends the term when the Lease was not renewed within the renew
// deadline. client-go ends the term later: after its renew attempt timed out,
// and with ReleaseOnCancel after one more release attempt, which can be
// after the lease duration.
func (e *elector) watchRenewals(ctx context.Context, lock *renewTrackingLock, endTerm func()) {
	interval := e.cfg.RetryPeriod / 2
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if since := lock.sinceRenew(); since > e.cfg.RenewDeadline {
				slog.Warn("Lease not renewed within the renew deadline: ending the term", "identity", e.cfg.identity(), "since_last_renew", since)
				endTerm()
				return
			}
		}
	}
}

// renewTrackingLock records the time of the last successful acquire or renew
// by this replica (monotonic clock).
type renewTrackingLock struct {
	resourcelock.Interface
	base      time.Time
	lastRenew atomic.Int64 // nanoseconds since base
}

func newRenewTrackingLock(l resourcelock.Interface) *renewTrackingLock {
	return &renewTrackingLock{Interface: l, base: time.Now()}
}

func (l *renewTrackingLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	start := time.Since(l.base)
	err := l.Interface.Create(ctx, ler)
	l.record(err, ler, start)
	return err
}

func (l *renewTrackingLock) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	start := time.Since(l.base)
	err := l.Interface.Update(ctx, ler)
	l.record(err, ler, start)
	return err
}

// record stores the time before the call: the API server can commit the
// renew at any moment of a slow call, and the other replicas count the lease
// duration from their own observation of it.
func (l *renewTrackingLock) record(err error, ler resourcelock.LeaderElectionRecord, start time.Duration) {
	if err == nil && ler.HolderIdentity == l.Identity() {
		l.lastRenew.Store(int64(start))
	}
}

func (l *renewTrackingLock) sinceRenew() time.Duration {
	return time.Since(l.base) - time.Duration(l.lastRenew.Load())
}
