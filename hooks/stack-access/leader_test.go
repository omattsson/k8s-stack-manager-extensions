package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestStartTerm(t *testing.T) {
	t.Parallel()
	el := newElector(nil, testConfig(t, nil))
	if el.isLeader() {
		t.Fatal("leader before any term")
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if el.startTerm(done) {
		t.Fatal("a done term must not start (late OnStartedLeading goroutine)")
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	if !el.startTerm(ctx1) || !el.isLeader() {
		t.Fatal("first term did not start")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if el.startTerm(ctx2) {
		t.Fatal("a second term started while the first is alive")
	}
	cancel1()
	if el.isLeader() {
		t.Fatal("still leader after the term ended")
	}
	if !el.startTerm(ctx2) || !el.isLeader() {
		t.Fatal("next term did not start")
	}
}

func TestLeaderAddr(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, map[string]string{"LISTEN_ADDR": ":9090"})
	cfg.PodName, cfg.PodIP = "me", "10.0.0.1"
	tests := []struct {
		id   string
		want string
		ok   bool
	}{
		{id: "", ok: false},
		{id: "me@10.0.0.1", ok: false}, // itself
		{id: "other@10.0.0.5", want: "10.0.0.5:9090", ok: true},
		{id: "other@fd00::5", want: "[fd00::5]:9090", ok: true},
		{id: "other", ok: false},
		{id: "other@not-an-ip", ok: false},
	}
	for _, tt := range tests {
		el := newElector(nil, cfg)
		if tt.id != "" {
			id := tt.id
			el.leaderID.Store(&id)
		}
		got, ok := el.leaderAddr()
		if ok != tt.ok || got != tt.want {
			t.Errorf("leaderAddr(%q) = %q, %v; want %q, %v", tt.id, got, ok, tt.want, tt.ok)
		}
	}
}

func TestRunWithoutElection(t *testing.T) {
	t.Parallel()
	el := newElector(nil, testConfig(t, nil))
	ctx, cancel := context.WithCancel(context.Background())
	led := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		el.run(ctx, func(c context.Context) {
			led <- el.isLeader()
			<-c.Done()
		})
		close(done)
	}()
	if !<-led {
		t.Fatal("not leader inside lead")
	}
	cancel()
	<-done
	if el.isLeader() {
		t.Fatal("leader after run returned")
	}
}

// TestRunElectionOneLeader runs two electors on one fake API and checks that
// exactly one leads, and that the other takes over when the first stops.
func TestRunElectionOneLeader(t *testing.T) {
	t.Parallel()
	client := fake.NewSimpleClientset()
	mk := func(name, ip string) *elector {
		cfg := testConfig(t, map[string]string{
			"LEADER_ELECTION_ENABLED": "true",
			"POD_NAME":                name,
			"POD_NAMESPACE":           "extensions",
			"POD_IP":                  ip,
			"LEASE_DURATION":          "3s",
			"RENEW_DEADLINE":          "2s",
			"RETRY_PERIOD":            "500ms",
		})
		return newElector(client, cfg)
	}
	a, b := mk("pod-a", "10.0.0.1"), mk("pod-b", "10.0.0.2")
	var terms atomic.Int32
	lead := func(ctx context.Context) {
		terms.Add(1)
		<-ctx.Done()
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() { a.run(ctxA, lead); close(doneA) }()
	eventually(t, "pod-a leads", a.isLeader)

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go b.run(ctxB, lead)
	// pod-b sees pod-a as the leader and does not lead.
	eventually(t, "pod-b knows the leader", func() bool {
		addr, ok := b.leaderAddr()
		return ok && addr == "10.0.0.1:8080"
	})
	time.Sleep(time.Second)
	if b.isLeader() {
		t.Fatal("two leaders")
	}

	// Stopping pod-a releases the lease; pod-b takes over.
	cancelA()
	<-doneA
	if a.isLeader() {
		t.Fatal("pod-a still leads after stop")
	}
	eventually(t, "pod-b leads", b.isLeader)
	// startTerm runs before lead counts the term.
	eventually(t, "two terms", func() bool { return terms.Load() == 2 })
}

// fakeLock is a resourcelock.Interface for the watchdog test.
type fakeLock struct{ identity string }

func (f *fakeLock) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	return &resourcelock.LeaderElectionRecord{}, nil, nil
}
func (f *fakeLock) Create(context.Context, resourcelock.LeaderElectionRecord) error { return nil }
func (f *fakeLock) Update(context.Context, resourcelock.LeaderElectionRecord) error { return nil }
func (f *fakeLock) RecordEvent(string)                                              {}
func (f *fakeLock) Identity() string                                                { return f.identity }
func (f *fakeLock) Describe() string                                                { return "fake" }

func TestWatchRenewalsEndsTerm(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, map[string]string{"RENEW_DEADLINE": "300ms", "RETRY_PERIOD": "100ms"})
	el := newElector(nil, cfg)
	lock := newRenewTrackingLock(&fakeLock{identity: "me"})
	if err := lock.Update(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: "me"}); err != nil {
		t.Fatal(err)
	}
	if lock.sinceRenew() > time.Second {
		t.Fatalf("renew not recorded: %v", lock.sinceRenew())
	}
	// A record of another holder (a release) is not a renew.
	time.Sleep(200 * time.Millisecond)
	_ = lock.Update(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: ""})
	if lock.sinceRenew() < 200*time.Millisecond {
		t.Fatal("a release counted as a renew")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !el.startTerm(ctx) {
		t.Fatal("startTerm failed")
	}
	go el.watchRenewals(ctx, lock, cancel)
	eventually(t, "the watchdog ends the term", func() bool { return !el.isLeader() })
}

// TestLateRenewStartsNewTerm: a renew that succeeds after the watchdog ended
// the term must not leave the replica holding the Lease without a term. The
// watchdog ends the campaign too, so the replica campaigns again and leads
// with a new term.
func TestLateRenewStartsNewTerm(t *testing.T) {
	t.Parallel()
	client := fake.NewSimpleClientset()
	var slow atomic.Bool
	client.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if slow.CompareAndSwap(true, false) {
			time.Sleep(1500 * time.Millisecond) // longer than RENEW_DEADLINE
		}
		return false, nil, nil
	})
	cfg := testConfig(t, map[string]string{
		"LEADER_ELECTION_ENABLED": "true",
		"POD_NAME":                "pod-a",
		"POD_NAMESPACE":           "extensions",
		"POD_IP":                  "10.0.0.1",
		"LEASE_DURATION":          "4s",
		"RENEW_DEADLINE":          "1s",
		"RETRY_PERIOD":            "200ms",
	})
	el := newElector(client, cfg)
	var terms atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = el.run(ctx, func(c context.Context) {
			terms.Add(1)
			<-c.Done()
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()

	eventually(t, "first term", func() bool { return el.isLeader() && terms.Load() == 1 })
	slow.Store(true)
	eventually(t, "the watchdog ends the first term", func() bool { return !el.isLeader() || terms.Load() > 1 })
	eventually(t, "a second term after the late renew", func() bool { return el.isLeader() && terms.Load() == 2 })
}
