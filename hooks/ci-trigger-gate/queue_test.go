package main

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_QueueTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "unset keeps one limit", value: "", want: 0},
		{name: "minutes", value: "20", want: 20 * time.Minute},
		{name: "zero", value: "0", want: 0},
		{name: "negative falls back", value: "-1", want: 0},
		{name: "not a number falls back", value: "x", want: 0},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadConfig(func(k string) string {
				switch k {
				case "CI_TRIGGER_WEBHOOK_SECRET":
					return "s"
				case "QUEUE_TIMEOUT_MINUTES":
					return tt.value
				}
				return ""
			})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.QueueTimeout != tt.want {
				t.Errorf("QueueTimeout = %s, want %s", cfg.QueueTimeout, tt.want)
			}
		})
	}
}

// queueEnv is a test env with a branch build of chart "api" that waits
// queueWaitPolls status reads for an agent, then runs runPolls reads.
func queueEnv(t *testing.T, queueWaitPolls, runPolls int, mutate func(*config)) *testEnv {
	t.Helper()
	e := newTestEnv(t, mutate)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.queueWaitPolls = queueWaitPolls
	e.ado.queuePolls = runPolls
	e.ado.onQueueSuccess = func(tag string) { e.acr.push("dev/api", tag, dockerV2Type, `{"m":"built"}`) }
	return e
}

func TestHook_QueueTimeoutDenies(t *testing.T) {
	t.Parallel()
	e := queueEnv(t, -1, 2, func(c *config) { c.QueueTimeout = 40 * time.Millisecond; c.BuildTimeout = time.Hour })

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed {
		t.Fatalf("resp = %+v", res.resp)
	}
	for _, want := range []string{"did not start within 40ms", "waits for a free build agent", "stays queued", "https://ado.example/build/101"} {
		if !strings.Contains(res.resp.Message, want) {
			t.Errorf("message %q does not contain %q", res.resp.Message, want)
		}
	}
	if !strings.Contains(res.logText(), "queued, waiting for a free build agent") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_BuildTimeoutWhileQueuedSaysQueued(t *testing.T) {
	t.Parallel()
	// No queue limit: the build limit counts from the start of the wait.
	e := queueEnv(t, -1, 2, func(c *config) { c.BuildTimeout = 200 * time.Millisecond })

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "did not start within 200ms") ||
		!strings.Contains(res.resp.Message, "stays queued") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_BuildTimeoutWhileRunningSaysNotFinished(t *testing.T) {
	t.Parallel()
	// The build runs at once and never ends within the limit.
	e := queueEnv(t, 0, 1_000_000, func(c *config) { c.QueueTimeout = time.Hour; c.BuildTimeout = 60 * time.Millisecond })

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if res.resp.Allowed || !strings.Contains(res.resp.Message, "did not finish within 60ms") {
		t.Errorf("resp = %+v", res.resp)
	}
}

func TestHook_QueueTimeDoesNotCountAgainstBuildTimeout(t *testing.T) {
	t.Parallel()
	// At least 1.2s in the queue (30 polls of 40ms), more than BuildTimeout,
	// then a short run. With one limit from the start, the build times out.
	e := queueEnv(t, 30, 3, func(c *config) {
		c.PollInterval = 40 * time.Millisecond
		c.QueueTimeout = 5 * time.Second
		c.BuildTimeout = time.Second
	})

	start := time.Now()
	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("the wait took %s; the test needs a queue phase longer than BuildTimeout", d)
	}
	if !strings.Contains(res.logText(), "an agent took the build") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_NextDeployReusesQueuedBuild(t *testing.T) {
	t.Parallel()
	e := queueEnv(t, -1, 2, func(c *config) { c.QueueTimeout = 40 * time.Millisecond; c.BuildTimeout = time.Hour })

	first := e.post(t, envelope("", appChart("api", "feature/x")))
	if first.resp.Allowed || !strings.Contains(first.resp.Message, "stays queued") {
		t.Fatalf("first deploy: resp = %+v", first.resp)
	}
	// An agent takes the build after the first deploy gave up.
	e.ado.set(func(f *fakeADO) { f.builds[101].queueLeft = 0 })

	second := e.post(t, envelope("", appChart("api", "feature/x")))
	if !second.resp.Allowed {
		t.Fatalf("second deploy: resp = %+v\n%s", second.resp, second.logText())
	}
	if e.ado.queuedCount() != 1 {
		t.Errorf("queued = %d, want 1 (the second deploy reuses build #101)", e.ado.queuedCount())
	}
	if !strings.Contains(second.logText(), "Reusing build #101 (notStarted") {
		t.Errorf("logs:\n%s", second.logText())
	}
}

func TestIsQueued(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status string
		want   bool
	}{
		{status: "notStarted", want: true},
		{status: "postponed", want: true},
		{status: "inProgress", want: false},
		{status: "cancelling", want: false},
		{status: "completed", want: false},
		{status: "", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()
			if got := isQueued(tt.status); got != tt.want {
				t.Errorf("isQueued(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}
