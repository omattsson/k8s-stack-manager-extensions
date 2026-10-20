package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Job flow
// ---------------------------------------------------------------------------

func TestJob_SuccessFlow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) {
		f.queueWaitPolls = 3
		f.runPolls = 3
		f.runs["vstfs:///Build/Build/101"] = []testRun{
			{TotalTests: 15, PassedTests: 10, UnanalyzedTests: 2, IncompleteTests: 1},
			{TotalTests: 5, PassedTests: 5},
		}
	})

	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobSucceeded {
		t.Fatalf("status = %s", s)
	}
	url := e.ado.webURL(101)
	want := []string{
		"Queued build 20261020.1 of pipeline 42 (suite smoke): " + url,
		"Waiting for an agent...",
		"Build started",
		"Build finished: succeeded",
		"Tests: 15 passed, 2 failed, 3 other",
		"Test results: " + url + "&view=ms.vss-test-web.build-test-results-tab",
	}
	got := e.logLines(t, job.JobID)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	e.ado.mu.Lock()
	q := e.ado.runQueries
	e.ado.mu.Unlock()
	if len(q) != 1 || q[0].Get("buildUri") != "vstfs:///Build/Build/101" {
		t.Errorf("test run queries = %v", q)
	}
	if _, _, other := e.ado.counts(); other != 0 {
		t.Errorf("unexpected ADO calls = %d", other)
	}
}

func TestJob_WaitingLineAtMostOncePerInterval(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.WaitLogInterval = time.Minute })
	// The clock moves 20 seconds for each read, so every third read in the
	// queue writes a line.
	var mu sync.Mutex
	clock := time.Now()
	e.h.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(20 * time.Second)
		return clock
	}
	e.ado.set(func(f *fakeADO) { f.queueWaitPolls = 30 })

	job := e.run(t, testInstance(), "smoke")
	e.waitDone(t, job.JobID)
	if n := count(e.logLines(t, job.JobID), "Waiting for an agent..."); n != 10 {
		t.Errorf("waiting lines = %d, want 10 for 30 reads over 10 minutes", n)
	}
}

func TestJob_ResultMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		result string
		want   string
	}{
		{"succeeded", jobSucceeded},
		{"failed", jobFailed},
		{"partiallySucceeded", jobFailed},
		{"canceled", jobCanceled},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.result, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			e.ado.set(func(f *fakeADO) { f.nextResult = tt.result })
			job := e.run(t, testInstance(), "smoke")
			if s := e.waitDone(t, job.JobID); s != tt.want {
				t.Errorf("status = %s, want %s", s, tt.want)
			}
			lines := e.logLines(t, job.JobID)
			if count(lines, "Build finished: "+tt.result) != 1 {
				t.Errorf("log:\n%s", strings.Join(lines, "\n"))
			}
			rr := e.getLog(t, job.JobID, "i1", 0)
			if got := rr.Header().Get("X-Job-Status"); got != tt.want {
				t.Errorf("X-Job-Status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapBuildResult(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"succeeded":          jobSucceeded,
		"failed":             jobFailed,
		"partiallySucceeded": jobFailed,
		"canceled":           jobCanceled,
		"none":               jobFailed,
		"":                   jobFailed,
	}
	for result, want := range tests {
		if got := mapBuildResult(result); got != want {
			t.Errorf("mapBuildResult(%q) = %q, want %q", result, got, want)
		}
	}
}

func TestJob_NoTestRuns(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobSucceeded {
		t.Fatalf("status = %s", s)
	}
	lines := e.logLines(t, job.JobID)
	if lines[len(lines)-1] != "No test results published" {
		t.Errorf("log:\n%s", strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "Tests: ") || strings.HasPrefix(l, "Test results: ") {
			t.Errorf("unexpected line %q", l)
		}
	}
}

func TestJob_TestRunsReadErrorIsNotAFailure(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.failRuns = true })
	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobSucceeded {
		t.Fatalf("status = %s", s)
	}
	lines := e.logLines(t, job.JobID)
	if lines[len(lines)-1] != "Cannot read the test results: Azure DevOps returned status 500" {
		t.Errorf("log:\n%s", strings.Join(lines, "\n"))
	}
	if strings.Contains(e.logText(job.JobID), "boom") {
		t.Error("the log contains the ADO response body")
	}
}

func TestJob_Timeout(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.TestTimeout = 50 * time.Millisecond })
	e.ado.set(func(f *fakeADO) { f.runPolls = -1 }) // the build never ends

	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobTimedOut {
		t.Fatalf("status = %s", s)
	}
	lines := e.logLines(t, job.JobID)
	want := "Stopped following after 50ms. The build continues: " + e.ado.webURL(101)
	if lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
	// The runner never cancels the build.
	if _, _, other := e.ado.counts(); other != 0 {
		t.Errorf("unexpected ADO calls = %d", other)
	}
	e.ado.mu.Lock()
	status := e.ado.builds[101].status
	e.ado.mu.Unlock()
	if status == "completed" || status == "cancelling" {
		t.Errorf("build status = %q", status)
	}
}

func TestJob_PollErrorsForTheWindowEndUnknown(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) {
		c.PollInterval = 5 * time.Millisecond
		c.MaxPollBackoff = 40 * time.Millisecond
		c.PollErrorWindow = 300 * time.Millisecond
	})
	e.ado.set(func(f *fakeADO) { f.failBuildGets = -1 })

	start := time.Now()
	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobUnknown {
		t.Fatalf("status = %s", s)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("the job gave up after %s, before the error window of 300ms", d)
	}
	lines := e.logLines(t, job.JobID)
	want := "Stopped following: cannot read the build status for 300ms (Azure DevOps returned status 500). The build continues: " + e.ado.webURL(101)
	if lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
	// Back off: 5, 10, 20, 40, 40, ... ms gives about 10 reads in 300ms, not 60.
	if _, gets, _ := e.ado.counts(); gets < 3 || gets > 20 {
		t.Errorf("build reads = %d, want 3 to 20 with back off", gets)
	}
}

func TestJob_ShortOutageDoesNotEndTheJob(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.PollErrorWindow = time.Second })
	// More failed reads than the old limit of 5, within the window.
	e.ado.set(func(f *fakeADO) { f.failBuildGets = 8 })

	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobSucceeded {
		t.Fatalf("status = %s\n%s", s, e.logText(job.JobID))
	}
}

func TestJob_RetryAfterIsHonored(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.PollErrorWindow = 10 * time.Second })
	e.ado.set(func(f *fakeADO) {
		f.failBuildGets = 1
		f.failStatus = http.StatusTooManyRequests
		f.retryAfter = "1"
	})

	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobSucceeded {
		t.Fatalf("status = %s", s)
	}
	e.ado.mu.Lock()
	times := append([]time.Time(nil), e.ado.readTimes...)
	e.ado.mu.Unlock()
	if len(times) < 2 {
		t.Fatalf("reads = %d", len(times))
	}
	// Without Retry-After, the next read comes after 10ms.
	if gap := times[1].Sub(times[0]); gap < 900*time.Millisecond {
		t.Errorf("gap after 429 = %s, want about 1s (Retry-After)", gap)
	}
}

func TestJob_CancellingIsNotStarted(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) {
		f.nextStatuses = []string{"notStarted", "cancelling", "cancelling", "completed"}
		f.nextResult = "canceled"
	})
	job := e.run(t, testInstance(), "smoke")
	if s := e.waitDone(t, job.JobID); s != jobCanceled {
		t.Fatalf("status = %s", s)
	}
	lines := e.logLines(t, job.JobID)
	if count(lines, "Build started") != 0 || count(lines, "Build finished: canceled") != 1 {
		t.Errorf("log:\n%s", strings.Join(lines, "\n"))
	}
}

func TestNextPollDelay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                         string
		delay, max, retryAfter, want time.Duration
	}{
		{"doubles", 15 * time.Second, 2 * time.Minute, 0, 30 * time.Second},
		{"capped", 90 * time.Second, 2 * time.Minute, 0, 2 * time.Minute},
		{"retry-after wins", 15 * time.Second, 2 * time.Minute, 45 * time.Second, 45 * time.Second},
		{"shorter retry-after", 30 * time.Second, 2 * time.Minute, 10 * time.Second, time.Minute},
		{"retry-after capped", 15 * time.Second, 2 * time.Minute, time.Hour, maxRetryAfter},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nextPollDelay(tt.delay, tt.max, tt.retryAfter); got != tt.want {
				t.Errorf("nextPollDelay = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"":                              0,
		"30":                            30 * time.Second,
		" 5 ":                           5 * time.Second,
		"0":                             0,
		"-3":                            0,
		"soon":                          0,
		"Thu, 15 Jan 2026 10:01:00 GMT": time.Minute,
		"Thu, 15 Jan 2026 09:59:00 GMT": 0,
	}
	for in, want := range tests {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestJob_LogCap(t *testing.T) {
	t.Parallel()
	j := &job{maxLog: 400, status: jobRunning}
	for i := range 20 {
		j.logf("line %02d %s", i, strings.Repeat("x", 30))
	}
	data, _ := j.read(0)
	text := string(data)
	if len(data) > 400 {
		t.Errorf("log has %d bytes, cap is 400", len(data))
	}
	if !strings.Contains(strings.SplitN(text, "\n", 2)[0], "line 00 ") {
		t.Errorf("the log does not keep the start:\n%s", text)
	}
	if n := strings.Count(text, "Log truncated at "); n != 1 {
		t.Errorf("truncation lines = %d:\n%s", n, text)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if !strings.Contains(lines[len(lines)-1], "Later lines are dropped.") {
		t.Errorf("last line = %q", lines[len(lines)-1])
	}
	before := len(data)
	j.logf("Build finished: succeeded")
	if after, _ := j.read(0); len(after) != before {
		t.Errorf("a line was added after the truncation")
	}
}

func TestJob_LogLineIsOneLine(t *testing.T) {
	t.Parallel()
	j := &job{maxLog: defaultMaxLogBytes, status: jobRunning}
	j.logf("a\nb\rc")
	data, _ := j.read(0)
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z a b c\n$`).Match(data) {
		t.Errorf("line = %q", data)
	}
}

// ---------------------------------------------------------------------------
// Job store
// ---------------------------------------------------------------------------

func finishedJob(id, instance string, at time.Time) *job {
	return &job{id: id, instanceID: instance, status: jobSucceeded, finished: at}
}

func TestJobStore_RemoveExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := newJobStore(maxJobs)
	s.add(&job{id: "running", instanceID: "a", status: jobRunning})
	s.add(finishedJob("old", "b", now.Add(-25*time.Hour)))
	s.add(finishedJob("new", "c", now.Add(-time.Hour)))

	if n := s.removeExpired(now, 24*time.Hour); n != 1 {
		t.Errorf("removed = %d, want 1", n)
	}
	if s.get("old") != nil || s.get("new") == nil || s.get("running") == nil {
		t.Errorf("jobs = %v", s.jobs)
	}
	if _, ok := s.byInstance["b"]; ok {
		t.Error("byInstance keeps a removed job")
	}
	if s.running("a") == nil || s.running("c") != nil {
		t.Error("running() is wrong")
	}
}

func TestJobStore_RemoveExpiredKeepsNewerJobOfInstance(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := newJobStore(maxJobs)
	s.add(finishedJob("old", "a", now.Add(-25*time.Hour)))
	s.add(&job{id: "new", instanceID: "a", status: jobRunning})
	s.removeExpired(now, 24*time.Hour)
	if s.running("a") == nil || s.running("a").id != "new" {
		t.Error("the cleanup of an old job removed the newer job of the instance")
	}
}

func TestJobStore_Reserve(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := newJobStore(2)
	s.add(finishedJob("older", "a", now.Add(-2*time.Hour)))
	s.add(finishedJob("newer", "b", now.Add(-time.Hour)))
	if err := s.reserve(0); err != nil {
		t.Fatalf("reserve = %v with finished jobs", err)
	}
	if s.get("older") != nil || s.get("newer") == nil {
		t.Errorf("jobs = %v", s.jobs)
	}
	// The reservation counts: the store holds one job and one reservation.
	if err := s.reserve(0); err != nil {
		t.Fatalf("reserve = %v, want the newer finished job removed", err)
	}
	if err := s.reserve(0); !errors.Is(err, errStoreFull) {
		t.Errorf("reserve = %v with two reservations in a store of 2", err)
	}
	s.release()
	if err := s.reserve(0); err != nil {
		t.Errorf("reserve = %v after release", err)
	}
	s.add(&job{id: "r1", instanceID: "x", status: jobRunning})
	s.add(&job{id: "r2", instanceID: "y", status: jobRunning})
	if s.reserved != 0 || len(s.jobs) != 2 {
		t.Errorf("reserved = %d, jobs = %d", s.reserved, len(s.jobs))
	}
	if err := s.reserve(0); !errors.Is(err, errStoreFull) {
		t.Errorf("reserve = %v with only running jobs", err)
	}
}

func TestJobStore_ReserveRunningCap(t *testing.T) {
	t.Parallel()
	s := newJobStore(maxJobs)
	s.add(&job{id: "r1", instanceID: "a", status: jobRunning})
	s.add(finishedJob("f1", "b", time.Now()))
	// One running job and no reservation: a cap of 2 has room for one more.
	if err := s.reserve(2); err != nil {
		t.Fatalf("reserve = %v", err)
	}
	// The reservation counts against the cap.
	if err := s.reserve(2); !errors.Is(err, errTooManyRunning) {
		t.Errorf("reserve = %v, want errTooManyRunning", err)
	}
	s.release()
	if err := s.reserve(0); err != nil {
		t.Errorf("reserve without a cap = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestSummarize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		runs                []testRun
		passed, failed, oth int
	}{
		{name: "one run", runs: []testRun{{TotalTests: 10, PassedTests: 7, UnanalyzedTests: 2, NotApplicableTests: 1}}, passed: 7, failed: 2, oth: 1},
		{name: "skipped tests count as other", runs: []testRun{{TotalTests: 10, PassedTests: 6}}, passed: 6, oth: 4},
		{name: "sum over runs", runs: []testRun{{TotalTests: 3, PassedTests: 3}, {TotalTests: 4, PassedTests: 1, UnanalyzedTests: 3}}, passed: 4, failed: 3},
		{name: "total too small", runs: []testRun{{TotalTests: 1, PassedTests: 2, IncompleteTests: 1, NotApplicableTests: 1}}, passed: 2, oth: 2},
		{name: "no runs", runs: nil},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, f, o := summarize(tt.runs)
			if p != tt.passed || f != tt.failed || o != tt.oth {
				t.Errorf("summarize = %d, %d, %d; want %d, %d, %d", p, f, o, tt.passed, tt.failed, tt.oth)
			}
		})
	}
}

func TestTestResultsLink(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://ado.example/org/proj/_build/results?buildId=7": "https://ado.example/org/proj/_build/results?buildId=7&view=ms.vss-test-web.build-test-results-tab",
		"https://ado.example/build/7":                           "https://ado.example/build/7?view=ms.vss-test-web.build-test-results-tab",
	}
	for in, want := range tests {
		if got := testResultsLink(in); got != want {
			t.Errorf("testResultsLink(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildLinkAndURIFallbacks(t *testing.T) {
	t.Parallel()
	a := newADOClient("example org", "example-project", authPAT, "p", nil)
	b := &buildInfo{ID: 7}
	if got := a.buildLink(b); got != "https://dev.azure.com/example%20org/example-project/_build/results?buildId=7" {
		t.Errorf("buildLink = %q", got)
	}
	if got := buildURI(b); got != "vstfs:///Build/Build/7" {
		t.Errorf("buildURI = %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
	tests := map[time.Duration]string{
		60 * time.Minute:      "60 minutes",
		time.Minute:           "1 minute",
		50 * time.Millisecond: "50ms",
		90 * time.Second:      "1m30s",
	}
	for d, want := range tests {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestNewJobID(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`^job-[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 100 {
		id := newJobID()
		if !re.MatchString(id) || !jobIDRe.MatchString(id) {
			t.Fatalf("job ID %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate job ID %q", id)
		}
		seen[id] = true
	}
}

func TestShortError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want string
	}{
		{&adoStatusError{Status: 500, URL: "https://x", Body: "secret"}, "Azure DevOps returned status 500"},
		{fmt.Errorf("wrap: %w", &adoStatusError{Status: http.StatusNonAuthoritativeInfo}), "Azure DevOps refused the credentials"},
		{fmt.Errorf("%w: token: %w", errADOAuth, errFake), "cannot get an Azure DevOps token"},
		{fmt.Errorf("ADO GET: %w", context.DeadlineExceeded), "Azure DevOps did not answer in time"},
		{fmt.Errorf("ADO GET: %w", context.Canceled), "the request was canceled"},
		{errors.New("dial tcp https://x: refused"), "the request to Azure DevOps failed"},
	}
	for _, tt := range tests {
		if got := shortError(tt.err); got != tt.want {
			t.Errorf("shortError(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestADO_PATAuthHeader(t *testing.T) {
	t.Parallel()
	a := newADOClient("o", "p", authPAT, "secret-pat", nil)
	h, err := a.authHeader(t.Context())
	if err != nil || h != basicAuth("", "secret-pat") {
		t.Errorf("authHeader = %q, %v", h, err)
	}
	a.pat = ""
	if _, err := a.authHeader(t.Context()); !errors.Is(err, errADOAuth) {
		t.Errorf("authHeader without PAT: %v", err)
	}
}

func TestEntraTokenCached(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.run(t, testInstance(), "smoke")
	other := testInstance()
	other.ID = "i2"
	e.run(t, other, "smoke")
	if n := e.cred.count(adoScope); n != 1 {
		t.Errorf("token calls = %d, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

func TestStop_EndsPollingAndKeepsBuilds(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.ado.set(func(f *fakeADO) { f.runPolls = -1 })
	e.h.startJanitor(time.Millisecond)
	started := e.run(t, testInstance(), "smoke")

	// Wait for the first status reads.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, gets, _ := e.ado.counts(); gets > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no status reads")
		}
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	e.h.stop(2 * time.Second)
	if d := time.Since(start); d > time.Second {
		t.Errorf("stop took %s", d)
	}
	_, gets, other := e.ado.counts()
	time.Sleep(30 * time.Millisecond)
	if _, later, _ := e.ado.counts(); later != gets {
		t.Errorf("status reads continued after stop: %d then %d", gets, later)
	}
	if other != 0 {
		t.Errorf("unexpected ADO calls = %d", other)
	}
	if s, _ := e.h.store.get(started.JobID).state(); s != jobRunning {
		t.Errorf("status after stop = %s", s)
	}
	if e.h.startJob(&job{id: "x", maxLog: defaultMaxLogBytes, status: jobRunning}) {
		t.Error("startJob after stop = true")
	}
}
