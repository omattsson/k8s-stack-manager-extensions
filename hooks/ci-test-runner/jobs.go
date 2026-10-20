package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Job statuses. The job log endpoint sends them in X-Job-Status.
const (
	jobRunning   = "running"
	jobSucceeded = "succeeded"
	jobFailed    = "failed"
	jobCanceled  = "canceled"
	// jobUnknown: the runner stopped following the build because it could
	// not read the build status. The build result is not known.
	jobUnknown = "unknown"
	// jobTimedOut: the runner stopped following the build after
	// TEST_TIMEOUT_MINUTES. The build result is not known.
	jobTimedOut = "timed_out"
)

const (
	// defaultMaxLogBytes caps the log of one job. The k8s-stack-manager
	// backend reads at most 256 KiB in one call.
	defaultMaxLogBytes = 256 << 10
	// truncationReserve keeps room for the truncation line under the cap.
	truncationReserve = 128
	// maxJobs is the maximum number of jobs in memory. When the store is
	// full, the oldest finished job goes first.
	maxJobs = 1000
	// defaultPollErrorWindow is the time of failed status reads in a row
	// after which a job stops following its build.
	defaultPollErrorWindow = 10 * time.Minute
	// defaultMaxPollBackoff is the longest wait between two status reads
	// after errors.
	defaultMaxPollBackoff = 2 * time.Minute
	// maxRetryAfter caps the Retry-After delay of Azure DevOps.
	maxRetryAfter = 5 * time.Minute
	// janitorInterval is the time between two runs of the retention cleanup.
	janitorInterval = time.Minute
)

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

// job follows one Azure DevOps build. The log is append-only. Readers get
// the status and the log under one lock. The final lines are written before
// the final status, so a reader that sees a final status has all lines.
type job struct {
	finished     time.Time
	id           string
	instanceID   string
	instanceName string
	suite        string
	buildNumber  string
	buildURL     string
	status       string
	log          []byte
	buildID      int
	pipelineID   int
	maxLog       int
	truncated    bool
	mu           sync.Mutex
}

// newJobID returns "job-" and 32 hex characters from crypto/rand.
func newJobID() string {
	b := make([]byte, 16)
	rand.Read(b) // never returns an error since Go 1.24
	return "job-" + hex.EncodeToString(b)
}

// logf appends one line with a UTC time stamp. A new line in the message
// becomes a space, so one call writes exactly one line.
func (j *job) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	ts := time.Now().UTC().Format(time.RFC3339)
	line := ts + " " + msg + "\n"

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.truncated {
		return
	}
	if len(j.log)+len(line) > j.maxLog-truncationReserve {
		// Keep the start of the log and drop the rest.
		j.truncated = true
		j.log = append(j.log, fmt.Sprintf("%s Log truncated at %d bytes. Later lines are dropped.\n", ts, len(j.log))...)
		return
	}
	j.log = append(j.log, line...)
}

// finish sets the final status.
func (j *job) finish(status string) {
	j.mu.Lock()
	j.status = status
	j.finished = time.Now()
	j.mu.Unlock()
}

// read returns a copy of the log from offset and the current status.
func (j *job) read(offset int) ([]byte, string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if offset >= len(j.log) {
		return nil, j.status
	}
	return bytes.Clone(j.log[offset:]), j.status
}

// number returns the build number, or "#<build id>" without one.
func (j *job) number() string {
	if j.buildNumber != "" {
		return j.buildNumber
	}
	return "#" + strconv.Itoa(j.buildID)
}

// state returns the status and the finish time.
func (j *job) state() (string, time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status, j.finished
}

// ---------------------------------------------------------------------------
// Job store
// ---------------------------------------------------------------------------

// jobStore keeps the jobs in memory. A restart loses them.
type jobStore struct {
	jobs       map[string]*job
	byInstance map[string]*job // newest job of each instance
	max        int
	// reserved is the number of slots that requests hold while they queue
	// a build. len(jobs) + reserved is never more than max.
	reserved int
	mu       sync.Mutex
}

func newJobStore(max int) *jobStore {
	return &jobStore{jobs: map[string]*job{}, byInstance: map[string]*job{}, max: max}
}

func (s *jobStore) get(id string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

// running returns the running job of an instance, or nil.
func (s *jobStore) running(instanceID string) *job {
	s.mu.Lock()
	j := s.byInstance[instanceID]
	s.mu.Unlock()
	if j == nil {
		return nil
	}
	if status, _ := j.state(); status != jobRunning {
		return nil
	}
	return j
}

// Reservation errors.
var (
	// errStoreFull: all slots hold running jobs or other reservations.
	errStoreFull = errors.New("job store is full")
	// errTooManyRunning: MAX_RUNNING_JOBS jobs run or are reserved.
	errTooManyRunning = errors.New("too many running jobs")
)

// reserve takes a slot for one new job. maxRunning (0: no cap) limits the
// running jobs plus the reservations. When the store is full, reserve
// removes the oldest finished jobs first. After nil, the caller must call
// add or release.
func (s *jobStore) reserve(maxRunning int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxRunning > 0 {
		running := s.reserved
		for _, j := range s.jobs {
			if status, _ := j.state(); status == jobRunning {
				running++
			}
		}
		if running >= maxRunning {
			return errTooManyRunning
		}
	}
	for len(s.jobs)+s.reserved >= s.max {
		var oldest *job
		var oldestAt time.Time
		for _, j := range s.jobs {
			status, at := j.state()
			if status == jobRunning {
				continue
			}
			if oldest == nil || at.Before(oldestAt) {
				oldest, oldestAt = j, at
			}
		}
		if oldest == nil {
			return errStoreFull
		}
		s.removeLocked(oldest)
	}
	s.reserved++
	return nil
}

// release gives back a reserved slot, for example when the queue call fails.
func (s *jobStore) release() {
	s.mu.Lock()
	if s.reserved > 0 {
		s.reserved--
	}
	s.mu.Unlock()
}

// add stores j in a reserved slot.
func (s *jobStore) add(j *job) {
	s.mu.Lock()
	if s.reserved > 0 {
		s.reserved--
	}
	s.jobs[j.id] = j
	s.byInstance[j.instanceID] = j
	s.mu.Unlock()
}

// removeExpired removes the jobs that finished before now - retention.
// It returns the number of removed jobs.
func (s *jobStore) removeExpired(now time.Time, retention time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		status, at := j.state()
		if status != jobRunning && at.Add(retention).Before(now) {
			s.removeLocked(j)
			n++
		}
	}
	return n
}

func (s *jobStore) removeLocked(j *job) {
	delete(s.jobs, j.id)
	if s.byInstance[j.instanceID] == j {
		delete(s.byInstance, j.instanceID)
	}
}

// ---------------------------------------------------------------------------
// Keyed lock
// ---------------------------------------------------------------------------

// keyedMutex serialises work per key. The runner uses it so that two
// requests for the same instance do not queue two builds. A waiter stops
// waiting when its context ends.
type keyedMutex struct {
	locks map[string]*keyedLock
	mu    sync.Mutex
}

type keyedLock struct {
	held chan struct{} // holds one token while the lock is held
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: map[string]*keyedLock{}}
}

// lock takes the lock of key. It returns the unlock function, or the error
// of ctx when ctx ends first.
func (k *keyedMutex) lock(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{held: make(chan struct{}, 1)}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	drop := func() {
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
	select {
	case l.held <- struct{}{}:
		return func() {
			<-l.held
			drop()
		}, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

// ---------------------------------------------------------------------------
// Following a build
// ---------------------------------------------------------------------------

// startJob starts the goroutine that follows the build of j. It returns
// false after stop, when the runner shuts down.
func (h *handler) startJob(j *job) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return false
	}
	h.wg.Add(1)
	go h.follow(j)
	return true
}

// follow polls the build of j until the build completes, the time limit
// ends, the status reads fail for PollErrorWindow, or the runner stops. After
// a failed read it waits longer: the interval doubles up to MaxPollBackoff,
// and a Retry-After delay of Azure DevOps wins when it is longer. It never
// cancels the build.
func (h *handler) follow(j *job) {
	defer h.wg.Done()
	ctx := h.ctx
	logger := slog.With("job", j.id, "instance", j.instanceName, "build_id", j.buildID)

	deadline := time.NewTimer(h.cfg.TestTimeout)
	defer deadline.Stop()
	wait := time.NewTimer(h.cfg.PollInterval)
	defer wait.Stop()

	delay := h.cfg.PollInterval
	var errorsSince, lastWait time.Time
	started := false
	for {
		select {
		case <-ctx.Done():
			logger.Info("stopped following the build: shutdown")
			return
		case <-deadline.C:
			h.end(j, jobTimedOut, fmt.Sprintf("Stopped following after %s. The build continues: %s", formatDuration(h.cfg.TestTimeout), j.buildURL))
			return
		case <-wait.C:
		}

		b, err := h.ci.getBuild(ctx, j.buildID)
		if err != nil {
			if ctx.Err() != nil {
				logger.Info("stopped following the build: shutdown")
				return
			}
			now := h.now()
			if errorsSince.IsZero() {
				errorsSince = now
			}
			logger.Warn("cannot read the build", "error", err, "failing_for", now.Sub(errorsSince))
			if now.Sub(errorsSince) >= h.cfg.PollErrorWindow {
				h.end(j, jobUnknown, fmt.Sprintf("Stopped following: cannot read the build status for %s (%s). The build continues: %s",
					formatDuration(h.cfg.PollErrorWindow), shortError(err), j.buildURL))
				return
			}
			delay = nextPollDelay(delay, h.cfg.MaxPollBackoff, retryAfter(err))
			wait.Reset(delay)
			continue
		}
		errorsSince = time.Time{}
		delay = h.cfg.PollInterval
		wait.Reset(delay)

		switch {
		case isQueued(b.Status):
			if now := h.now(); lastWait.IsZero() || now.Sub(lastWait) >= h.cfg.WaitLogInterval {
				lastWait = now
				j.logf("Waiting for an agent...")
			}
		case b.Status == "inProgress":
			if !started {
				started = true
				j.logf("Build started")
			}
		case b.Status == "completed":
			h.complete(ctx, j, b)
			return
		}
		// Other states (for example cancelling) write no line.
	}
}

// nextPollDelay returns the wait after a failed read: twice delay, at most
// max. A longer Retry-After delay wins, up to maxRetryAfter.
func nextPollDelay(delay, max, retryAfter time.Duration) time.Duration {
	d := 2 * delay
	if d > max {
		d = max
	}
	if retryAfter > d {
		d = min(retryAfter, maxRetryAfter)
	}
	return d
}

// complete writes the result lines of a completed build and ends the job.
// A failed test run read is a log line, not a job failure.
//
// A report-only pipeline gives partiallySucceeded for a red suite, and a
// warning step gives the same result. So for partiallySucceeded the test
// counts decide: passed tests and no failed tests give succeeded; failed
// tests, no test results or no passed tests give failed. When the test runs
// cannot be read, the result is unknown.
func (h *handler) complete(ctx context.Context, j *job, b *buildInfo) {
	result := b.Result
	if result == "" {
		result = "none"
	}
	j.logf("Build finished: %s", result)

	passed, failed := 0, 0
	runs, err := h.ci.testRuns(ctx, buildURI(b))
	switch {
	case err != nil:
		slog.Warn("cannot read the test runs", "job", j.id, "build_id", j.buildID, "error", err)
		j.logf("Cannot read the test results: %s", shortError(err))
	case len(runs) == 0:
		j.logf("No test results published")
	default:
		var other int
		passed, failed, other = summarize(runs)
		j.logf("Tests: %d passed, %d failed, %d other", passed, failed, other)
		j.logf("Test results: %s", testResultsLink(j.buildURL))
	}

	status := mapBuildResult(b.Result)
	if b.Result == "partiallySucceeded" {
		switch {
		case err != nil:
			status = jobUnknown
			j.logf("The build finished with warnings or failed tests. See the run page: %s", j.buildURL)
		case len(runs) > 0 && failed == 0 && passed > 0:
			status = jobSucceeded
			j.logf("Build finished with warnings. See the run page: %s", j.buildURL)
		}
	}
	j.finish(status)
	slog.Info("job finished", "job", j.id, "instance", j.instanceName, "build_id", j.buildID, "result", result, "status", status)
}

// end writes a last line and sets the final status.
func (h *handler) end(j *job, status, line string) {
	j.logf("%s", line)
	j.finish(status)
	slog.Info("job finished", "job", j.id, "instance", j.instanceName, "build_id", j.buildID, "status", status, "reason", line)
}

// summarize adds up the test counts of all runs. For each run, "other" is
// the rest of totalTests (for example skipped tests), and at least
// incompleteTests plus notApplicableTests.
func summarize(runs []testRun) (passed, failed, other int) {
	for _, r := range runs {
		passed += r.PassedTests
		failed += r.UnanalyzedTests
		o := r.TotalTests - r.PassedTests - r.UnanalyzedTests
		if alt := r.IncompleteTests + r.NotApplicableTests; alt > o {
			o = alt
		}
		other += o
	}
	return passed, failed, other
}

// mapBuildResult maps an Azure DevOps build result to a job status.
func mapBuildResult(result string) string {
	switch result {
	case "succeeded":
		return jobSucceeded
	case "canceled":
		return jobCanceled
	default: // failed, partiallySucceeded, none
		return jobFailed
	}
}

// isQueued reports whether an Azure DevOps build status means that the build
// waits for an agent.
func isQueued(status string) bool {
	return status == "notStarted" || status == "postponed"
}

// formatDuration writes whole minutes as "N minutes", else Go duration text.
func formatDuration(d time.Duration) string {
	if d > 0 && d%time.Minute == 0 {
		if n := int(d / time.Minute); n != 1 {
			return fmt.Sprintf("%d minutes", n)
		}
		return "1 minute"
	}
	return d.String()
}

// startJanitor removes finished jobs after JOB_RETENTION_HOURS.
func (h *handler) startJanitor(every time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-t.C:
				if n := h.store.removeExpired(time.Now(), h.cfg.JobRetention); n > 0 {
					slog.Info("removed finished jobs", "count", n)
				}
			}
		}
	}()
}

// stop stops the goroutines and waits up to timeout for them. The builds
// in Azure DevOps continue.
func (h *handler) stop(timeout time.Duration) {
	h.mu.Lock()
	h.stopped = true
	h.mu.Unlock()
	h.cancel()

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("job goroutines did not stop in time")
	}
}
