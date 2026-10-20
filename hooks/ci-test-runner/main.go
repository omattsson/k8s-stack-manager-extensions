// Package main implements a k8s-stack-manager custom action that runs a test
// pipeline in Azure DevOps against a stack.
//
// POST /action queues the pipeline and answers at once with a job ID. A
// goroutine follows the build and writes a job log. The k8s-stack-manager
// UI polls the log at GET /jobs/{job_id}/log.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ---------------------------------------------------------------------------
// Types — mirrors the k8s-stack-manager action envelope (subset)
// ---------------------------------------------------------------------------

type ActionRequest struct {
	Timestamp  time.Time      `json:"timestamp"`
	Instance   *InstanceRef   `json:"instance"`
	Parameters map[string]any `json:"parameters"`
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Action     string         `json:"action"`
	RequestID  string         `json:"request_id"`
}

type InstanceRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Branch    string `json:"branch,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	Status    string `json:"status,omitempty"`
}

// actionResponse is the body of a successful POST /action.
type actionResponse struct {
	JobID    string `json:"job_id"`
	Status   string `json:"status"`
	Suite    string `json:"suite"`
	BuildURL string `json:"build_url"`
	Message  string `json:"message,omitempty"`
	BuildID  int    `json:"build_id"`
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const (
	maxRequestBodySize int64 = 1 << 20 // 1 MiB
	signatureHeader          = "X-StackManager-Signature"
	// maxClockSkew is the allowed distance between a request time and the
	// clock of the runner.
	maxClockSkew = 5 * time.Minute
	// requestTimeout limits POST /action from its arrival: the wait for the
	// lock of the instance and the queue call. The runner answers before
	// the action timeout of the backend (timeout_seconds 30).
	requestTimeout = 25 * time.Second
	// replayWindow is the time that the runner remembers a request_id.
	replayWindow = 10 * time.Minute
	// maxRequestIDLength limits a remembered request_id.
	maxRequestIDLength = 128
	// jobStopTimeout is the time that the job goroutines get on shutdown.
	jobStopTimeout = 5 * time.Second
)

// suiteConfig is one entry of TEST_PIPELINES.
type suiteConfig struct {
	SourceBranch string `json:"source_branch"`
	PipelineID   int    `json:"pipeline_id"`
}

type config struct {
	Suites               map[string]suiteConfig
	ListenAddr           string
	Secret               string
	ADOOrg               string
	ADOProject           string
	ADOAuth              string
	ADOPAT               string
	AzureClientID        string
	PipelineSourceBranch string
	PollInterval         time.Duration
	TestTimeout          time.Duration
	JobRetention         time.Duration
	ShutdownTimeout      time.Duration
	// WaitLogInterval is the minimum time between two "Waiting for an
	// agent..." lines.
	WaitLogInterval time.Duration
	// PollErrorWindow is the time of failed status reads in a row after
	// which a job ends with status unknown.
	PollErrorWindow time.Duration
	// MaxPollBackoff is the longest wait between two reads after errors.
	MaxPollBackoff time.Duration
	// MaxLogBytes caps the log of one job.
	MaxLogBytes   int
	AllowUnsigned bool
}

// loadConfig reads the configuration from getenv.
func loadConfig(getenv func(string) string) (config, error) {
	get := func(key, fallback string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return fallback
	}

	cfg := config{
		ListenAddr:           get("LISTEN_ADDR", ":8080"),
		Secret:               getenv("CI_TEST_RUNNER_SECRET"),
		ADOOrg:               get("ADO_ORG", ""),
		ADOProject:           get("ADO_PROJECT", ""),
		ADOPAT:               getenv("ADO_PAT"),
		AzureClientID:        get("AZURE_CLIENT_ID", ""),
		PipelineSourceBranch: get("PIPELINE_SOURCE_BRANCH", "refs/heads/main"),
		PollInterval:         time.Duration(envInt(get, "POLL_INTERVAL_SECONDS", 15, 1)) * time.Second,
		TestTimeout:          time.Duration(envInt(get, "TEST_TIMEOUT_MINUTES", 60, 1)) * time.Minute,
		JobRetention:         time.Duration(envInt(get, "JOB_RETENTION_HOURS", 24, 1)) * time.Hour,
		ShutdownTimeout:      time.Duration(envInt(get, "SHUTDOWN_TIMEOUT_SECONDS", 30, 0)) * time.Second,
		WaitLogInterval:      time.Minute,
		PollErrorWindow:      defaultPollErrorWindow,
		MaxPollBackoff:       defaultMaxPollBackoff,
		MaxLogBytes:          defaultMaxLogBytes,
		AllowUnsigned:        strings.EqualFold(get("ALLOW_UNSIGNED", ""), "true"),
	}

	if cfg.Secret == "" && !cfg.AllowUnsigned {
		return config{}, errors.New("CI_TEST_RUNNER_SECRET is not set; set ALLOW_UNSIGNED=true to accept unsigned requests")
	}
	if cfg.ADOOrg == "" || cfg.ADOProject == "" {
		return config{}, errors.New("ADO_ORG and ADO_PROJECT must be set")
	}
	if !validRef(cfg.PipelineSourceBranch) {
		return config{}, fmt.Errorf("PIPELINE_SOURCE_BRANCH %q must be a ref such as refs/heads/main", cfg.PipelineSourceBranch)
	}

	suites, err := parseTestPipelines(getenv("TEST_PIPELINES"))
	if err != nil {
		return config{}, err
	}
	cfg.Suites = suites

	var ok bool
	cfg.ADOAuth, ok = resolveAuthMode(get("ADO_AUTH", ""), authPAT, cfg.AzureClientID != "", cfg.ADOPAT != "")
	if !ok {
		return config{}, fmt.Errorf("ADO_AUTH must be %q or %q", authPAT, authWorkloadIdentity)
	}
	switch {
	case cfg.ADOAuth == "":
		return config{}, errors.New("no Azure DevOps credentials: set AZURE_CLIENT_ID for workload identity, or ADO_PAT")
	case cfg.ADOAuth == authPAT && cfg.ADOPAT == "":
		return config{}, errors.New("ADO_AUTH is pat, but ADO_PAT is not set")
	}
	return cfg, nil
}

// envInt reads a whole number. It uses fallback when the value is not valid
// or is less than min.
func envInt(get func(string, string) string, key string, fallback, min int) int {
	n, err := strconv.Atoi(get(key, strconv.Itoa(fallback)))
	if err != nil || n < min {
		return fallback
	}
	return n
}

var suiteNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// parseTestPipelines parses TEST_PIPELINES: a JSON object from suite name to
// {"pipeline_id": 42, "source_branch": "refs/heads/main"}. source_branch is
// optional.
func parseTestPipelines(s string) (map[string]suiteConfig, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New(`TEST_PIPELINES is not set; set it to a JSON object such as {"smoke": {"pipeline_id": 42}}`)
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	var suites map[string]suiteConfig
	if err := dec.Decode(&suites); err != nil {
		return nil, fmt.Errorf("TEST_PIPELINES is not a valid JSON object of suites: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("TEST_PIPELINES has data after the JSON object")
	}
	if len(suites) == 0 {
		return nil, errors.New("TEST_PIPELINES must have at least one suite")
	}
	for name, sc := range suites {
		if !suiteNameRe.MatchString(name) {
			return nil, fmt.Errorf("TEST_PIPELINES: suite name %q must match %s", name, suiteNameRe)
		}
		if sc.PipelineID <= 0 {
			return nil, fmt.Errorf("TEST_PIPELINES: suite %q needs a positive pipeline_id", name)
		}
		if sc.SourceBranch != "" && !validRef(sc.SourceBranch) {
			return nil, fmt.Errorf("TEST_PIPELINES: suite %q: source_branch %q must be a ref such as refs/heads/main", name, sc.SourceBranch)
		}
	}
	return suites, nil
}

// suiteNames returns the sorted suite names.
func (c config) suiteNames() []string {
	names := make([]string, 0, len(c.Suites))
	for n := range c.Suites {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// ---------------------------------------------------------------------------
// Input checks
// ---------------------------------------------------------------------------

var (
	labelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,250}$`)
	refRe    = regexp.MustCompile(`^refs/[A-Za-z0-9_./-]{1,250}$`)
	jobIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)
	statusRe = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

// validLabel reports whether s is an RFC 1123 label (at most 63 characters).
func validLabel(s string) bool { return labelRe.MatchString(s) }

// validBranch reports whether a branch name is safe to send to the pipeline.
// The pipeline gets the branch as a template parameter, so the runner
// accepts only a small set of characters.
func validBranch(s string) bool {
	return branchRe.MatchString(s) &&
		!strings.Contains(s, "..") &&
		!strings.HasPrefix(s, "-") &&
		!strings.HasPrefix(s, "/")
}

// validRef reports whether s is a safe Git ref for the pipeline repo, for
// example refs/heads/main.
func validRef(s string) bool {
	return refRe.MatchString(s) &&
		!strings.Contains(s, "..") &&
		!strings.Contains(s, "//") &&
		!strings.HasSuffix(s, "/")
}

// outsideWindow reports whether t is more than maxClockSkew from now.
func outsideWindow(now, t time.Time) bool {
	d := now.Sub(t)
	return d > maxClockSkew || d < -maxClockSkew
}

// ---------------------------------------------------------------------------
// HMAC verification
// ---------------------------------------------------------------------------

// verifySignature checks the HMAC signature of msg (the body of a POST, or
// the request URI of a GET). Without a secret it accepts the request only
// when allowUnsigned is true.
func verifySignature(secret string, allowUnsigned bool, msg []byte, signature string) bool {
	if secret == "" {
		return allowUnsigned
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// replayCache remembers request IDs, so a captured request cannot run twice.
type replayCache struct {
	seen      map[string]time.Time
	lastPurge time.Time
	mu        sync.Mutex
}

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]time.Time{}}
}

// seenBefore records id at now. It returns true when the cache got id
// within replayWindow before.
func (c *replayCache) seenBefore(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastPurge) >= time.Minute {
		for k, t := range c.seen {
			if now.Sub(t) >= replayWindow {
				delete(c.seen, k)
			}
		}
		c.lastPurge = now
	}
	if t, ok := c.seen[id]; ok && now.Sub(t) < replayWindow {
		return true
	}
	c.seen[id] = now
	return false
}

// handler holds the dependencies and the jobs of the runner.
type handler struct {
	ci      ciProvider
	store   *jobStore
	locks   *keyedMutex
	replays *replayCache
	ctx     context.Context // job goroutines; canceled by stop
	cancel  context.CancelFunc
	now     func() time.Time
	cfg     config
	// requestTimeout limits POST /action (default requestTimeout). Tests
	// make it short.
	requestTimeout time.Duration
	wg             sync.WaitGroup
	mu             sync.Mutex
	// stopped is true after stop. No new goroutine starts then.
	stopped bool
}

func newHandler(cfg config, ci ciProvider) *handler {
	if cfg.WaitLogInterval <= 0 {
		cfg.WaitLogInterval = time.Minute
	}
	if cfg.MaxLogBytes <= 0 {
		cfg.MaxLogBytes = defaultMaxLogBytes
	}
	if cfg.PollErrorWindow <= 0 {
		cfg.PollErrorWindow = defaultPollErrorWindow
	}
	if cfg.MaxPollBackoff <= 0 {
		cfg.MaxPollBackoff = defaultMaxPollBackoff
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &handler{
		cfg:     cfg,
		ci:      ci,
		store:   newJobStore(maxJobs),
		locks:   newKeyedMutex(),
		replays: newReplayCache(),
		ctx:     ctx,
		cancel:  cancel,
		now:     time.Now,

		requestTimeout: requestTimeout,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// selectSuite reads parameters.suite. It returns a message for the user
// when the suite is missing or unknown.
func (h *handler) selectSuite(params map[string]any) (string, suiteConfig, string) {
	names := strings.Join(h.cfg.suiteNames(), ", ")
	v, ok := params["suite"]
	if !ok || v == nil {
		return "", suiteConfig{}, "Select a test suite (parameter suite). Suites: " + names
	}
	name, ok := v.(string)
	if !ok {
		return "", suiteConfig{}, "The parameter suite must be a string. Suites: " + names
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", suiteConfig{}, "Select a test suite (parameter suite). Suites: " + names
	}
	sc, ok := h.cfg.Suites[name]
	if !ok {
		if len(name) > 40 {
			name = name[:40] + "..."
		}
		return "", suiteConfig{}, fmt.Sprintf("Unknown suite %q. Suites: %s", name, names)
	}
	return name, sc, ""
}

// checkInstance checks the instance fields that go to the pipeline. It
// returns a message for the user, or "".
func checkInstance(inst *InstanceRef, branch string) string {
	switch {
	case !validLabel(inst.Name):
		return "The stack name is not a valid RFC 1123 label (lowercase letters, digits and '-', at most 63 characters)"
	case !validLabel(inst.Namespace):
		return "The stack namespace is not a valid RFC 1123 label (lowercase letters, digits and '-', at most 63 characters)"
	case branch == "":
		return "The stack has no branch"
	case !validBranch(branch):
		return "The branch is not allowed: use only letters, digits, '.', '_', '-' and '/', no '..', and no leading '-' or '/'"
	}
	return ""
}

// isStopping reports whether stop has started.
func (h *handler) isStopping() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stopped
}

// statusMessage returns the refusal for a stack that is not running or
// partial.
func statusMessage(status string) string {
	switch status {
	case "queued", "deploying", "stabilizing":
		return fmt.Sprintf("Wait until the stack is running (status: %s)", status)
	}
	if !statusRe.MatchString(status) {
		status = "unknown"
	}
	return fmt.Sprintf("Deploy the stack first (status: %s)", status)
}

// actionHandler handles POST /action: it queues the test pipeline for the
// instance, or returns the running job of the instance.
func (h *handler) actionHandler(w http.ResponseWriter, r *http.Request) {
	// One deadline from the arrival of the request. A request that waits for
	// the lock of its instance does not get a new budget.
	ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read error")
		return
	}
	if int64(len(body)) > maxRequestBodySize {
		writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	if !verifySignature(h.cfg.Secret, h.cfg.AllowUnsigned, body, r.Header.Get(signatureHeader)) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	var req ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	// The timestamp and the request ID are in the signed body. With a
	// secret, both are required, so a captured request cannot run again.
	if h.cfg.Secret != "" {
		if req.Timestamp.IsZero() {
			writeError(w, http.StatusUnauthorized, "request has no timestamp")
			return
		}
		if req.RequestID == "" {
			writeError(w, http.StatusUnauthorized, "request has no request_id")
			return
		}
	}
	if !req.Timestamp.IsZero() && outsideWindow(h.now(), req.Timestamp) {
		writeError(w, http.StatusUnauthorized, "request timestamp is more than 5 minutes from the clock of the runner")
		return
	}
	if len(req.RequestID) > maxRequestIDLength {
		writeError(w, http.StatusBadRequest, "request_id is too long")
		return
	}
	if req.RequestID != "" && h.replays.seenBefore(req.RequestID, h.now()) {
		writeError(w, http.StatusConflict, "request_id was already received")
		return
	}

	inst := req.Instance
	if inst == nil || inst.ID == "" {
		writeError(w, http.StatusBadRequest, "request has no instance")
		return
	}
	logger := slog.With("request_id", req.RequestID, "instance", inst.Name, "instance_id", inst.ID)

	suiteName, suite, msg := h.selectSuite(req.Parameters)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if inst.Status != "running" && inst.Status != "partial" {
		writeError(w, http.StatusConflict, statusMessage(inst.Status))
		return
	}
	branch := strings.TrimPrefix(inst.Branch, "refs/heads/")
	if msg := checkInstance(inst, branch); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if h.isStopping() {
		writeError(w, http.StatusServiceUnavailable, "The test runner is stopping. Try again in a moment.")
		return
	}

	// One job for each instance. The lock makes a second request wait until
	// the first one has queued its build, so it returns that job.
	unlock, err := h.locks.lock(ctx, inst.ID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Another request for this stack is in progress. Try again in a moment.")
		return
	}
	defer unlock()
	if ctx.Err() != nil {
		writeError(w, http.StatusServiceUnavailable, "Another request for this stack is in progress. Try again in a moment.")
		return
	}
	if j := h.store.running(inst.ID); j != nil {
		writeJSON(w, http.StatusOK, actionResponse{
			JobID:    j.id,
			Status:   jobRunning,
			Suite:    j.suite,
			BuildID:  j.buildID,
			BuildURL: j.buildURL,
			Message:  "A test run for this stack is in progress. This is its log.",
		})
		return
	}
	if !h.store.reserve() {
		writeError(w, http.StatusServiceUnavailable, "Too many test runs. Try again later.")
		return
	}

	sourceBranch := suite.SourceBranch
	if sourceBranch == "" {
		sourceBranch = h.cfg.PipelineSourceBranch
	}
	params := map[string]string{
		"stackName": inst.Name,
		"namespace": inst.Namespace,
		"branch":    branch,
		"suite":     suiteName,
	}
	b, err := h.ci.queueBuild(ctx, suite.PipelineID, sourceBranch, params)
	if err != nil {
		h.store.release()
		logger.Error("queue build", "pipeline_id", suite.PipelineID, "suite", suiteName, "error", err)
		writeError(w, http.StatusBadGateway, "Cannot queue the test pipeline: "+shortError(err))
		return
	}

	j := &job{
		id:           newJobID(),
		instanceID:   inst.ID,
		instanceName: inst.Name,
		suite:        suiteName,
		buildID:      b.ID,
		buildNumber:  b.BuildNumber,
		buildURL:     h.ci.buildLink(b),
		pipelineID:   suite.PipelineID,
		status:       jobRunning,
		maxLog:       h.cfg.MaxLogBytes,
	}
	number := j.buildNumber
	if number == "" {
		number = "#" + strconv.Itoa(j.buildID)
	}
	j.logf("Queued build %s of pipeline %d (suite %s): %s", number, j.pipelineID, suiteName, j.buildURL)
	h.store.add(j)
	if !h.startJob(j) {
		// stop started during the queue call. The build exists, so the
		// answer still has the job and the build link.
		h.end(j, jobUnknown, "The test runner stopped before it could follow the build. The build continues: "+j.buildURL)
	}
	logger.Info("queued test build", "job", j.id, "suite", suiteName, "pipeline_id", j.pipelineID, "build_id", j.buildID)

	writeJSON(w, http.StatusAccepted, actionResponse{
		JobID:    j.id,
		Status:   "started",
		Suite:    suiteName,
		BuildID:  j.buildID,
		BuildURL: j.buildURL,
	})
}

// jobLogHandler handles GET /jobs/{job_id}/log?instance_id=&offset=&ts=.
// The signature is the HMAC of the request URI, exactly as received.
func (h *handler) jobLogHandler(w http.ResponseWriter, r *http.Request) {
	if !verifySignature(h.cfg.Secret, h.cfg.AllowUnsigned, []byte(r.RequestURI), r.Header.Get(signatureHeader)) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	q := r.URL.Query()
	ts, err := strconv.ParseInt(q.Get("ts"), 10, 64)
	if err != nil || outsideWindow(h.now(), time.Unix(ts, 0)) {
		writeError(w, http.StatusUnauthorized, "ts is missing or more than 5 minutes from the clock of the runner")
		return
	}
	id := r.PathValue("job_id")
	var j *job
	if jobIDRe.MatchString(id) {
		j = h.store.get(id)
	}
	// A job of another instance is unknown to the caller.
	if j == nil || q.Get("instance_id") != j.instanceID {
		writeError(w, http.StatusNotFound, "unknown job")
		return
	}
	offset := 0
	if s := q.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = n
	}

	data, status := j.read(offset)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Job-Status", status)
	w.Header().Set("X-Log-Offset", strconv.Itoa(offset+len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// healthHandler is the liveness probe. It makes no external calls.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// readyHandler gets an Azure DevOps token. It is not the readiness probe of
// the example manifest.
func (h *handler) readyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := h.ci.ping(ctx); err != nil {
		// The answer has a fixed reason. The detail goes to the pod log only.
		slog.Warn("not ready", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error", "message": "no Azure DevOps token; see the runner log"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (h *handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /action", h.actionHandler)
	mux.HandleFunc("GET /jobs/{job_id}/log", h.jobLogHandler)
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /readyz", h.readyHandler)
	return mux
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	if cfg.Secret == "" {
		slog.Warn("WARNING: CI_TEST_RUNNER_SECRET is not set and ALLOW_UNSIGNED=true — the runner accepts unsigned requests from anyone who can reach it")
	}

	// The credential reads AZURE_CLIENT_ID, AZURE_TENANT_ID and
	// AZURE_FEDERATED_TOKEN_FILE.
	var entra *entraTokenSource
	if cfg.ADOAuth == authWorkloadIdentity {
		cred, err := azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			slog.Error("workload identity credential", "error", err)
			os.Exit(1)
		}
		entra = newEntraTokenSource(cred)
	}

	ci := newADOClient(cfg.ADOOrg, cfg.ADOProject, cfg.ADOAuth, cfg.ADOPAT, entra)
	h := newHandler(cfg, ci)
	h.startJanitor(janitorInterval)

	slog.Info("ci-test-runner starting",
		"addr", cfg.ListenAddr,
		"ado_org", cfg.ADOOrg,
		"ado_project", cfg.ADOProject,
		"ado_auth", cfg.ADOAuth,
		"suites", cfg.suiteNames(),
		"pipeline_source_branch", cfg.PipelineSourceBranch,
		"poll_interval", cfg.PollInterval,
		"test_timeout", cfg.TestTimeout,
		"job_retention", cfg.JobRetention,
		"shutdown_timeout", cfg.ShutdownTimeout,
	)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Longer than queueTimeout: POST /action waits for the queue call.
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("listen", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = serve(ctx, server, ln, cfg.ShutdownTimeout)
	// The builds in Azure DevOps continue. The jobs are lost.
	h.stop(jobStopTimeout)
	if err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// serve runs srv until ctx is done. Then it stops new requests and gives
// in-flight requests up to timeout to finish. After the timeout it cancels
// the request contexts.
func serve(ctx context.Context, srv *http.Server, ln net.Listener, timeout time.Duration) error {
	reqCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	srv.BaseContext = func(net.Listener) context.Context { return reqCtx }

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down", "timeout", timeout)
	sctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err == nil {
		return nil
	}

	slog.Warn("in-flight requests did not finish in time; stopping them")
	cancelRequests()
	sctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := srv.Shutdown(sctx2); err != nil {
		return srv.Close()
	}
	return nil
}
