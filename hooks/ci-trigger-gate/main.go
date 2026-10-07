// Package main implements a pre-deploy webhook that makes sure a container
// image exists for each chart before the deploy starts.
//
// For a branch that exists in the chart's source repo, it builds the image
// with an Azure DevOps pipeline when needed and blocks the deploy until the
// build is done. For a branch that does not exist, or a default branch, it
// makes the branch tag an alias of a fallback tag in the registry.
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
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ---------------------------------------------------------------------------
// Types — mirrors k8s-stack-manager hook envelope (subset)
// ---------------------------------------------------------------------------

type EventEnvelope struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Event      string            `json:"event"`
	Timestamp  string            `json:"timestamp"`
	RequestID  string            `json:"request_id"`
	Instance   *InstanceRef      `json:"instance,omitempty"`
	Deployment *DeploymentRef    `json:"deployment,omitempty"`
	Charts     []ChartRef        `json:"charts,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type InstanceRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Branch    string `json:"branch,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
}

type DeploymentRef struct {
	ID        string `json:"id"`
	StartedAt string `json:"started_at"`
}

type ChartRef struct {
	Name            string `json:"name"`
	ReleaseName     string `json:"release_name,omitempty"`
	Version         string `json:"version,omitempty"`
	SourceRepoURL   string `json:"source_repo_url,omitempty"`
	BuildPipelineID string `json:"build_pipeline_id,omitempty"`
	Branch          string `json:"branch,omitempty"`
	ImageTag        string `json:"image_tag,omitempty"`
}

type HookResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const maxRequestBodySize int64 = 1 << 20 // 1 MiB

type config struct {
	ExtraImages          map[string][]string
	DefaultBranches      map[string]bool
	ListenAddr           string
	Secret               string
	RegistryURL          string
	RegistryAuth         string
	RegistryUsername     string
	RegistryPassword     string
	ADOOrg               string
	ADOProject           string
	ADOAuth              string
	ADOPAT               string
	AzureClientID        string
	AzureTenantID        string
	ImageRepoPrefix      string
	FallbackTag          string
	PipelineSourceBranch string
	PollInterval         time.Duration
	BuildTimeout         time.Duration
	CacheTTL             time.Duration
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
		Secret:               getenv("CI_TRIGGER_WEBHOOK_SECRET"),
		RegistryURL:          normalizeRegistryHost(get("REGISTRY_URL", "")),
		RegistryUsername:     getenv("REGISTRY_USERNAME"),
		RegistryPassword:     getenv("REGISTRY_PASSWORD"),
		ADOOrg:               get("ADO_ORG", ""),
		ADOProject:           get("ADO_PROJECT", ""),
		ADOPAT:               getenv("ADO_PAT"),
		AzureClientID:        get("AZURE_CLIENT_ID", ""),
		AzureTenantID:        get("AZURE_TENANT_ID", ""),
		ImageRepoPrefix:      get("IMAGE_REPO_PREFIX", ""),
		FallbackTag:          get("FALLBACK_TAG", "latest-dev"),
		PipelineSourceBranch: get("PIPELINE_SOURCE_BRANCH", "refs/heads/main"),
		PollInterval:         time.Duration(envInt(get, "POLL_INTERVAL_SECONDS", 15, 1)) * time.Second,
		BuildTimeout:         time.Duration(envInt(get, "BUILD_TIMEOUT_MINUTES", 25, 1)) * time.Minute,
		CacheTTL:             time.Duration(envInt(get, "CACHE_TTL_MINUTES", 5, 0)) * time.Minute,
		DefaultBranches:      map[string]bool{},
	}

	for _, b := range strings.Split(get("DEFAULT_BRANCHES", "main,master"), ",") {
		if b = strings.TrimSpace(b); b != "" {
			cfg.DefaultBranches[b] = true
		}
	}

	extra, err := parseExtraImages(getenv("CHART_EXTRA_IMAGES"))
	if err != nil {
		return config{}, err
	}
	cfg.ExtraImages = extra

	wi := cfg.AzureClientID != ""
	var ok bool
	cfg.RegistryAuth, ok = resolveAuthMode(get("REGISTRY_AUTH", ""), authBasic, wi,
		cfg.RegistryUsername != "" && cfg.RegistryPassword != "")
	if !ok {
		return config{}, fmt.Errorf("REGISTRY_AUTH must be %q or %q", authBasic, authWorkloadIdentity)
	}
	cfg.ADOAuth, ok = resolveAuthMode(get("ADO_AUTH", ""), authPAT, wi, cfg.ADOPAT != "")
	if !ok {
		return config{}, fmt.Errorf("ADO_AUTH must be %q or %q", authPAT, authWorkloadIdentity)
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

// parseExtraImages parses CHART_EXTRA_IMAGES: "chart=repoSuffix,chart=repoSuffix".
func parseExtraImages(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		chart, suffix, ok := strings.Cut(item, "=")
		chart, suffix = strings.TrimSpace(chart), strings.TrimSpace(suffix)
		if !ok || chart == "" || suffix == "" {
			return nil, fmt.Errorf("CHART_EXTRA_IMAGES: entry %q is not chart=repoSuffix", item)
		}
		out[chart] = append(out[chart], suffix)
	}
	return out, nil
}

// reposFor returns the image repositories of a chart, without duplicates.
func (c config) reposFor(chart string) []string {
	repos := []string{c.ImageRepoPrefix + chart}
	seen := map[string]bool{repos[0]: true}
	for _, suffix := range c.ExtraImages[chart] {
		r := c.ImageRepoPrefix + suffix
		if !seen[r] {
			seen[r] = true
			repos = append(repos, r)
		}
	}
	return repos
}

// ---------------------------------------------------------------------------
// HMAC verification
// ---------------------------------------------------------------------------

func verifySignature(secret string, body []byte, signature string) bool {
	if secret == "" {
		return true
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ---------------------------------------------------------------------------
// Image cache
// ---------------------------------------------------------------------------

// imageCache remembers branch images that the gate found. It never holds
// alias tags.
type imageCache struct {
	entries map[string]time.Time
	now     func() time.Time
	ttl     time.Duration
	mu      sync.RWMutex
}

func newImageCache(ttl time.Duration) *imageCache {
	return &imageCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
		now:     time.Now,
	}
}

func (c *imageCache) isVerified(repo, tag string) bool {
	key := repo + ":" + tag
	c.mu.RLock()
	t, ok := c.entries[key]
	c.mu.RUnlock()
	return ok && c.now().Before(t.Add(c.ttl))
}

func (c *imageCache) markVerified(repo, tag string) {
	key := repo + ":" + tag
	c.mu.Lock()
	c.entries[key] = c.now()
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Keyed lock
// ---------------------------------------------------------------------------

// keyedMutex serialises work per key. The gate uses it so that two deploys
// of the same branch do not queue two builds.
type keyedMutex struct {
	locks map[string]*keyedLock
	mu    sync.Mutex
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: map[string]*keyedLock{}}
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Chart processing
// ---------------------------------------------------------------------------

type logFunc func(format string, args ...any)

// handler holds dependencies for the hook handler, enabling injection in tests.
type handler struct {
	registry   registryClient
	ci         ciProvider
	cache      *imageCache
	queueLocks *keyedMutex
	cfg        config
}

func newHandler(cfg config, reg registryClient, ci ciProvider) *handler {
	return &handler{
		cfg:        cfg,
		registry:   reg,
		ci:         ci,
		cache:      newImageCache(cfg.CacheTTL),
		queueLocks: newKeyedMutex(),
	}
}

// processChart makes sure the images of one chart are ready.
func (h *handler) processChart(ctx context.Context, chart ChartRef, branch string, log logFunc) error {
	tag := chart.ImageTag
	if tag == "" {
		tag = sanitizeImageTag(branch)
	}
	repos := h.cfg.reposFor(chart.Name)

	if h.cfg.DefaultBranches[branch] {
		return h.aliasRepos(ctx, repos, tag, fmt.Sprintf("branch %q is a default branch", branch), log)
	}

	src, ok := parseADORepoURL(chart.SourceRepoURL)
	if !ok {
		// The gate cannot check the branch. Build, as before.
		log("Source repo %q is not an Azure DevOps Git URL; assuming branch %q exists", chart.SourceRepoURL, branch)
	} else {
		exists, err := h.ci.branchExists(ctx, src, branch)
		if err != nil {
			return fmt.Errorf("check branch %q in %s/%s: %w", branch, src.Project, src.Repo, err)
		}
		if !exists {
			return h.aliasRepos(ctx, repos, tag, fmt.Sprintf("branch %q does not exist in %s", branch, src.Repo), log)
		}
	}
	return h.ensureBuilt(ctx, chart, repos, branch, tag, log)
}

// aliasRepos makes repo:tag point to repo:FALLBACK_TAG in each repo.
func (h *handler) aliasRepos(ctx context.Context, repos []string, tag, reason string, log logFunc) error {
	fallback := h.cfg.FallbackTag
	for _, repo := range repos {
		fb, err := h.registry.getManifest(ctx, repo, fallback)
		if err != nil {
			return err
		}
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		if fb == nil {
			if cur != "" {
				log("WARNING: %s:%s does not exist; keeping %s:%s (%s)", repo, fallback, repo, tag, shortDigest(cur))
				continue
			}
			return fmt.Errorf("%s:%s does not exist and fallback %s:%s does not exist", repo, tag, repo, fallback)
		}
		if cur == fb.digest {
			log("%s; %s:%s already points to %s (%s)", reason, repo, tag, fallback, shortDigest(fb.digest))
			continue
		}
		if err := h.registry.putManifest(ctx, repo, tag, fb); err != nil {
			return fmt.Errorf("alias %s:%s to %s: %w", repo, tag, fallback, err)
		}
		log("%s; tagged %s:%s as alias of %s (%s)", reason, repo, tag, fallback, shortDigest(fb.digest))
	}
	return nil
}

// ensureBuilt makes sure a branch image exists in each repo. It queues or
// reuses a build when an image is missing or is still the fallback alias.
func (h *handler) ensureBuilt(ctx context.Context, chart ChartRef, repos []string, branch, tag string, log logFunc) error {
	pipelineID, err := strconv.Atoi(chart.BuildPipelineID)
	if err != nil {
		return fmt.Errorf("build_pipeline_id %q is not a number", chart.BuildPipelineID)
	}

	needBuild := false
	for _, repo := range repos {
		if h.cache.isVerified(repo, tag) {
			log("Image %s:%s found (cached)", repo, tag)
			continue
		}
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		if cur == "" {
			log("Image %s:%s not found", repo, tag)
			needBuild = true
			continue
		}
		fb, err := h.registry.headDigest(ctx, repo, h.cfg.FallbackTag)
		if err != nil {
			return err
		}
		if cur == fb {
			log("Image %s:%s is an alias of %s; a branch build is needed", repo, tag, h.cfg.FallbackTag)
			needBuild = true
			continue
		}
		log("Image %s:%s found (%s)", repo, tag, shortDigest(cur))
		h.cache.markVerified(repo, tag)
	}
	if !needBuild {
		return nil
	}

	build, err := h.findOrQueueBuild(ctx, pipelineID, branch, tag, log)
	if err != nil {
		return err
	}
	if err := h.waitForBuild(ctx, build, chart.Name, log); err != nil {
		return err
	}

	for _, repo := range repos {
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		if cur == "" {
			return fmt.Errorf("build #%d succeeded but %s:%s does not exist: %s", build.ID, repo, tag, h.link(build))
		}
		h.cache.markVerified(repo, tag)
	}
	log("Images for %s are ready", chart.Name)
	return nil
}

func (h *handler) link(b *buildInfo) string {
	return buildLink(h.cfg.ADOOrg, h.cfg.ADOProject, b)
}

// findOrQueueBuild reuses a running build for the same tag, or queues one.
func (h *handler) findOrQueueBuild(ctx context.Context, pipelineID int, branch, tag string, log logFunc) (*buildInfo, error) {
	unlock := h.queueLocks.lock(strconv.Itoa(pipelineID) + "|" + tag)
	defer unlock()

	b, err := h.ci.findRunningBuild(ctx, pipelineID, tag)
	if err != nil {
		log("WARNING: cannot list running builds of pipeline %d: %v", pipelineID, err)
	}
	if b != nil {
		log("Reusing running build #%d (pipeline %d, tag %s): %s", b.ID, pipelineID, tag, h.link(b))
		return b, nil
	}

	b, err = h.ci.queueBuild(ctx, pipelineID, branch, tag)
	if err != nil {
		return nil, fmt.Errorf("queue build of pipeline %d for branch %q: %w", pipelineID, branch, err)
	}
	log("Queued build #%d (pipeline %d, branch %s, tag %s): %s", b.ID, pipelineID, branch, tag, h.link(b))
	return b, nil
}

// waitForBuild polls a build until it completes, fails or times out.
func (h *handler) waitForBuild(ctx context.Context, b *buildInfo, chart string, log logFunc) error {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.BuildTimeout)
	defer cancel()

	start := time.Now()
	ticker := time.NewTicker(h.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("build #%d for %s did not finish within %s: %s", b.ID, chart, h.cfg.BuildTimeout, h.link(b))
			}
			return fmt.Errorf("stopped waiting for build #%d for %s: %w", b.ID, chart, ctx.Err())
		case <-ticker.C:
		}

		cur, err := h.ci.getBuild(ctx, b.ID)
		if err != nil {
			log("WARNING: cannot read build #%d: %v", b.ID, err)
			continue
		}
		elapsed := time.Since(start).Truncate(time.Second)
		if cur.Status != "completed" {
			log("Build #%d for %s: %s (%s)", b.ID, chart, cur.Status, elapsed)
			continue
		}
		switch cur.Result {
		case "succeeded", "partiallySucceeded":
			log("Build #%d for %s: %s (%s)", b.ID, chart, cur.Result, elapsed)
			return nil
		default:
			return fmt.Errorf("build #%d for %s finished with result %q: %s", b.ID, chart, cur.Result, h.link(b))
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func (h *handler) hookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-StackManager-Signature")
	if !verifySignature(h.cfg.Secret, body, sig) {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	var env EventEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	logger := slog.With("request_id", env.RequestID)
	if env.Instance != nil {
		logger = logger.With("instance", env.Instance.Name)
	}

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	// Charts run in parallel. The mutex keeps output lines whole.
	var writeMu sync.Mutex
	logLine := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		msg = strings.ReplaceAll(msg, "\n", " ")
		writeMu.Lock()
		fmt.Fprintf(w, "LOG: %s\n", msg)
		if flusher != nil {
			flusher.Flush()
		}
		writeMu.Unlock()
		logger.Info(msg)
	}

	respond := func(resp HookResponse) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("failed to write hook response", "error", err, "allowed", resp.Allowed)
		}
	}

	if env.Instance == nil {
		respond(HookResponse{Allowed: false, Message: "envelope missing instance"})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		failures []string
	)
	for _, chart := range env.Charts {
		branch := chart.Branch
		if branch == "" {
			branch = env.Instance.Branch
		}
		branch = strings.TrimPrefix(branch, "refs/heads/")
		if branch == "" {
			continue
		}
		if reason := skipReason(chart, branch); reason != "" {
			logLine("[%s] Skipped: %s", chart.Name, reason)
			continue
		}

		wg.Add(1)
		go func(chart ChartRef, branch string) {
			defer wg.Done()
			chartLog := func(format string, args ...any) {
				logLine("[%s] "+format, append([]any{chart.Name}, args...)...)
			}
			err := h.processChart(ctx, chart, branch, chartLog)
			if err == nil {
				return
			}
			errMu.Lock()
			defer errMu.Unlock()
			// After the first failure the other charts stop. Report only
			// the real failures, not the stops.
			if len(failures) > 0 && errors.Is(err, context.Canceled) {
				return
			}
			chartLog("ERROR: %v", err)
			failures = append(failures, fmt.Sprintf("%s: %v", chart.Name, err))
			cancel()
		}(chart, branch)
	}
	wg.Wait()

	if len(failures) > 0 {
		respond(HookResponse{Allowed: false, Message: strings.Join(failures, "; ")})
		return
	}
	respond(HookResponse{Allowed: true, Message: "all images ready"})
}

// healthHandler is the liveness probe. It makes no external calls.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// readyHandler is the readiness probe. It gets a registry token and an
// Azure DevOps token.
func (h *handler) readyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	fail := func(what string, err error) {
		msg := what + ": " + err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		slog.Warn("not ready", "reason", msg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": msg})
	}
	if err := h.registry.ping(ctx); err != nil {
		fail("registry", err)
		return
	}
	if err := h.ci.ping(ctx); err != nil {
		fail("azure devops", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (h *handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", h.hookHandler)
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", h.readyHandler)
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
		slog.Warn("CI_TRIGGER_WEBHOOK_SECRET not set — signature verification disabled")
	}

	// The credential reads AZURE_CLIENT_ID, AZURE_TENANT_ID and
	// AZURE_FEDERATED_TOKEN_FILE.
	var entra *entraTokenSource
	if cfg.RegistryAuth == authWorkloadIdentity || cfg.ADOAuth == authWorkloadIdentity {
		cred, err := azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			slog.Error("workload identity credential", "error", err)
			os.Exit(1)
		}
		entra = newEntraTokenSource(cred)
	}

	reg := newACRClient(cfg.RegistryURL, cfg.RegistryAuth, cfg.RegistryUsername, cfg.RegistryPassword, cfg.AzureTenantID, entra)
	ci := newADOClient(cfg.ADOOrg, cfg.ADOProject, cfg.ADOAuth, cfg.ADOPAT, cfg.PipelineSourceBranch, entra)
	h := newHandler(cfg, reg, ci)

	slog.Info("ci-trigger-gate starting",
		"addr", cfg.ListenAddr,
		"registry", cfg.RegistryURL,
		"registry_auth", cfg.RegistryAuth,
		"ado_org", cfg.ADOOrg,
		"ado_project", cfg.ADOProject,
		"ado_auth", cfg.ADOAuth,
		"image_repo_prefix", cfg.ImageRepoPrefix,
		"fallback_tag", cfg.FallbackTag,
		"pipeline_source_branch", cfg.PipelineSourceBranch,
		"poll_interval", cfg.PollInterval,
		"build_timeout", cfg.BuildTimeout,
		"cache_ttl", cfg.CacheTTL,
	)

	server := &http.Server{
		Addr:        cfg.ListenAddr,
		Handler:     h.routes(),
		ReadTimeout: 10 * time.Second,
		// WriteTimeout deliberately disabled — the dispatcher's context timeout
		// (from timeout_seconds in hooks-config) is the real deadline. WriteTimeout
		// counts from request header read, so it would race with long CI builds.
		IdleTimeout: 30 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
