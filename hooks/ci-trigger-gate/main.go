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
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	ProtectedTags        *regexp.Regexp
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
	AliasMarkerSuffix    string
	PollInterval         time.Duration
	BuildTimeout         time.Duration
	CacheTTL             time.Duration
	ShutdownTimeout      time.Duration
	AllowUnsigned        bool
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
		AliasMarkerSuffix:    get("ALIAS_MARKER_SUFFIX", ".alias"),
		PollInterval:         time.Duration(envInt(get, "POLL_INTERVAL_SECONDS", 15, 1)) * time.Second,
		BuildTimeout:         time.Duration(envInt(get, "BUILD_TIMEOUT_MINUTES", 25, 1)) * time.Minute,
		CacheTTL:             time.Duration(envInt(get, "CACHE_TTL_MINUTES", 5, 0)) * time.Minute,
		ShutdownTimeout:      time.Duration(envInt(get, "SHUTDOWN_TIMEOUT_SECONDS", 30, 0)) * time.Second,
		AllowUnsigned:        strings.EqualFold(get("ALLOW_UNSIGNED", ""), "true"),
		DefaultBranches:      map[string]bool{},
	}

	if cfg.Secret == "" && !cfg.AllowUnsigned {
		return config{}, errors.New("CI_TRIGGER_WEBHOOK_SECRET is not set; set ALLOW_UNSIGNED=true to accept unsigned requests")
	}
	if !validTag(cfg.FallbackTag) {
		return config{}, fmt.Errorf("FALLBACK_TAG %q is not a valid image tag", cfg.FallbackTag)
	}

	if !validMarkerSuffix(cfg.AliasMarkerSuffix) {
		return config{}, fmt.Errorf("ALIAS_MARKER_SUFFIX %q must start with '.', '-' or '_', use only letters, digits, '.', '_' and '-', and have at most %d characters", cfg.AliasMarkerSuffix, maxMarkerSuffix)
	}

	protected, err := regexp.Compile(get("PROTECTED_TAGS", defaultProtectedTags))
	if err != nil {
		return config{}, fmt.Errorf("PROTECTED_TAGS: %w", err)
	}
	cfg.ProtectedTags = protected

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

// isProtected reports whether the gate must never alias or build tag.
// FALLBACK_TAG and alias marker tags are always protected.
func (c config) isProtected(tag string) bool {
	if tag == c.FallbackTag {
		return true
	}
	if c.AliasMarkerSuffix != "" && strings.HasSuffix(tag, c.AliasMarkerSuffix) {
		return true
	}
	return c.ProtectedTags != nil && c.ProtectedTags.MatchString(tag)
}

// markerTag returns the alias marker tag of tag: tag + ALIAS_MARKER_SUFFIX.
// When the result is longer than 128 characters, the tag part is cut and
// gets "-" and the first 8 hex characters of the SHA-256 of the full tag,
// so the marker stays valid and unique.
func (c config) markerTag(tag string) string {
	if len(tag)+len(c.AliasMarkerSuffix) <= maxTagLength {
		return tag + c.AliasMarkerSuffix
	}
	sum := sha256.Sum256([]byte(tag))
	keep := maxTagLength - len(c.AliasMarkerSuffix) - 9
	return tag[:keep] + "-" + hex.EncodeToString(sum[:4]) + c.AliasMarkerSuffix
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

// verifySignature checks the HMAC signature of body. Without a secret it
// accepts the request only when allowUnsigned is true.
func verifySignature(secret string, allowUnsigned bool, body []byte, signature string) bool {
	if secret == "" {
		return allowUnsigned
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
func (h *handler) processChart(ctx context.Context, chart ChartRef, branch, tag string, log logFunc) error {
	// Check all input before the first registry or ADO call.
	if !validBranch(branch) {
		return fmt.Errorf("branch %q is not allowed: use only letters, digits, '.', '_', '-' and '/', no '..', and no leading '-' or '/'", branch)
	}
	if !validTag(tag) {
		return fmt.Errorf("image tag %q is not a valid tag", tag)
	}
	repos := h.cfg.reposFor(chart.Name)
	for _, repo := range repos {
		if !validRepo(repo) {
			return fmt.Errorf("image repository %q is not a valid repository name", repo)
		}
	}

	if h.cfg.isProtected(tag) {
		return h.checkProtected(ctx, repos, tag, log)
	}

	if h.cfg.DefaultBranches[branch] {
		return h.aliasRepos(ctx, repos, tag, fmt.Sprintf("branch %q is a default branch", branch), log)
	}

	src, ok := parseADORepoURL(chart.SourceRepoURL)
	if !ok {
		// The gate cannot check the branch. Build, as before.
		log("Source repo %q is not an Azure DevOps Git URL; assuming branch %q exists", chart.SourceRepoURL, branch)
	} else {
		if h.cfg.ADOOrg != "" && !strings.EqualFold(src.Org, h.cfg.ADOOrg) {
			return fmt.Errorf("source repo organization %q is not ADO_ORG %q; the gate checks branches only in ADO_ORG", src.Org, h.cfg.ADOOrg)
		}
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

// checkProtected allows a protected tag only when it exists in each repo.
// The gate never aliases or builds a protected tag.
func (h *handler) checkProtected(ctx context.Context, repos []string, tag string, log logFunc) error {
	for _, repo := range repos {
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		if cur == "" {
			return fmt.Errorf("%s:%s does not exist; %q is a protected tag, so the gate does not create or build it", repo, tag, tag)
		}
		log("Image %s:%s found (protected tag, %s)", repo, tag, shortDigest(cur))
	}
	return nil
}

// isGateAlias reports whether repo:tag (with the given digest) is an alias
// that the gate made. It is when the marker tag exists and has the same
// digest. A marker with another digest is stale and does not count.
func (h *handler) isGateAlias(ctx context.Context, repo, tag, digest string) (bool, error) {
	if digest == "" {
		return false, nil
	}
	m, err := h.registry.headDigest(ctx, repo, h.cfg.markerTag(tag))
	if err != nil {
		return false, err
	}
	return m == digest, nil
}

// putAlias points the marker tag and repo:tag to fb. The marker comes first,
// so a failure between the two writes never leaves an unmarked alias.
func (h *handler) putAlias(ctx context.Context, repo, tag string, fb *manifest) error {
	marker := h.cfg.markerTag(tag)
	if err := h.registry.putManifest(ctx, repo, marker, fb); err != nil {
		return fmt.Errorf("write alias marker %s:%s: %w", repo, marker, err)
	}
	if err := h.registry.putManifest(ctx, repo, tag, fb); err != nil {
		return fmt.Errorf("alias %s:%s to %s: %w", repo, tag, h.cfg.FallbackTag, err)
	}
	return nil
}

// aliasRepos makes repo:tag an alias of repo:FALLBACK_TAG in each repo.
// It creates a missing tag, and moves an alias that the gate made when the
// fallback moved. It never overwrites a real image.
func (h *handler) aliasRepos(ctx context.Context, repos []string, tag, reason string, log logFunc) error {
	fallback := h.cfg.FallbackTag
	for _, repo := range repos {
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		fb, err := h.registry.getManifest(ctx, repo, fallback)
		if err != nil {
			return err
		}
		if fb == nil {
			if cur == "" {
				return fmt.Errorf("%s:%s does not exist and fallback %s:%s does not exist", repo, tag, repo, fallback)
			}
			log("WARNING: %s:%s does not exist; keeping existing %s:%s (%s)", repo, fallback, repo, tag, shortDigest(cur))
			continue
		}
		if cur == "" {
			if err := h.putAlias(ctx, repo, tag, fb); err != nil {
				return err
			}
			log("%s; tagged %s:%s as alias of %s (%s)", reason, repo, tag, fallback, shortDigest(fb.digest))
			continue
		}
		alias, err := h.isGateAlias(ctx, repo, tag, cur)
		if err != nil {
			return err
		}
		switch {
		case !alias:
			log("%s; keeping existing %s:%s (%s)", reason, repo, tag, shortDigest(cur))
		case cur == fb.digest:
			log("%s; %s:%s already points to %s (%s)", reason, repo, tag, fallback, shortDigest(fb.digest))
		default:
			if err := h.putAlias(ctx, repo, tag, fb); err != nil {
				return err
			}
			log("%s; moved alias %s:%s from %s to %s (%s)", reason, repo, tag, shortDigest(cur), fallback, shortDigest(fb.digest))
		}
	}
	return nil
}

// ensureBuilt makes sure a branch image exists in each repo. It queues or
// reuses a build when an image is missing or is an alias that the gate made.
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
		alias, err := h.isGateAlias(ctx, repo, tag, cur)
		if err != nil {
			return err
		}
		if alias {
			log("Image %s:%s is a former alias of %s; a branch build replaces it", repo, tag, h.cfg.FallbackTag)
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

	// The build must have pushed a new image for every repo of the chart.
	// The old marker can stay: it no longer matches the tag, so it is harmless.
	for _, repo := range repos {
		cur, err := h.registry.headDigest(ctx, repo, tag)
		if err != nil {
			return err
		}
		alias, err := h.isGateAlias(ctx, repo, tag, cur)
		if err != nil {
			return err
		}
		if cur == "" || alias {
			return fmt.Errorf("build #%d succeeded but the pipeline did not push imageTag %s to %s: %s", build.ID, tag, repo, h.link(build))
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

// maxPollErrors is the number of failed status reads in a row after which
// the gate stops waiting for a build.
const maxPollErrors = 5

// waitForBuild polls a build until it completes, fails or times out.
func (h *handler) waitForBuild(ctx context.Context, b *buildInfo, chart string, log logFunc) error {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.BuildTimeout)
	defer cancel()

	start := time.Now()
	ticker := time.NewTicker(h.cfg.PollInterval)
	defer ticker.Stop()
	pollErrors := 0

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
			if ctx.Err() != nil {
				continue // the select above reports it
			}
			pollErrors++
			if pollErrors >= maxPollErrors {
				return fmt.Errorf("cannot read build #%d for %s %d times in a row: %v: %s", b.ID, chart, pollErrors, err, h.link(b))
			}
			log("WARNING: cannot read build #%d: %v", b.ID, err)
			continue
		}
		pollErrors = 0
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
	if !verifySignature(h.cfg.Secret, h.cfg.AllowUnsigned, body, sig) {
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
		tag := chart.ImageTag
		if tag == "" {
			tag = sanitizeImageTag(branch)
		}
		if reason := skipReason(chart, tag); reason != "" {
			logLine("[%s] Skipped: %s", chart.Name, reason)
			continue
		}

		wg.Add(1)
		go func(chart ChartRef, branch, tag string) {
			defer wg.Done()
			chartLog := func(format string, args ...any) {
				logLine("[%s] "+format, append([]any{chart.Name}, args...)...)
			}
			err := h.processChart(ctx, chart, branch, tag, chartLog)
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
		}(chart, branch, tag)
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
		slog.Warn("WARNING: CI_TRIGGER_WEBHOOK_SECRET is not set and ALLOW_UNSIGNED=true — the gate accepts unsigned requests from anyone who can reach it")
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
		"shutdown_timeout", cfg.ShutdownTimeout,
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

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("listen", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := serve(ctx, server, ln, cfg.ShutdownTimeout); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// serve runs srv until ctx is done. Then it stops new requests and gives
// in-flight hooks up to timeout to finish. After the timeout it cancels the
// request contexts, so a hook that waits for a build denies the deploy and
// returns.
func serve(ctx context.Context, srv *http.Server, ln net.Listener, timeout time.Duration) error {
	hookCtx, cancelHooks := context.WithCancel(context.Background())
	defer cancelHooks()
	srv.BaseContext = func(net.Listener) context.Context { return hookCtx }

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

	slog.Warn("in-flight hooks did not finish in time; stopping them")
	cancelHooks()
	sctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := srv.Shutdown(sctx2); err != nil {
		return srv.Close()
	}
	return nil
}
