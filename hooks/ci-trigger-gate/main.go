// Package main implements a pre-deploy webhook that checks if container images
// exist for the branch being deployed and triggers CI builds (Azure DevOps)
// if they don't — blocking the deploy until all images are ready.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
}

type HookResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var (
	secret       string
	listenAddr   string
	pollInterval time.Duration
	cacheTTL     time.Duration

	registryURL      string
	registryUsername string
	registryPassword string

	adoOrg     string
	adoProject string
	adoPAT     string

	maxRequestBodySize int64 = 1 << 20 // 1 MiB
)

// Global singletons initialised in main / initConfig.
var (
	cache *imageCache
	ado   *adoProvider
)

func initConfig() {
	secret = os.Getenv("CI_TRIGGER_WEBHOOK_SECRET")
	listenAddr = envOrDefault("LISTEN_ADDR", ":8080")
	registryURL = os.Getenv("REGISTRY_URL")
	registryUsername = os.Getenv("REGISTRY_USERNAME")
	registryPassword = os.Getenv("REGISTRY_PASSWORD")
	adoOrg = os.Getenv("ADO_ORG")
	adoProject = os.Getenv("ADO_PROJECT")
	adoPAT = os.Getenv("ADO_PAT")

	pollSec, err := strconv.Atoi(envOrDefault("POLL_INTERVAL_SECONDS", "15"))
	if err != nil || pollSec < 1 {
		pollSec = 15
	}
	pollInterval = time.Duration(pollSec) * time.Second

	cacheMins, err := strconv.Atoi(envOrDefault("CACHE_TTL_MINUTES", "5"))
	if err != nil || cacheMins < 0 {
		cacheMins = 5
	}
	cacheTTL = time.Duration(cacheMins) * time.Minute
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Branch → OCI tag sanitization
// ---------------------------------------------------------------------------

func sanitizeBranch(branch string) string {
	tag := strings.ToLower(branch)
	tag = strings.ReplaceAll(tag, "/", "-")
	var b strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	tag = b.String()
	tag = strings.Trim(tag, "-.")
	if len(tag) > 128 {
		tag = tag[:128]
	}
	return tag
}

// ---------------------------------------------------------------------------
// Skip logic
// ---------------------------------------------------------------------------

var semverRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)

func shouldSkipChart(chart ChartRef, branch string) bool {
	if chart.BuildPipelineID == "" {
		return true
	}
	if semverRe.MatchString(branch) {
		return true
	}
	if branch == "main" || branch == "master" {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// HMAC verification
// ---------------------------------------------------------------------------

func verifySignature(body []byte, signature string) bool {
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

type imageCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	ttl     time.Duration
	now     func() time.Time
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
// Registry — Docker Registry HTTP API v2
// ---------------------------------------------------------------------------

// registryChecker checks image existence. Abstracted for testing.
type registryChecker interface {
	imageExists(ctx context.Context, repo, tag string) (bool, error)
}

type acrRegistry struct {
	url      string
	username string
	password string
	client   *http.Client
}

func (r *acrRegistry) imageExists(ctx context.Context, repo, tag string) (bool, error) {
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", r.url, repo, tag)
	accept := "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

	exists, needToken, err := r.headManifest(ctx, manifestURL, accept, r.basicAuth())
	if err != nil {
		return false, err
	}
	if !needToken {
		return exists, nil
	}

	token, err := r.exchangeToken(ctx, repo)
	if err != nil {
		return false, fmt.Errorf("ACR token exchange: %w", err)
	}
	exists, _, err = r.headManifest(ctx, manifestURL, accept, "Bearer "+token)
	return exists, err
}

func (r *acrRegistry) basicAuth() string {
	creds := r.username + ":" + r.password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (r *acrRegistry) headManifest(ctx context.Context, url, accept, auth string) (exists bool, needToken bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("Authorization", auth)

	resp, err := r.client.Do(req)
	if err != nil {
		return false, false, fmt.Errorf("registry HEAD: %w", err)
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, false, nil
	case http.StatusNotFound:
		return false, false, nil
	case http.StatusUnauthorized:
		return false, true, nil
	default:
		return false, false, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}
}

func (r *acrRegistry) exchangeToken(ctx context.Context, repo string) (string, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/token?service=%s&scope=repository:%s:pull",
		r.url, url.QueryEscape(r.url), url.QueryEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", r.basicAuth())

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange returned status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return tok.AccessToken, nil
}

// ---------------------------------------------------------------------------
// ADO CI provider
// ---------------------------------------------------------------------------

type ciProvider interface {
	findRunningBuild(ctx context.Context, pipelineID, branch string) (string, error)
	triggerBuild(ctx context.Context, pipelineID, branch, imageTag string) (string, error)
	getBuildStatus(ctx context.Context, buildID string) (status string, result string, err error)
}

type adoProvider struct {
	org, project, pat string
	client            *http.Client
	baseURLOverride   string // for testing; empty uses the real ADO URL
}

func (a *adoProvider) baseURL() string {
	if a.baseURLOverride != "" {
		return a.baseURLOverride
	}
	return fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/build/builds", a.org, a.project)
}

func (a *adoProvider) authHeader() string {
	creds := ":" + a.pat
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (a *adoProvider) findRunningBuild(ctx context.Context, pipelineID, branch string) (string, error) {
	u := fmt.Sprintf("%s?api-version=7.1&definitions=%s&branchName=refs/heads/%s&statusFilter=inProgress,notStarted",
		a.baseURL(), url.QueryEscape(pipelineID), url.QueryEscape(branch))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", a.authHeader())

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ADO find builds: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ADO find builds returned status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID int `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode ADO response: %w", err)
	}
	if len(result.Value) == 0 {
		return "", nil
	}
	return strconv.Itoa(result.Value[0].ID), nil
}

func (a *adoProvider) triggerBuild(ctx context.Context, pipelineID, branch, imageTag string) (string, error) {
	defID, err := strconv.Atoi(pipelineID)
	if err != nil {
		return "", fmt.Errorf("invalid pipeline ID %q: %w", pipelineID, err)
	}

	body := struct {
		Definition struct {
			ID int `json:"id"`
		} `json:"definition"`
		SourceBranch       string            `json:"sourceBranch"`
		TemplateParameters map[string]string `json:"templateParameters,omitempty"`
	}{
		SourceBranch: "refs/heads/main",
		TemplateParameters: map[string]string{
			"branch":   branch,
			"imageTag": imageTag,
		},
	}
	body.Definition.ID = defID

	payload, _ := json.Marshal(body)

	u := a.baseURL() + "?api-version=7.1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", a.authHeader())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ADO trigger build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("ADO trigger returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode ADO trigger response: %w", err)
	}
	return strconv.Itoa(result.ID), nil
}

func (a *adoProvider) getBuildStatus(ctx context.Context, buildID string) (string, string, error) {
	u := fmt.Sprintf("%s/%s?api-version=7.1", a.baseURL(), url.QueryEscape(buildID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", a.authHeader())

	resp, err := a.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ADO get build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ADO get build returned status %d", resp.StatusCode)
	}

	var result struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("decode ADO build response: %w", err)
	}
	return result.Status, result.Result, nil
}

// ---------------------------------------------------------------------------
// Build job + poll
// ---------------------------------------------------------------------------

type buildJob struct {
	chart   ChartRef
	repo    string
	tag     string
	buildID string
}

func pollBuild(ctx context.Context, ci ciProvider, job buildJob, interval time.Duration, logLine func(string, ...any)) error {
	start := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled waiting for build #%s", job.buildID)
		case <-ticker.C:
			status, result, err := ci.getBuildStatus(ctx, job.buildID)
			if err != nil {
				logLine("WARNING: failed to poll build #%s: %v", job.buildID, err)
				continue
			}
			elapsed := time.Since(start).Truncate(time.Second)
			if status == "completed" {
				if result == "succeeded" || result == "partiallySucceeded" {
					logLine("Build #%s for %s completed successfully (%s)", job.buildID, job.repo, elapsed)
					return nil
				}
				return fmt.Errorf("build #%s for %s failed: %s (%s)", job.buildID, job.repo, result, elapsed)
			}
			logLine("Build #%s for %s: %s (%s)", job.buildID, job.repo, status, elapsed)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// handler holds dependencies for the hook handler, enabling injection in tests.
type handler struct {
	registry registryChecker
	ci       ciProvider
	cache    *imageCache
	poll     time.Duration
}

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
	if !verifySignature(body, sig) {
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

	logLine := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(w, "LOG: %s\n", msg)
		if flusher != nil {
			flusher.Flush()
		}
		logger.Info(msg)
	}

	respond := func(resp HookResponse) {
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("failed to write hook response", "error", err, "allowed", resp.Allowed)
		}
	}

	if env.Instance == nil {
		respond(HookResponse{Allowed: false, Message: "envelope missing instance"})
		return
	}

	defaultBranch := env.Instance.Branch

	var jobs []buildJob

	for _, chart := range env.Charts {
		branch := chart.Branch
		if branch == "" {
			branch = defaultBranch
		}
		if branch == "" {
			continue
		}

		if shouldSkipChart(chart, branch) {
			continue
		}

		tag := sanitizeBranch(branch)
		if tag == "" {
			logLine("Branch %q sanitized to empty tag, skipping %s", branch, chart.Name)
			continue
		}

		repo := chart.Name
		logLine("Checking image %s:%s...", repo, tag)

		if h.cache.isVerified(repo, tag) {
			logLine("Image %s:%s verified (cached)", repo, tag)
			continue
		}

		exists, err := h.registry.imageExists(r.Context(), repo, tag)
		if err != nil {
			logLine("WARNING: registry check failed for %s:%s: %v", repo, tag, err)
		}
		if exists {
			logLine("Image %s:%s found in registry", repo, tag)
			h.cache.markVerified(repo, tag)
			continue
		}

		logLine("Image %s:%s not found, checking for running builds...", repo, tag)
		existingID, findErr := h.ci.findRunningBuild(r.Context(), chart.BuildPipelineID, branch)
		if findErr != nil {
			logLine("WARNING: failed to check running builds for %s: %v", repo, findErr)
		}
		if existingID != "" {
			logLine("Found running build #%s for %s, attaching...", existingID, repo)
			jobs = append(jobs, buildJob{chart: chart, repo: repo, tag: tag, buildID: existingID})
			continue
		}

		logLine("Triggering build for %s (pipeline %s, branch %s)...", repo, chart.BuildPipelineID, branch)
		buildID, err := h.ci.triggerBuild(r.Context(), chart.BuildPipelineID, branch, tag)
		if err != nil {
			logLine("ERROR: failed to trigger build for %s: %v", repo, err)
			respond(HookResponse{
				Allowed: false,
				Message: fmt.Sprintf("failed to trigger build for %s: %v", repo, err),
			})
			return
		}
		logLine("Build #%s queued for %s", buildID, repo)
		jobs = append(jobs, buildJob{chart: chart, repo: repo, tag: tag, buildID: buildID})
	}

	for _, job := range jobs {
		if err := pollBuild(r.Context(), h.ci, job, h.poll, logLine); err != nil {
			respond(HookResponse{Allowed: false, Message: err.Error()})
			return
		}
		h.cache.markVerified(job.repo, job.tag)
	}

	if len(jobs) > 0 {
		logLine("All builds completed successfully")
	}
	respond(HookResponse{Allowed: true, Message: "all images ready"})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if registryURL == "" || adoPAT == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"error","message":"missing required configuration"}`))
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	initConfig()

	if secret == "" {
		slog.Warn("CI_TRIGGER_WEBHOOK_SECRET not set — signature verification disabled")
	}

	cache = newImageCache(cacheTTL)
	ado = &adoProvider{
		org:     adoOrg,
		project: adoProject,
		pat:     adoPAT,
		client:  &http.Client{Timeout: 30 * time.Second},
	}

	reg := &acrRegistry{
		url:      registryURL,
		username: registryUsername,
		password: registryPassword,
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	h := &handler{
		registry: reg,
		ci:       ado,
		cache:    cache,
		poll:     pollInterval,
	}

	slog.Info("ci-trigger-gate starting",
		"addr", listenAddr,
		"registry", registryURL,
		"ado_org", adoOrg,
		"ado_project", adoProject,
		"poll_interval", pollInterval,
		"cache_ttl", cacheTTL,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/hook", h.hookHandler)
	mux.HandleFunc("/healthz", healthHandler)

	server := &http.Server{
		Addr:        listenAddr,
		Handler:     mux,
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
