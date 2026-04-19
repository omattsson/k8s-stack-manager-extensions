// Package main implements a pre-deploy webhook that scans container images
// for vulnerabilities using Trivy and blocks deploys with critical/high CVEs.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// EventEnvelope mirrors the k8s-stack-manager hook envelope (subset).
type EventEnvelope struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Event      string            `json:"event"`
	RequestID  string            `json:"request_id"`
	Instance   *InstanceRef      `json:"instance,omitempty"`
	Charts     []ChartRef        `json:"charts,omitempty"`
	Values     map[string]any    `json:"values,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// InstanceRef identifies a stack instance.
type InstanceRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ChartRef describes a chart involved in the event.
type ChartRef struct {
	Name        string `json:"name"`
	ReleaseName string `json:"release_name,omitempty"`
	Version     string `json:"version,omitempty"`
}

// HookResponse is returned to k8s-stack-manager.
type HookResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}

// cacheEntry holds a scan result with expiry.
type cacheEntry struct {
	clean   bool
	message string
	expires time.Time
}

var (
	secret             string
	severityThreshold  string
	trivyTimeout       string
	cacheTTL           time.Duration
	listenAddr         string
	scanCache          = make(map[string]cacheEntry)
	scanCacheMu        sync.RWMutex
	maxRequestBodySize int64 = 1 << 20 // 1 MiB
)

func init() {
	secret = os.Getenv("SCANNER_WEBHOOK_SECRET")
	severityThreshold = os.Getenv("SEVERITY_THRESHOLD")
	if severityThreshold == "" {
		severityThreshold = "CRITICAL,HIGH"
	}
	trivyTimeout = os.Getenv("TRIVY_TIMEOUT")
	if trivyTimeout == "" {
		trivyTimeout = "120s"
	}
	cacheTTLMin := os.Getenv("CACHE_TTL_MINUTES")
	if cacheTTLMin == "" {
		cacheTTLMin = "30"
	}
	var minutes int
	if _, err := fmt.Sscanf(cacheTTLMin, "%d", &minutes); err != nil {
		minutes = 30
	}
	cacheTTL = time.Duration(minutes) * time.Minute
	listenAddr = os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
}

func verifySignature(body []byte, signature string) bool {
	if secret == "" {
		return true
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// extractImages pulls image references from the envelope.
func extractImages(env *EventEnvelope) []string {
	var images []string

	// Check metadata.images override first
	if env.Metadata != nil {
		if explicit, ok := env.Metadata["images"]; ok && explicit != "" {
			for _, img := range strings.Split(explicit, ",") {
				img = strings.TrimSpace(img)
				if img != "" {
					images = append(images, img)
				}
			}
			return images
		}
	}

	// Extract from values: look for <chart>.image.repository + <chart>.image.tag
	if env.Values != nil {
		for _, chart := range env.Charts {
			chartVals, ok := env.Values[chart.Name]
			if !ok {
				continue
			}
			chartMap, ok := chartVals.(map[string]any)
			if !ok {
				continue
			}
			imageVals, ok := chartMap["image"]
			if !ok {
				continue
			}
			imageMap, ok := imageVals.(map[string]any)
			if !ok {
				continue
			}
			repo, _ := imageMap["repository"].(string)
			tag, _ := imageMap["tag"].(string)
			if repo != "" {
				if tag != "" {
					images = append(images, repo+":"+tag)
				} else {
					images = append(images, repo+":latest")
				}
			}
		}
	}

	return images
}

// scanImage runs trivy against a single image. Returns (clean, message).
func scanImage(image string) (bool, string) {
	// Check cache
	scanCacheMu.RLock()
	if entry, ok := scanCache[image]; ok && time.Now().Before(entry.expires) {
		scanCacheMu.RUnlock()
		return entry.clean, entry.message
	}
	scanCacheMu.RUnlock()

	slog.Info("scanning image", "image", image, "severity", severityThreshold)

	cmd := exec.Command("trivy", "image",
		"--severity", severityThreshold,
		"--exit-code", "1",
		"--no-progress",
		"--timeout", trivyTimeout,
		"--format", "json",
		image,
	)
	output, err := cmd.CombinedOutput()

	clean := err == nil
	var message string
	if !clean {
		// Parse trivy JSON output for a summary
		message = summarizeTrivyOutput(output, image)
	}

	// Cache result
	scanCacheMu.Lock()
	scanCache[image] = cacheEntry{
		clean:   clean,
		message: message,
		expires: time.Now().Add(cacheTTL),
	}
	scanCacheMu.Unlock()

	return clean, message
}

// summarizeTrivyOutput extracts a human-readable summary from trivy JSON output.
func summarizeTrivyOutput(output []byte, image string) string {
	// Try to parse the JSON output for vulnerability counts
	var result struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
				Title           string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Sprintf("image %s has vulnerabilities (trivy exit code non-zero)", image)
	}

	var critical, high int
	var firstCVE string
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			switch v.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			}
			if firstCVE == "" {
				firstCVE = fmt.Sprintf("%s (%s): %s", v.VulnerabilityID, v.Severity, v.Title)
			}
		}
	}

	summary := fmt.Sprintf("image %s: %d critical, %d high vulnerabilities", image, critical, high)
	if firstCVE != "" {
		summary += fmt.Sprintf("; first: %s", firstCVE)
	}
	return summary
}

func hookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Verify HMAC signature
	sig := r.Header.Get("X-StackManager-Signature")
	if !verifySignature(body, sig) {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// Parse envelope
	var envelope EventEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	logger := slog.With("request_id", envelope.RequestID)

	if envelope.Instance != nil {
		logger = logger.With("instance", envelope.Instance.Name)
	}

	images := extractImages(&envelope)
	if len(images) == 0 {
		logger.Info("no images found in envelope, allowing deploy")
		respondJSON(w, HookResponse{Allowed: true, Message: "no images to scan"})
		return
	}

	logger.Info("scanning images", "count", len(images), "images", images)

	// Scan all images
	var failures []string
	for _, img := range images {
		clean, msg := scanImage(img)
		if !clean {
			failures = append(failures, msg)
		}
	}

	if len(failures) > 0 {
		message := fmt.Sprintf("deploy blocked: %d image(s) failed security scan: %s",
			len(failures), strings.Join(failures, "; "))
		logger.Warn("deploy denied", "failures", len(failures))
		respondJSON(w, HookResponse{Allowed: false, Message: message})
		return
	}

	logger.Info("all images clean, allowing deploy")
	respondJSON(w, HookResponse{Allowed: true})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	// Check trivy is available
	if _, err := exec.LookPath("trivy"); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"error","message":"trivy not found in PATH"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func respondJSON(w http.ResponseWriter, resp HookResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	if secret == "" {
		slog.Warn("SCANNER_WEBHOOK_SECRET not set — signature verification disabled")
	}

	slog.Info("security-scan-gate starting",
		"severity", severityThreshold,
		"cache_ttl", cacheTTL,
		"trivy_timeout", trivyTimeout,
		"addr", listenAddr,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/hook", hookHandler)
	mux.HandleFunc("/healthz", healthHandler)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 180 * time.Second, // long write timeout for trivy scans
		IdleTimeout:  30 * time.Second,
	}

	slog.Info("security-scan-gate listening", "addr", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
