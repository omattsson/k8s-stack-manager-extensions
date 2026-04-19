// Package main implements a debug-bundle action webhook that collects
// diagnostics (pod logs, events, describe output) for a stack instance
// and returns a downloadable archive.
package main

import (
	"archive/tar"
	"compress/gzip"
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
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ActionRequest mirrors the k8s-stack-manager action envelope (subset).
type ActionRequest struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Action     string         `json:"action"`
	RequestID  string         `json:"request_id"`
	Instance   *InstanceRef   `json:"instance"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// InstanceRef identifies a stack instance.
type InstanceRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	OwnerID   string `json:"owner_id"`
	ClusterID string `json:"cluster_id,omitempty"`
}

// BundleResult is returned as the action response body.
type BundleResult struct {
	BundlePath  string `json:"bundle_path"`
	BundleURL   string `json:"bundle_url,omitempty"`
	Namespace   string `json:"namespace"`
	PodCount    int    `json:"pod_count"`
	SizeBytes   int64  `json:"size_bytes"`
	CollectedAt string `json:"collected_at"`
}

var (
	secret          string
	outputDir       string
	bundleBaseURL   string
	logTailLines    string
	listenAddr      string
	maxRequestBody  int64 = 1 << 20 // 1 MiB
	bundleTTLHours  int
	cleanupOnce     sync.Once
)

func init() {
	secret = os.Getenv("DEBUG_BUNDLE_SECRET")
	outputDir = os.Getenv("BUNDLE_OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "/tmp/bundles"
	}
	bundleBaseURL = os.Getenv("BUNDLE_BASE_URL")
	logTailLines = os.Getenv("LOG_TAIL_LINES")
	if logTailLines == "" {
		logTailLines = "500"
	}
	listenAddr = os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	ttl := os.Getenv("BUNDLE_TTL_HOURS")
	if ttl == "" {
		ttl = "24"
	}
	fmt.Sscanf(ttl, "%d", &bundleTTLHours)
	if bundleTTLHours == 0 {
		bundleTTLHours = 24
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

// runKubectl executes a kubectl command and returns its output.
func runKubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// collectBundle gathers diagnostics for the given namespace into a tar.gz file.
func collectBundle(namespace string) (*BundleResult, error) {
	timestamp := time.Now().UTC().Format("20060102T150405")
	bundleName := fmt.Sprintf("%s-%s", namespace, timestamp)
	bundleDir := filepath.Join(outputDir, bundleName)
	logsDir := filepath.Join(bundleDir, "logs")

	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create bundle dir: %w", err)
	}

	// Collect pod list
	podsOutput, _ := runKubectl("-n", namespace, "get", "pods", "-o", "wide", "--no-headers")
	os.WriteFile(filepath.Join(bundleDir, "pods.txt"), []byte(podsOutput), 0o644)

	// Count pods
	podCount := 0
	for _, line := range strings.Split(strings.TrimSpace(podsOutput), "\n") {
		if strings.TrimSpace(line) != "" {
			podCount++
		}
	}

	// Collect describe
	describeOutput, _ := runKubectl("-n", namespace, "describe", "pods")
	os.WriteFile(filepath.Join(bundleDir, "describe-pods.txt"), []byte(describeOutput), 0o644)

	// Collect events
	eventsOutput, _ := runKubectl("-n", namespace, "get", "events", "--sort-by=.lastTimestamp")
	os.WriteFile(filepath.Join(bundleDir, "events.txt"), []byte(eventsOutput), 0o644)

	// Collect top (optional — metrics-server may not be available)
	topOutput, err := runKubectl("-n", namespace, "top", "pods", "--no-headers")
	if err == nil {
		os.WriteFile(filepath.Join(bundleDir, "top-pods.txt"), []byte(topOutput), 0o644)
	}

	// Collect logs per pod/container
	podsJSON, err := runKubectl("-n", namespace, "get", "pods", "-o", "json")
	if err == nil {
		collectPodLogs(namespace, podsJSON, logsDir)
	}

	// Create tar.gz
	tarPath := filepath.Join(outputDir, bundleName+".tar.gz")
	if err := createTarGz(tarPath, bundleDir, bundleName); err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}

	// Clean up the uncompressed directory
	os.RemoveAll(bundleDir)

	// Get archive size
	info, err := os.Stat(tarPath)
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}

	result := &BundleResult{
		BundlePath:  tarPath,
		Namespace:   namespace,
		PodCount:    podCount,
		SizeBytes:   info.Size(),
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if bundleBaseURL != "" {
		result.BundleURL = fmt.Sprintf("%s/download/%s.tar.gz", bundleBaseURL, bundleName)
	} else {
		result.BundleURL = fmt.Sprintf("/download/%s.tar.gz", bundleName)
	}

	return result, nil
}

// collectPodLogs parses the pods JSON and collects logs for each container.
func collectPodLogs(namespace, podsJSON, logsDir string) {
	var podList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name string `json:"name"`
				} `json:"containers"`
				InitContainers []struct {
					Name string `json:"name"`
				} `json:"initContainers"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(podsJSON), &podList); err != nil {
		slog.Warn("failed to parse pods JSON", "error", err)
		return
	}

	for _, pod := range podList.Items {
		podDir := filepath.Join(logsDir, pod.Metadata.Name)
		os.MkdirAll(podDir, 0o755)

		allContainers := make([]string, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
		for _, c := range pod.Spec.InitContainers {
			allContainers = append(allContainers, c.Name)
		}
		for _, c := range pod.Spec.Containers {
			allContainers = append(allContainers, c.Name)
		}

		for _, container := range allContainers {
			logOutput, err := runKubectl("-n", namespace, "logs", pod.Metadata.Name,
				"-c", container, "--tail", logTailLines)
			if err != nil {
				logOutput = fmt.Sprintf("(failed to collect logs: %v)", err)
			}
			os.WriteFile(filepath.Join(podDir, container+".log"), []byte(logOutput), 0o644)
		}
	}
}

// createTarGz creates a gzipped tar archive from a directory.
func createTarGz(tarPath, sourceDir, prefix string) error {
	f, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Join(prefix, relPath)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(tw, file)
		return err
	})
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
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

	// Parse action request
	var req ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	logger := slog.With("request_id", req.RequestID)
	if req.Instance == nil {
		logger.Error("no instance in request")
		http.Error(w, `{"error":"instance required"}`, http.StatusBadRequest)
		return
	}

	namespace := req.Instance.Namespace
	if namespace == "" {
		logger.Error("no namespace in instance")
		http.Error(w, `{"error":"namespace required"}`, http.StatusBadRequest)
		return
	}

	// Validate namespace format to prevent command injection
	for _, ch := range namespace {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			logger.Error("invalid namespace characters", "namespace", namespace)
			http.Error(w, `{"error":"invalid namespace"}`, http.StatusBadRequest)
			return
		}
	}

	logger.Info("collecting debug bundle", "namespace", namespace, "instance", req.Instance.Name)

	result, err := collectBundle(namespace)
	if err != nil {
		logger.Error("bundle collection failed", "error", err)
		http.Error(w, `{"error":"bundle collection failed"}`, http.StatusInternalServerError)
		return
	}

	logger.Info("bundle collected",
		"namespace", namespace,
		"pods", result.PodCount,
		"size", result.SizeBytes,
		"path", result.BundlePath,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// downloadHandler serves bundle files for download.
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := filepath.Base(r.URL.Path)
	// Validate filename to prevent path traversal
	if strings.Contains(filename, "..") || !strings.HasSuffix(filename, ".tar.gz") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	filePath := filepath.Join(outputDir, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, filePath)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"error","message":"kubectl not found in PATH"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// cleanupOldBundles removes bundles older than BUNDLE_TTL_HOURS.
func cleanupOldBundles() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			continue
		}
		cutoff := time.Now().Add(-time.Duration(bundleTTLHours) * time.Hour)
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				path := filepath.Join(outputDir, entry.Name())
				slog.Info("cleaning up old bundle", "path", path)
				os.Remove(path)
			}
		}
	}
}

func main() {
	if secret == "" {
		slog.Warn("DEBUG_BUNDLE_SECRET not set — signature verification disabled")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		slog.Error("failed to create output directory", "dir", outputDir, "error", err)
		os.Exit(1)
	}

	// Start background cleanup
	go cleanupOldBundles()

	slog.Info("debug-bundle starting",
		"output_dir", outputDir,
		"bundle_ttl_hours", bundleTTLHours,
		"log_tail_lines", logTailLines,
		"addr", listenAddr,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/action", actionHandler)
	mux.HandleFunc("/download/", downloadHandler)
	mux.HandleFunc("/healthz", healthHandler)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	slog.Info("debug-bundle listening", "addr", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
