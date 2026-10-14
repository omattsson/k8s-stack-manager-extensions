package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	oldCommit   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherCommit = "cccccccccccccccccccccccccccccccccccccccc"
)

func TestLoadConfig_RebuildOnNewCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    bool
		wantErr bool
	}{
		{name: "default is true", value: "", want: true},
		{name: "false turns the check off", value: "false", want: false},
		{name: "TRUE", value: "TRUE", want: true},
		{name: "invalid value fails", value: "maybe", wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadConfig(func(k string) string {
				switch k {
				case "CI_TRIGGER_WEBHOOK_SECRET":
					return "s"
				case "REBUILD_ON_NEW_COMMIT":
					return tt.value
				}
				return ""
			})
			if tt.wantErr {
				if err == nil {
					t.Error("loadConfig succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.RebuildOnNewCommit != tt.want {
				t.Errorf("RebuildOnNewCommit = %v, want %v", cfg.RebuildOnNewCommit, tt.want)
			}
		})
	}
}

func TestHook_RebuildOnNewCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		setup      func(e *testEnv)
		mutate     func(c *config)
		sourceURL  string
		wantQueued int
		wantLogs   []string
		notLogs    []string
	}{
		{
			name:       "label equals the branch head",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", testHead) },
			wantLogs:   []string{"Image dev/api:feature-x found"},
			notLogs:    []string{"WARNING"},
			wantQueued: 0,
		},
		{
			name:       "short label equals the branch head",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", strings.ToUpper(testHead[:12])) },
			wantLogs:   []string{"Image dev/api:feature-x found"},
			wantQueued: 0,
		},
		{
			name:       "label differs from the branch head",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", oldCommit) },
			wantLogs:   []string{"Image dev/api:feature-x is at bbbbbbbb, branch is at aaaaaaaa; building again", "Queued build #101"},
			notLogs:    []string{"WARNING"},
			wantQueued: 1,
		},
		{
			name:       "image index with an old label",
			setup:      func(e *testEnv) { e.acr.pushIndex("dev/api", "feature-x", oldCommit) },
			wantLogs:   []string{"is at bbbbbbbb, branch is at aaaaaaaa; building again"},
			wantQueued: 1,
		},
		{
			name:       "image index at the branch head",
			setup:      func(e *testEnv) { e.acr.pushIndex("dev/api", "feature-x", testHead) },
			wantLogs:   []string{"Image dev/api:feature-x found"},
			wantQueued: 0,
		},
		{
			name:       "image without the label is kept",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", "") },
			wantLogs:   []string{"WARNING: dev/api:feature-x has no label org.opencontainers.image.revision"},
			wantQueued: 0,
		},
		{
			name: "label read error keeps the image",
			setup: func(e *testEnv) {
				// The config blob does not exist.
				e.acr.push("dev/api", "feature-x", dockerV2Type, `{"schemaVersion":2,"config":{"digest":"sha256:0000"}}`)
			},
			wantLogs:   []string{"WARNING: cannot read label org.opencontainers.image.revision of dev/api:feature-x"},
			wantQueued: 0,
		},
		{
			name:       "check turned off",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", oldCommit) },
			mutate:     func(c *config) { c.RebuildOnNewCommit = false },
			wantLogs:   []string{"Image dev/api:feature-x found"},
			notLogs:    []string{"WARNING", "building again"},
			wantQueued: 0,
		},
		{
			name:       "source repo outside Azure DevOps has no head",
			setup:      func(e *testEnv) { e.acr.pushImage("dev/api", "feature-x", oldCommit) },
			sourceURL:  "https://github.com/acme/api.git",
			wantLogs:   []string{"Image dev/api:feature-x found"},
			notLogs:    []string{"building again"},
			wantQueued: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, tt.mutate)
			e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
			e.ado.refs["org/proj/api"] = []string{"feature/x"}
			e.ado.onQueueSuccess = func(tag string) { e.acr.pushImage("dev/api", tag, testHead) }
			tt.setup(e)

			chart := appChart("api", "feature/x")
			if tt.sourceURL != "" {
				chart.SourceRepoURL = tt.sourceURL
			}
			res := e.post(t, envelope("", chart))
			if !res.resp.Allowed {
				t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
			}
			if got := e.ado.queuedCount(); got != tt.wantQueued {
				t.Errorf("queued = %d, want %d\n%s", got, tt.wantQueued, res.logText())
			}
			for _, want := range tt.wantLogs {
				if !strings.Contains(res.logText(), want) {
					t.Errorf("logs do not contain %q:\n%s", want, res.logText())
				}
			}
			for _, not := range tt.notLogs {
				if strings.Contains(res.logText(), not) {
					t.Errorf("logs contain %q:\n%s", not, res.logText())
				}
			}
			if tt.wantQueued > 0 {
				q := e.ado.firstQueued()
				if q.TemplateParameters["branch"] != "feature/x" || q.TemplateParameters["imageTag"] != "feature-x" {
					t.Errorf("queued build = %+v", q)
				}
			}
		})
	}
}

func TestHook_ExtraRepoOlderTriggersBuild(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, func(c *config) { c.ExtraImages = map[string][]string{"pdf": {"gotenberg"}} })
	e.acr.pushImage("dev/pdf", "feature-y", testHead)
	e.acr.pushImage("dev/gotenberg", "feature-y", oldCommit)
	e.ado.refs["org/proj/pdf"] = []string{"feature/y"}
	e.ado.onQueueSuccess = func(tag string) {
		e.acr.pushImage("dev/pdf", tag, testHead)
		e.acr.pushImage("dev/gotenberg", tag, testHead)
	}

	res := e.post(t, envelope("", appChart("pdf", "feature/y")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if e.ado.queuedCount() != 1 {
		t.Errorf("queued = %d, want 1\n%s", e.ado.queuedCount(), res.logText())
	}
	if !strings.Contains(res.logText(), "Image dev/gotenberg:feature-y is at bbbbbbbb") {
		t.Errorf("logs:\n%s", res.logText())
	}
}

func TestHook_CacheChecksTheNewHead(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.pushImage("dev/api", "feature-x", testHead)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.onQueueSuccess = func(tag string) { e.acr.pushImage("dev/api", tag, otherCommit) }

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed || e.ado.queuedCount() != 0 {
		t.Fatalf("first deploy: resp = %+v, queued = %d\n%s", res.resp, e.ado.queuedCount(), res.logText())
	}
	res = e.post(t, envelope("", appChart("api", "feature/x")))
	if !strings.Contains(res.logText(), "(cached)") {
		t.Errorf("second deploy with the same head did not use the cache:\n%s", res.logText())
	}

	// A new commit on the branch bypasses the cache.
	e.ado.set(func(f *fakeADO) { f.heads["org/proj/api/feature/x"] = otherCommit })
	res = e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if e.ado.queuedCount() != 1 || strings.Contains(res.logText(), "(cached)") {
		t.Errorf("queued = %d, want 1\n%s", e.ado.queuedCount(), res.logText())
	}
}

func TestHook_BuildFromOtherCommitWarns(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.pushImage("dev/api", "feature-x", oldCommit)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	// The pipeline labels the image with another commit.
	e.ado.onQueueSuccess = func(tag string) { e.acr.pushImage("dev/api", tag, otherCommit) }

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	if !strings.Contains(res.logText(), "WARNING: the build pushed dev/api:feature-x from commit cccccccc, but the branch was at aaaaaaaa") {
		t.Errorf("logs:\n%s", res.logText())
	}

	// The gate remembers that it built the image for this head: no build
	// loop, also after the cache expires.
	e.h.cache = newImageCache(0)
	res = e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed || e.ado.queuedCount() != 1 {
		t.Errorf("queued = %d, want 1\n%s", e.ado.queuedCount(), res.logText())
	}

	// A new commit builds again.
	e.ado.set(func(f *fakeADO) { f.heads["org/proj/api/feature/x"] = otherCommit[:39] + "d" })
	res = e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed || e.ado.queuedCount() != 2 {
		t.Errorf("queued = %d, want 2\n%s", e.ado.queuedCount(), res.logText())
	}
}

func TestHook_ReusedOldBuildBuildsAgain(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.pushImage("dev/api", "feature-x", oldCommit)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	// A build of the older commit runs already.
	e.ado.addRunning(8, 42, "feature-x", func() { e.acr.pushImage("dev/api", "feature-x", oldCommit) })
	e.ado.onQueueSuccess = func(tag string) { e.acr.pushImage("dev/api", tag, testHead) }

	res := e.post(t, envelope("", appChart("api", "feature/x")))
	if !res.resp.Allowed {
		t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
	}
	for _, want := range []string{"Reusing running build #8", "Reused build #8 pushed dev/api:feature-x from commit bbbbbbbb, but the branch is at aaaaaaaa; building again", "Queued build #101"} {
		if !strings.Contains(res.logText(), want) {
			t.Errorf("logs do not contain %q:\n%s", want, res.logText())
		}
	}
	if e.ado.queuedCount() != 1 {
		t.Errorf("queued = %d, want 1", e.ado.queuedCount())
	}
	rev, err := e.h.registry.imageRevision(context.Background(), "dev/api", e.acr.digest("dev/api", "feature-x"))
	if err != nil || rev != testHead {
		t.Errorf("final image revision = %q, %v; want the branch head", rev, err)
	}
}

func TestHook_ConcurrentRetriesShareOneBuild(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
	e.acr.pushImage("dev/api", "feature-x", oldCommit)
	e.ado.refs["org/proj/api"] = []string{"feature/x"}
	e.ado.set(func(f *fakeADO) { f.queuePolls = 6 })
	// Both deploys reuse a running build of the older commit.
	e.ado.addRunning(8, 42, "feature-x", func() { e.acr.pushImage("dev/api", "feature-x", oldCommit) })
	e.ado.onQueueSuccess = func(tag string) { e.acr.pushImage("dev/api", tag, testHead) }

	body, _ := json.Marshal(envelope("", appChart("api", "feature/x")))
	outs := make([]string, 2)
	var wg sync.WaitGroup
	for i := range outs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			e.h.hookHandler(rr, httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(string(body))))
			outs[i] = rr.Body.String()
		}(i)
	}
	wg.Wait()

	for _, out := range outs {
		if res := parseStream(t, out); !res.resp.Allowed {
			t.Errorf("resp = %+v\n%s", res.resp, res.logText())
		}
	}
	if got := e.ado.queuedCount(); got != 1 {
		t.Errorf("queued = %d, want 1\n%s\n---\n%s", got, outs[0], outs[1])
	}
}

func TestHook_DefaultAndProtectedTagsReadNoLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		branch string
		tag    string
	}{
		{name: "default branch", branch: "main", tag: "main"},
		{name: "protected tag", branch: "latest", tag: "latest"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			e.acr.push("dev/api", "latest-dev", dockerV2Type, `{"m":"fallback"}`)
			e.acr.pushImage("dev/api", tt.tag, oldCommit)
			e.ado.refs["org/proj/api"] = []string{tt.branch}

			chart := appChart("api", tt.branch)
			chart.ImageTag = tt.tag
			res := e.post(t, envelope("", chart))
			if !res.resp.Allowed {
				t.Fatalf("resp = %+v\n%s", res.resp, res.logText())
			}
			if e.acr.blobGetCount() != 0 || e.ado.queuedCount() != 0 {
				t.Errorf("blob reads = %d, queued = %d; want 0/0\n%s", e.acr.blobGetCount(), e.ado.queuedCount(), res.logText())
			}
		})
	}
}

func TestACR_BlobRedirectDropsToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.pushImage("dev/api", "feature-x", testHead)

	var gotAuth []string
	var mu sync.Mutex
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, "/storage/")
		i := strings.LastIndex(rest, "/")
		e.acr.mu.Lock()
		b, ok := e.acr.blobs[rest[:i]][rest[i+1:]]
		e.acr.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(storage.Close)
	// Another host name than the registry (127.0.0.1), as a storage account is.
	e.acr.mu.Lock()
	e.acr.blobRedirect = strings.Replace(storage.URL, "127.0.0.1", "localhost", 1)
	e.acr.mu.Unlock()

	rev, err := e.h.registry.imageRevision(context.Background(), "dev/api", e.acr.digest("dev/api", "feature-x"))
	if err != nil || rev != testHead {
		t.Fatalf("imageRevision = %q, %v", rev, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotAuth) != 1 || gotAuth[0] != "" {
		t.Errorf("storage requests got Authorization %q, want one request without it", gotAuth)
	}
}

func TestACR_GetBlobChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    []byte
		wantErr string
	}{
		{name: "digest mismatch", body: []byte(`{"other":true}`), wantErr: "digest mismatch"},
		{name: "too large", body: make([]byte, maxConfigBlobSize+1), wantErr: "larger than"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, nil)
			digest := digestOf([]byte(`{"expected":true}`))
			e.acr.mu.Lock()
			e.acr.blobs["dev/api"] = map[string][]byte{digest: tt.body}
			e.acr.mu.Unlock()

			_, err := e.h.registry.(*acrClient).getBlob(context.Background(), "dev/api", digest)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("getBlob error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestACR_ImageRevisionCached(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, nil)
	e.acr.pushImage("dev/api", "feature-x", testHead)
	digest := e.acr.digest("dev/api", "feature-x")

	for i := 0; i < 2; i++ {
		rev, err := e.h.registry.imageRevision(context.Background(), "dev/api", digest)
		if err != nil || rev != testHead {
			t.Fatalf("imageRevision = %q, %v", rev, err)
		}
	}
	if got := e.acr.blobGetCount(); got != 1 {
		t.Errorf("blob reads = %d, want 1", got)
	}
}

func TestSameCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "equal", a: testHead, b: testHead, want: true},
		{name: "short form", a: testHead[:7], b: testHead, want: true},
		{name: "short form second", a: testHead, b: testHead[:10], want: true},
		{name: "case and spaces", a: " " + strings.ToUpper(testHead) + " ", b: testHead, want: true},
		{name: "different", a: oldCommit, b: testHead},
		{name: "too short", a: testHead[:6], b: testHead},
		{name: "equal short", a: "abc", b: "abc", want: true},
		{name: "empty", a: "", b: ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sameCommit(tt.a, tt.b); got != tt.want {
				t.Errorf("sameCommit(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestPlatformManifest(t *testing.T) {
	t.Parallel()
	entry := func(os, arch, digest string) indexEntry {
		e := indexEntry{Digest: digest}
		if os != "" {
			e.Platform = &struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			}{OS: os, Architecture: arch}
		}
		return e
	}
	tests := []struct {
		name    string
		entries []indexEntry
		want    string
	}{
		{name: "linux/amd64 wins", entries: []indexEntry{entry("linux", "arm64", "arm"), entry("linux", "amd64", "amd")}, want: "amd"},
		{name: "attestation skipped", entries: []indexEntry{entry("unknown", "unknown", "att"), entry("linux", "arm64", "arm")}, want: "arm"},
		{name: "no platform", entries: []indexEntry{entry("", "", "x")}, want: ""},
		{name: "empty", want: ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := platformManifest(tt.entries); got != tt.want {
				t.Errorf("platformManifest = %q, want %q", got, tt.want)
			}
		})
	}
}
