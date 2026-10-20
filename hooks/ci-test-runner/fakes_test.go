package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// ---------------------------------------------------------------------------
// Fake Entra ID credential
// ---------------------------------------------------------------------------

type fakeCred struct {
	err   error
	calls map[string]int
	mu    sync.Mutex
}

func newFakeCred() *fakeCred { return &fakeCred{calls: map[string]int{}} }

func (f *fakeCred) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	scope := strings.Join(opts.Scopes, " ")
	f.calls[scope]++
	return azcore.AccessToken{Token: "entra:" + scope, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (f *fakeCred) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *fakeCred) count(scope string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[scope]
}

// ---------------------------------------------------------------------------
// Fake Azure DevOps
// ---------------------------------------------------------------------------

type fakeBuild struct {
	// statuses, when set, are the statuses of the next reads. The last one
	// stays.
	statuses  []string
	status    string
	result    string // result when the build completes
	queueLeft int    // reads that still show notStarted; -1 is forever
	runLeft   int    // reads that show inProgress; -1 is forever
	id        int
}

type queuedBuild struct {
	TemplateParameters map[string]string `json:"templateParameters"`
	SourceBranch       string            `json:"sourceBranch"`
	Definition         struct {
		ID int `json:"id"`
	} `json:"definition"`
}

type fakeADO struct {
	builds     map[int]*fakeBuild
	runs       map[string][]testRun // build URI → test runs
	srv        *httptest.Server
	nextResult string
	queued     []queuedBuild
	runQueries []url.Values
	queueDelay time.Duration
	// queueStatus, when set, is the status of every queue call.
	queueStatus int
	// failQueues is the number of next queue calls that fail with 500.
	failQueues int
	// nextStatuses, when set, are the read statuses of new builds.
	nextStatuses []string
	// failBuildGets is the number of next build reads that fail; -1 is all.
	failBuildGets int
	// failStatus is the status of a failed build read (default 500).
	failStatus int
	// retryAfter, when set, is the Retry-After header of a failed read.
	retryAfter string
	// readTimes are the times of the build reads.
	readTimes []time.Time
	// queueWaitPolls and runPolls are the defaults of new builds.
	queueWaitPolls int
	runPolls       int
	buildGets      int
	// otherCalls counts calls that the runner must never make, for example
	// a PATCH that cancels a build.
	otherCalls int
	nextID     int
	failRuns   bool
	mu         sync.Mutex
}

func newFakeADO(t *testing.T) *fakeADO {
	f := &fakeADO{
		builds:     map[int]*fakeBuild{},
		runs:       map[string][]testRun{},
		nextID:     100,
		nextResult: "succeeded",
		runPolls:   1,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeADO) set(fn func(*fakeADO)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeADO) queuedList() []queuedBuild {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]queuedBuild(nil), f.queued...)
}

func (f *fakeADO) counts() (queued, buildGets, other int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queued), f.buildGets, f.otherCalls
}

func (f *fakeADO) webURL(id int) string {
	return fmt.Sprintf("%s/org/proj/_build/results?buildId=%d", f.srv.URL, id)
}

func (f *fakeADO) buildJSON(b *fakeBuild) map[string]any {
	out := map[string]any{
		"id":          b.id,
		"buildNumber": fmt.Sprintf("20261020.%d", b.id-100),
		"status":      b.status,
		"uri":         fmt.Sprintf("vstfs:///Build/Build/%d", b.id),
		"_links":      map[string]any{"web": map[string]string{"href": f.webURL(b.id)}},
	}
	if b.status == "completed" {
		out["result"] = b.result
	}
	return out
}

func (f *fakeADO) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer entra:"+adoScope {
		// Real ADO sends 203 with a sign-in page.
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		w.Write([]byte("<html>sign in</html>"))
		return
	}
	f.mu.Lock()
	queueDelay := f.queueDelay
	f.mu.Unlock()

	path := r.URL.Path
	if !strings.HasPrefix(path, "/org/proj/_apis/") || r.URL.Query().Get("api-version") != "7.1" {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == "/org/proj/_apis/build/builds" && r.Method == http.MethodPost:
		if queueDelay > 0 {
			time.Sleep(queueDelay)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		var q queuedBuild
		json.NewDecoder(r.Body).Decode(&q)
		if f.queueStatus != 0 || f.failQueues > 0 {
			status := f.queueStatus
			if f.failQueues > 0 {
				f.failQueues--
				status = http.StatusInternalServerError
			}
			http.Error(w, "boom secret-token-123 at https://internal.example/x", status)
			return
		}
		f.queued = append(f.queued, q)
		f.nextID++
		b := &fakeBuild{
			id:        f.nextID,
			status:    "notStarted",
			result:    f.nextResult,
			queueLeft: f.queueWaitPolls,
			runLeft:   f.runPolls,
			statuses:  append([]string(nil), f.nextStatuses...),
		}
		f.builds[b.id] = b
		json.NewEncoder(w).Encode(f.buildJSON(b))

	case strings.HasPrefix(path, "/org/proj/_apis/build/builds/") && r.Method == http.MethodGet:
		f.mu.Lock()
		defer f.mu.Unlock()
		f.buildGets++
		f.readTimes = append(f.readTimes, time.Now())
		if f.failBuildGets != 0 {
			if f.failBuildGets > 0 {
				f.failBuildGets--
			}
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			status := f.failStatus
			if status == 0 {
				status = http.StatusInternalServerError
			}
			http.Error(w, "boom", status)
			return
		}
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/org/proj/_apis/build/builds/"))
		b, ok := f.builds[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(b.statuses) > 0:
			b.status = b.statuses[0]
			if len(b.statuses) > 1 {
				b.statuses = b.statuses[1:]
			}
		case b.status == "notStarted" && b.queueLeft != 0:
			if b.queueLeft > 0 {
				b.queueLeft--
			}
		case b.status != "completed" && b.runLeft != 0:
			if b.runLeft > 0 {
				b.runLeft--
			}
			b.status = "inProgress"
		default:
			b.status = "completed"
		}
		json.NewEncoder(w).Encode(f.buildJSON(b))

	case path == "/org/proj/_apis/test/runs" && r.Method == http.MethodGet:
		f.mu.Lock()
		defer f.mu.Unlock()
		f.runQueries = append(f.runQueries, r.URL.Query())
		if f.failRuns {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		runs := f.runs[r.URL.Query().Get("buildUri")]
		if runs == nil {
			runs = []testRun{}
		}
		json.NewEncoder(w).Encode(map[string]any{"value": runs, "count": len(runs)})

	default:
		f.mu.Lock()
		f.otherCalls++
		f.mu.Unlock()
		http.Error(w, "unexpected call", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Test wiring
// ---------------------------------------------------------------------------

type testEnv struct {
	ado  *fakeADO
	cred *fakeCred
	h    *handler
	mux  *http.ServeMux
}

func testConfig() config {
	return config{
		Suites: map[string]suiteConfig{
			"smoke": {PipelineID: 42},
			"full":  {PipelineID: 43, SourceBranch: "refs/heads/release"},
		},
		ADOOrg:               "org",
		ADOProject:           "proj",
		ADOAuth:              authWorkloadIdentity,
		PipelineSourceBranch: "refs/heads/main",
		PollInterval:         5 * time.Millisecond,
		TestTimeout:          5 * time.Second,
		JobRetention:         time.Hour,
		WaitLogInterval:      time.Hour,
		PollErrorWindow:      200 * time.Millisecond,
		MaxPollBackoff:       20 * time.Millisecond,
		MaxLogBytes:          defaultMaxLogBytes,
		AllowUnsigned:        true,
	}
}

func newTestEnv(t *testing.T, mutate func(*config)) *testEnv {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	e := &testEnv{ado: newFakeADO(t), cred: newFakeCred()}
	ci := newADOClient(cfg.ADOOrg, cfg.ADOProject, cfg.ADOAuth, cfg.ADOPAT, newEntraTokenSource(e.cred))
	ci.baseURL = e.ado.srv.URL
	e.h = newHandler(cfg, ci)
	e.mux = e.h.routes()
	// Cleanups run last in, first out: the runner stops before the fake.
	t.Cleanup(func() { e.h.stop(2 * time.Second) })
	return e
}

func testInstance() InstanceRef {
	return InstanceRef{
		ID:        "i1",
		Name:      "demo",
		Namespace: "stack-demo-alice",
		Branch:    "feature/login",
		Status:    "running",
	}
}

func actionBody(inst *InstanceRef, params map[string]any) []byte {
	req := ActionRequest{
		APIVersion: "hooks.k8sstackmanager.io/v1",
		Kind:       "ActionRequest",
		Action:     "run-tests",
		Timestamp:  time.Now(),
		RequestID:  fmt.Sprintf("req-%d", requestSeq.Add(1)),
		Instance:   inst,
		Parameters: params,
	}
	body, _ := json.Marshal(req)
	return body
}

func sign(secret string, msg []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// post sends POST /action. A non-empty sig sets the signature header.
func (e *testEnv) post(t *testing.T, body []byte, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/action", bytes.NewReader(body))
	if sig != "" {
		req.Header.Set(signatureHeader, sig)
	}
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	return rr
}

// run posts a valid request for inst and returns the response.
func (e *testEnv) run(t *testing.T, inst InstanceRef, suite string) actionResponse {
	t.Helper()
	body := actionBody(&inst, map[string]any{"suite": suite})
	rr := e.post(t, body, sign(e.h.cfg.Secret, body))
	if rr.Code != http.StatusAccepted && rr.Code != http.StatusOK {
		t.Fatalf("POST /action: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	return decodeAction(t, rr)
}

func decodeAction(t *testing.T, rr *httptest.ResponseRecorder) actionResponse {
	t.Helper()
	var resp actionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response %q is not JSON: %v", rr.Body.String(), err)
	}
	return resp
}

func errorText(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response %q is not JSON: %v", rr.Body.String(), err)
	}
	return resp["error"]
}

// logURI returns the request URI of a job log read, in the form that the
// backend sends (sorted query keys).
func logURI(jobID, instanceID string, offset int, ts int64) string {
	q := url.Values{}
	q.Set("offset", strconv.Itoa(offset))
	if instanceID != "" {
		q.Set("instance_id", instanceID)
	}
	q.Set("ts", strconv.FormatInt(ts, 10))
	return "/jobs/" + jobID + "/log?" + q.Encode()
}

// getURI sends GET uri, signed with sig when sig is not empty.
func (e *testEnv) getURI(t *testing.T, uri, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, uri, nil)
	if sig != "" {
		req.Header.Set(signatureHeader, sig)
	}
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	return rr
}

// getLog reads the job log with a valid ts and signature.
func (e *testEnv) getLog(t *testing.T, jobID, instanceID string, offset int) *httptest.ResponseRecorder {
	t.Helper()
	uri := logURI(jobID, instanceID, offset, time.Now().Unix())
	return e.getURI(t, uri, sign(e.h.cfg.Secret, []byte(uri)))
}

// waitDone waits until the job has a final status and returns it.
func (e *testEnv) waitDone(t *testing.T, jobID string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j := e.h.store.get(jobID); j != nil {
			if s, _ := j.state(); s != jobRunning {
				return s
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish; log:\n%s", jobID, e.logText(jobID))
	return ""
}

func (e *testEnv) logText(jobID string) string {
	j := e.h.store.get(jobID)
	if j == nil {
		return ""
	}
	data, _ := j.read(0)
	return string(data)
}

// logLines returns the log lines without their time stamps.
func (e *testEnv) logLines(t *testing.T, jobID string) []string {
	t.Helper()
	text := strings.TrimSuffix(e.logText(jobID), "\n")
	if text == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if !timestampRe.MatchString(line) {
			t.Errorf("line %q has no UTC time stamp", line)
		}
		out = append(out, timestampRe.ReplaceAllString(line, ""))
	}
	return out
}

func count(lines []string, want string) int {
	n := 0
	for _, l := range lines {
		if l == want {
			n++
		}
	}
	return n
}

var errFake = errors.New("fake failure")

// requestSeq gives each test request its own request_id.
var requestSeq atomic.Int64

var timestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z `)
