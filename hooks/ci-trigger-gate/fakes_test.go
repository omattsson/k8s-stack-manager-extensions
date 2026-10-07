package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

func (f *fakeCred) count(scope string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[scope]
}

// ---------------------------------------------------------------------------
// Fake Azure Container Registry
// ---------------------------------------------------------------------------

const (
	testRegistryHost = "test.azurecr.io"
	ociIndexType     = "application/vnd.oci.image.index.v1+json"
	dockerV2Type     = "application/vnd.docker.distribution.manifest.v2+json"
)

type storedManifest struct {
	contentType string
	body        []byte
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type fakeACR struct {
	manifests map[string]map[string]storedManifest // repo → tag → manifest
	srv       *httptest.Server
	puts      []string
	exchanges int
	username  string
	password  string
	mu        sync.Mutex
}

func newFakeACR(t *testing.T) *fakeACR {
	f := &fakeACR{manifests: map[string]map[string]storedManifest{}, username: "user", password: "pass"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACR) push(repo, tag, contentType, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.manifests[repo] == nil {
		f.manifests[repo] = map[string]storedManifest{}
	}
	f.manifests[repo][tag] = storedManifest{contentType: contentType, body: []byte(body)}
}

func (f *fakeACR) digest(repo, tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.manifests[repo][tag]
	if !ok {
		return ""
	}
	return digestOf(m.body)
}

func (f *fakeACR) contentType(repo, tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.manifests[repo][tag].contentType
}

func (f *fakeACR) putList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.puts...)
}

func (f *fakeACR) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}

func (f *fakeACR) exchangeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges
}

func (f *fakeACR) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/oauth2/exchange" && r.Method == http.MethodPost:
		r.ParseForm()
		if r.Form.Get("grant_type") != "access_token" || r.Form.Get("service") != testRegistryHost ||
			r.Form.Get("access_token") != "entra:"+acrScope {
			http.Error(w, "bad exchange", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.exchanges++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"refresh_token": "acr-refresh"})
	case r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost:
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "acr-refresh" ||
			r.Form.Get("service") != testRegistryHost {
			http.Error(w, "bad token request", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "acc|" + r.Form.Get("scope")})
	case r.URL.Path == "/oauth2/token" && r.Method == http.MethodGet:
		u, p, ok := r.BasicAuth()
		if !ok || u != f.username || p != f.password {
			http.Error(w, "bad basic auth", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "acc|" + r.URL.Query().Get("scope")})
	case strings.HasPrefix(r.URL.Path, "/v2/"):
		f.serveManifest(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeACR) serveManifest(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	i := strings.LastIndex(rest, "/manifests/")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	repo, ref := rest[:i], rest[i+len("/manifests/"):]
	if r.Header.Get("Authorization") != "Bearer acc|repository:"+repo+":pull,push" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		m, ok := f.manifests[repo][ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", m.contentType)
		w.Header().Set("Docker-Content-Digest", digestOf(m.body))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(m.body)
		}
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if f.manifests[repo] == nil {
			f.manifests[repo] = map[string]storedManifest{}
		}
		f.manifests[repo][ref] = storedManifest{contentType: r.Header.Get("Content-Type"), body: body}
		f.puts = append(f.puts, repo+":"+ref)
		w.Header().Set("Docker-Content-Digest", digestOf(body))
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Fake Azure DevOps
// ---------------------------------------------------------------------------

type fakeBuild struct {
	tp          map[string]string
	status      string
	finalResult string
	onSuccess   func()
	definition  int
	pollsLeft   int
	id          int
}

type queuedBuild struct {
	TemplateParameters map[string]string `json:"templateParameters"`
	SourceBranch       string            `json:"sourceBranch"`
	Definition         struct {
		ID int `json:"id"`
	} `json:"definition"`
}

type fakeADO struct {
	refs   map[string][]string // "org/project/repo" → branch names
	builds map[int]*fakeBuild
	srv    *httptest.Server
	// nextResult is the result of the next queued build.
	nextResult string
	// onQueueSuccess runs when a queued build succeeds (it "pushes" images).
	onQueueSuccess func(tag string)
	queued         []queuedBuild
	// omitListTP removes template parameters from the build list response.
	omitListTP bool
	// failBuildGets makes every read of one build fail with status 500.
	failBuildGets bool
	// queuePolls is the number of status reads before a queued build ends.
	queuePolls int
	buildGets  int
	nextID     int
	mu         sync.Mutex
}

func newFakeADO(t *testing.T) *fakeADO {
	f := &fakeADO{
		refs:       map[string][]string{},
		builds:     map[int]*fakeBuild{},
		nextID:     100,
		nextResult: "succeeded",
		queuePolls: 2,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeADO) queuedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queued)
}

func (f *fakeADO) getCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buildGets
}

func (f *fakeADO) set(fn func(*fakeADO)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeADO) firstQueued() queuedBuild {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queued[0]
}

func (f *fakeADO) buildJSON(b *fakeBuild, withTP bool) map[string]any {
	out := map[string]any{
		"id":     b.id,
		"status": b.status,
		"_links": map[string]any{"web": map[string]string{"href": fmt.Sprintf("https://ado.example/build/%d", b.id)}},
	}
	if b.status == "completed" {
		out["result"] = b.finalResult
	}
	if withTP {
		out["templateParameters"] = b.tp
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
	defer f.mu.Unlock()

	path := r.URL.Path
	switch {
	case strings.Contains(path, "/_apis/git/repositories/") && strings.HasSuffix(path, "/refs"):
		// /{org}/{project}/_apis/git/repositories/{repo}/refs
		segs := strings.Split(strings.Trim(path, "/"), "/")
		key := segs[0] + "/" + segs[1] + "/" + segs[5]
		prefix := "refs/" + r.URL.Query().Get("filter")
		var value []map[string]string
		for _, b := range f.refs[key] {
			if name := "refs/heads/" + b; strings.HasPrefix(name, prefix) {
				value = append(value, map[string]string{"name": name})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"value": value})

	case strings.HasSuffix(path, "/_apis/build/builds") && r.Method == http.MethodGet:
		def, _ := strconv.Atoi(r.URL.Query().Get("definitions"))
		var value []map[string]any
		for _, b := range f.builds {
			if b.definition == def && b.status != "completed" {
				value = append(value, f.buildJSON(b, !f.omitListTP))
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"value": value})

	case strings.HasSuffix(path, "/_apis/build/builds") && r.Method == http.MethodPost:
		var q queuedBuild
		json.NewDecoder(r.Body).Decode(&q)
		f.queued = append(f.queued, q)
		f.nextID++
		b := &fakeBuild{
			id:          f.nextID,
			definition:  q.Definition.ID,
			status:      "notStarted",
			tp:          q.TemplateParameters,
			pollsLeft:   f.queuePolls,
			finalResult: f.nextResult,
		}
		if f.onQueueSuccess != nil {
			tag := q.TemplateParameters["imageTag"]
			b.onSuccess = func() { f.onQueueSuccess(tag) }
		}
		f.builds[b.id] = b
		json.NewEncoder(w).Encode(f.buildJSON(b, true))

	case strings.Contains(path, "/_apis/build/builds/") && r.Method == http.MethodGet:
		f.buildGets++
		if f.failBuildGets {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		id, _ := strconv.Atoi(path[strings.LastIndex(path, "/")+1:])
		b, ok := f.builds[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if b.status != "completed" && b.pollsLeft >= 0 {
			b.pollsLeft--
			b.status = "inProgress"
			if b.pollsLeft < 0 {
				b.status = "completed"
				if b.finalResult == "succeeded" && b.onSuccess != nil {
					b.onSuccess()
				}
			}
		}
		json.NewEncoder(w).Encode(f.buildJSON(b, true))

	default:
		http.NotFound(w, r)
	}
}

// addRunning adds an unfinished build that succeeds after two polls.
func (f *fakeADO) addRunning(id, definition int, tag string, onSuccess func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds[id] = &fakeBuild{
		id: id, definition: definition, status: "inProgress", pollsLeft: 2,
		finalResult: "succeeded", tp: map[string]string{"branch": "x", "imageTag": tag}, onSuccess: onSuccess,
	}
}

// ---------------------------------------------------------------------------
// Test wiring
// ---------------------------------------------------------------------------

type testEnv struct {
	acr  *fakeACR
	ado  *fakeADO
	cred *fakeCred
	h    *handler
}

func testConfig() config {
	return config{
		ImageRepoPrefix:      "dev/",
		FallbackTag:          "latest-dev",
		DefaultBranches:      map[string]bool{"main": true, "master": true},
		ExtraImages:          map[string][]string{},
		ADOOrg:               "org",
		ADOProject:           "proj",
		RegistryURL:          testRegistryHost,
		RegistryAuth:         authWorkloadIdentity,
		ADOAuth:              authWorkloadIdentity,
		PipelineSourceBranch: "refs/heads/main",
		ProtectedTags:        regexp.MustCompile(defaultProtectedTags),
		AllowUnsigned:        true,
		AliasMarkerSuffix:    ".alias",
		PollInterval:         5 * time.Millisecond,
		BuildTimeout:         5 * time.Second,
		CacheTTL:             time.Minute,
	}
}

func newTestEnv(t *testing.T, mutate func(*config)) *testEnv {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	env := &testEnv{acr: newFakeACR(t), ado: newFakeADO(t), cred: newFakeCred()}
	entra := newEntraTokenSource(env.cred)

	reg := newACRClient(cfg.RegistryURL, cfg.RegistryAuth, env.acr.username, env.acr.password, "tenant", entra)
	reg.baseURL = env.acr.srv.URL
	ci := newADOClient(cfg.ADOOrg, cfg.ADOProject, cfg.ADOAuth, cfg.ADOPAT, cfg.PipelineSourceBranch, entra)
	ci.baseURL = env.ado.srv.URL

	env.h = newHandler(cfg, reg, ci)
	return env
}

// hookResult is a parsed streaming hook response.
type hookResult struct {
	logs []string
	resp HookResponse
}

func (r hookResult) logText() string { return strings.Join(r.logs, "\n") }

func (e *testEnv) post(t *testing.T, env EventEnvelope) hookResult {
	t.Helper()
	body, _ := json.Marshal(env)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(string(body)))
	e.h.hookHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	return parseStream(t, rr.Body.String())
}

func parseStream(t *testing.T, s string) hookResult {
	t.Helper()
	var res hookResult
	var last string
	for _, line := range strings.Split(s, "\n") {
		if l, ok := strings.CutPrefix(line, "LOG: "); ok {
			res.logs = append(res.logs, l)
			continue
		}
		if strings.TrimSpace(line) != "" {
			last = line
		}
	}
	if err := json.Unmarshal([]byte(last), &res.resp); err != nil {
		t.Fatalf("final line %q is not a HookResponse: %v", last, err)
	}
	return res
}

func envelope(branch string, charts ...ChartRef) EventEnvelope {
	return EventEnvelope{
		APIVersion: "hooks.stackmanager/v1",
		Kind:       "EventEnvelope",
		Event:      "pre-deploy",
		RequestID:  "req-1",
		Instance:   &InstanceRef{ID: "i1", Name: "inst", Namespace: "stack-inst", Branch: branch},
		Charts:     charts,
	}
}

func appChart(name, branch string) ChartRef {
	return ChartRef{
		Name:            name,
		SourceRepoURL:   "https://dev.azure.com/org/proj/_git/" + name,
		BuildPipelineID: "42",
		Branch:          branch,
		ImageTag:        sanitizeImageTag(branch),
	}
}

var errFake = errors.New("fake failure")
