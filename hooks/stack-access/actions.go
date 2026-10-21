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
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	signatureHeader = "X-StackManager-Signature"
	// forwardedHeader marks a request that a follower sent to the leader. A
	// follower never forwards such a request again.
	forwardedHeader = "X-Stack-Access-Forwarded"
	maxBodyBytes    = 64 << 10
	maxClockSkew    = 5 * time.Minute
	writeAttempts   = 3
	// The leader answers within writeBudget, before the forward of a
	// follower times out (forwardTimeout), and both stay below the action
	// timeout of k8s-stack-manager (timeout_seconds: 15). Otherwise a rotate
	// could finish after the user got an error, and nobody sees the new
	// password.
	writeBudget    = 8 * time.Second
	forwardTimeout = 12 * time.Second
	// seenTTL is longer than maxClockSkew both ways, so a replay of a signed
	// write request is refused for as long as its timestamp is valid.
	seenTTL = 2*maxClockSkew + time.Minute

	opShow   = "show"
	opRotate = "rotate"
	opSet    = "set"
)

// actionRequest is the part of the k8s-stack-manager ActionRequest that this
// service reads.
type actionRequest struct {
	Timestamp  time.Time      `json:"timestamp"`
	Parameters map[string]any `json:"parameters"`
	Kind       string         `json:"kind"`
	RequestID  string         `json:"request_id"`
	Instance   struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"instance"`
}

// accessResult is the answer of the show and rotate actions.
type accessResult struct {
	URL      string `json:"url,omitempty"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// actions serves POST /actions/{op}.
type actions struct {
	client  kubernetes.Interface
	store   *store
	elector *elector
	metrics *metrics
	forward *http.Client
	now     func() time.Time
	seen    *seenRequests
	cfg     config
}

func newActions(client kubernetes.Interface, st *store, el *elector, cfg config, m *metrics) *actions {
	return &actions{
		client:  client,
		store:   st,
		elector: el,
		metrics: m,
		cfg:     cfg,
		now:     time.Now,
		seen:    newSeenRequests(),
		forward: &http.Client{
			Timeout: forwardTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *actions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	a.serve(rec, r, op)
	label := op
	if op != opShow && op != opRotate && op != opSet {
		// A fixed label: the path is free text, and each new label value
		// would stay in memory.
		label = "unknown"
	}
	a.metrics.actionResult(label, rec.status)
}

func (a *actions) serve(w http.ResponseWriter, r *http.Request, op string) {
	if op != opShow && op != opRotate && op != opSet {
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	if !verifySignature(a.cfg.Secret, a.cfg.AllowUnsigned, body, r.Header.Get(signatureHeader)) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var req actionRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Kind != "ActionRequest" {
		writeError(w, http.StatusBadRequest, "body is not an ActionRequest")
		return
	}
	// The timestamp is in the signed body, so a captured request cannot be
	// sent again later.
	if a.cfg.Secret != "" && req.Timestamp.IsZero() {
		writeError(w, http.StatusUnauthorized, "request has no timestamp")
		return
	}
	if !req.Timestamp.IsZero() && outsideWindow(a.now(), req.Timestamp) {
		writeError(w, http.StatusUnauthorized, "request timestamp is more than 5 minutes from the clock of stack-access")
		return
	}

	if op != opShow && !a.elector.isLeader() {
		a.forwardToLeader(w, r, op, body)
		return
	}

	ns, err := a.store.stackNamespace(req.Instance.Namespace, req.Instance.Name)
	switch {
	case errors.Is(err, errNotSynced):
		writeError(w, http.StatusServiceUnavailable, "stack-access is starting. Try again in a minute.")
		return
	case err != nil:
		writeError(w, http.StatusNotFound, "The stack has no namespace yet. Deploy the stack, then try again.")
		return
	}

	switch op {
	case opShow:
		a.show(w, ns.Name, req.Instance.Name)
	case opRotate:
		a.write(r.Context(), w, req, ns.Name, func(c *credentials) error {
			pw, err := generatePassword(a.cfg.PasswordLength)
			// The user name follows a rename of the stack.
			c.Username = req.Instance.Name
			c.Password = pw
			return err
		}, true)
	case opSet:
		enabled, ok := boolParam(req.Parameters, "enabled")
		if !ok {
			writeError(w, http.StatusBadRequest, "parameter enabled (true or false) is required")
			return
		}
		a.write(r.Context(), w, req, ns.Name, func(c *credentials) error {
			c.Enabled = enabled
			return nil
		}, false)
	}
}

func (a *actions) show(w http.ResponseWriter, namespace, instance string) {
	sec, err := a.store.secret(namespace)
	if err != nil {
		writeError(w, http.StatusNotFound, "The stack has no access secret yet. Try again in a minute.")
		return
	}
	creds, ok := readCredentials(sec)
	if !ok {
		writeError(w, http.StatusConflict, "The access secret of the stack is invalid. Rotate the password to repair it.")
		return
	}
	writeJSON(w, http.StatusOK, a.result(instance, creds))
}

// write changes the access Secret on the leader. It reads the live Secret and
// updates it with that resource version, so a concurrent write fails with a
// conflict instead of being lost; the change is then tried again. A missing
// or invalid Secret gets new credentials. The write stops when the term of
// this replica ends, and it ends within writeBudget.
func (a *actions) write(ctx context.Context, w http.ResponseWriter, req actionRequest, namespace string, change func(*credentials) error, showPassword bool) {
	instance := req.Instance.Name
	term, ok := a.elector.termContext()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "The stack-access leader changed. Try again in a minute.")
		return
	}
	if req.RequestID != "" && !a.seen.add(req.RequestID, a.now()) {
		writeError(w, http.StatusConflict, "This request was already done. Run the action again.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, writeBudget)
	defer cancel()
	stop := context.AfterFunc(term, cancel)
	defer stop()

	secrets := a.client.CoreV1().Secrets(namespace)
	for attempt := 1; ; attempt++ {
		if !a.elector.isLeader() {
			writeError(w, http.StatusServiceUnavailable, "The stack-access leader changed. Try again in a minute.")
			return
		}
		creds, err := a.writeOnce(ctx, secrets, namespace, instance, change)
		if err == nil {
			res := a.result(instance, creds)
			if !showPassword {
				res.Password = ""
			}
			slog.Info("Access secret changed", "namespace", namespace, "instance", instance, "enabled", creds.Enabled, "password_rotated", showPassword)
			writeJSON(w, http.StatusOK, res)
			return
		}
		if (apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err)) && attempt < writeAttempts && ctx.Err() == nil {
			continue
		}
		slog.Warn("Cannot change the access secret", "namespace", namespace, "error", err)
		writeError(w, http.StatusInternalServerError, "Cannot change the access secret. Try again.")
		return
	}
}

type secretClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	Create(ctx context.Context, s *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	Update(ctx context.Context, s *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
}

func (a *actions) writeOnce(ctx context.Context, secrets secretClient, namespace, instance string, change func(*credentials) error) (credentials, error) {
	sec, err := secrets.Get(ctx, a.cfg.SecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		sec, err = newAccessSecret(a.cfg, namespace, instance)
		if err != nil {
			return credentials{}, err
		}
		creds, _ := readCredentials(sec)
		if err := change(&creds); err != nil {
			return credentials{}, err
		}
		applyCredentials(sec, creds)
		_, err = secrets.Create(ctx, sec, metav1.CreateOptions{})
		return creds, err
	}
	if err != nil {
		return credentials{}, err
	}
	creds, ok := readCredentials(sec)
	if !ok {
		pw, perr := generatePassword(a.cfg.PasswordLength)
		if perr != nil {
			return credentials{}, perr
		}
		creds = credentials{Username: instance, Password: pw, Enabled: a.cfg.DefaultEnabled}
	}
	if err := change(&creds); err != nil {
		return credentials{}, err
	}
	sec = sec.DeepCopy()
	applyCredentials(sec, creds)
	_, err = secrets.Update(ctx, sec, metav1.UpdateOptions{})
	return creds, err
}

func applyCredentials(sec *corev1.Secret, c credentials) {
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[keyUsername] = []byte(c.Username)
	sec.Data[keyPassword] = []byte(c.Password)
	sec.Data[keyEnabled] = []byte(strconv.FormatBool(c.Enabled))
}

func (a *actions) result(instance string, c credentials) accessResult {
	res := accessResult{Username: c.Username, Password: c.Password, Enabled: c.Enabled}
	if a.cfg.URLTemplate != "" {
		res.URL = strings.ReplaceAll(a.cfg.URLTemplate, "{instance}", instance)
	}
	return res
}

// forwardToLeader sends a write action, unchanged and still signed, to the
// leader and copies its answer.
func (a *actions) forwardToLeader(w http.ResponseWriter, r *http.Request, op string, body []byte) {
	unavailable := "No stack-access leader is ready. Try again in a minute."
	if r.Header.Get(forwardedHeader) != "" {
		// The leader changed while the request was on its way.
		writeError(w, http.StatusServiceUnavailable, unavailable)
		return
	}
	addr, ok := a.elector.leaderAddr()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, unavailable)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://"+addr+"/actions/"+op, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, unavailable)
		return
	}
	for _, h := range []string{"Content-Type", signatureHeader, "X-StackManager-Event", "X-StackManager-Request-Id", "Traceparent"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set(forwardedHeader, a.cfg.identity())
	resp, err := a.forward.Do(req)
	if err != nil {
		slog.Warn("Cannot forward the action to the leader", "leader", addr, "action", op, "error", err)
		writeError(w, http.StatusServiceUnavailable, unavailable)
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

// boolParam reads a bool parameter. It also accepts "true" and "false" as
// strings, for API callers that send strings.
func boolParam(params map[string]any, name string) (value, ok bool) {
	switch v := params[name].(type) {
	case bool:
		return v, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		return b, err == nil
	}
	return false, false
}

// verifySignature checks the HMAC signature of the body. Without a secret it
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

func outsideWindow(now, t time.Time) bool {
	d := now.Sub(t)
	return d > maxClockSkew || d < -maxClockSkew
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("Cannot write the response", "error", err)
	}
}

// writeError writes {"error": msg}. k8s-stack-manager stores the message of
// an answer of 400 or higher, so msg must never hold a password.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// String is for log and test output only.
func (r accessResult) String() string {
	return fmt.Sprintf("{url:%s username:%s enabled:%t}", r.URL, r.Username, r.Enabled)
}

// seenRequests remembers the request IDs of write actions, so a replay of a
// signed request within its timestamp window is refused. Only the leader
// writes, so one replica holds the list; a new leader starts empty.
type seenRequests struct {
	mu  sync.Mutex
	ids map[string]time.Time
}

func newSeenRequests() *seenRequests {
	return &seenRequests{ids: map[string]time.Time{}}
}

// add records id. It returns false when id was seen within seenTTL.
func (s *seenRequests) add(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.ids {
		if now.Sub(t) > seenTTL {
			delete(s.ids, k)
		}
	}
	if _, ok := s.ids[id]; ok {
		return false
	}
	s.ids[id] = now
	return true
}
