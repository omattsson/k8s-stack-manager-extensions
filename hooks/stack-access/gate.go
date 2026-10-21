package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Results of an auth check (metric label and log value).
const (
	resultBypass   = "bypass"
	resultOK       = "ok"
	resultDisabled = "disabled"
	resultDenied   = "denied"
	resultNotReady = "not_ready"
)

// gate answers the Traefik forwardAuth requests.
type gate struct {
	store   *store
	metrics *metrics
	cfg     config
}

// ServeHTTP answers 200 to let the request pass, 401 with a basic auth
// challenge, or 503 when the cache is not synced yet.
func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := forwardedHost(r)
	ip, ipOK := clientIP(r)

	if ipOK && g.bypassed(ip) {
		g.allow(w, resultBypass)
		return
	}

	instance := g.instanceOf(host)
	if instance == "" {
		g.deny(w, r, host, ip, "", "host does not name a stack")
		return
	}

	ns, err := g.store.namespaceForInstance(instance)
	if errors.Is(err, errNotSynced) {
		g.metrics.authResult(resultNotReady)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		g.deny(w, r, host, ip, instance, err.Error())
		return
	}
	sec, err := g.store.secret(ns.Name)
	if err != nil {
		g.deny(w, r, host, ip, instance, err.Error())
		return
	}
	creds, ok := readCredentials(sec)
	if !ok {
		g.deny(w, r, host, ip, instance, "access secret is invalid")
		return
	}
	if !creds.Enabled {
		g.allow(w, resultDisabled)
		return
	}
	user, pass, hasAuth := r.BasicAuth()
	if !hasAuth {
		g.deny(w, r, host, ip, instance, "no credentials")
		return
	}
	if !equalSecret(user, creds.Username) || !equalSecret(pass, creds.Password) {
		g.deny(w, r, host, ip, instance, "wrong credentials")
		return
	}
	g.allow(w, resultOK)
}

func (g *gate) bypassed(ip netip.Addr) bool {
	for _, p := range g.cfg.BypassCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// instanceOf returns the stack name in host, or "".
func (g *gate) instanceOf(host string) string {
	if host == "" {
		return ""
	}
	m := g.cfg.HostPattern.FindStringSubmatch(host)
	if m == nil {
		return ""
	}
	return m[g.cfg.HostPattern.SubexpIndex("instance")]
}

func (g *gate) allow(w http.ResponseWriter, result string) {
	g.metrics.authResult(result)
	w.WriteHeader(http.StatusOK)
}

func (g *gate) deny(w http.ResponseWriter, r *http.Request, host string, ip netip.Addr, instance, reason string) {
	g.metrics.authResult(resultDenied)
	// A first request without credentials is the normal start of a browser
	// login, so it logs at debug level.
	level := slog.LevelInfo
	if reason == "no credentials" {
		level = slog.LevelDebug
	}
	slog.Log(r.Context(), level, "Access denied",
		"host", host, "path", forwardedPath(r), "client_ip", ipString(ip), "reason", reason)
	realm := "stack"
	if instance != "" {
		realm = instance
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// equalSecret compares in constant time. Hashing first hides the length.
func equalSecret(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// clientIP returns the right-most X-Forwarded-For entry. Traefik writes it
// from the TCP peer when the middleware has trustForwardHeader: false, so a
// client cannot choose it. Without the header the IP is unknown, and no
// bypass applies.
func clientIP(r *http.Request) (netip.Addr, bool) {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return netip.Addr{}, false
	}
	parts := strings.Split(values[len(values)-1], ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	addr, err := netip.ParseAddr(last)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// forwardedHost returns the lower-case host of the original request, without
// a port.
func forwardedHost(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// forwardedPath returns the path of the original request without the query,
// which can hold tokens.
func forwardedPath(r *http.Request) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	if len(uri) > 200 {
		uri = uri[:200]
	}
	return uri
}

func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
