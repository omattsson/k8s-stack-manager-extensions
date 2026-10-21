package main

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/leaderelection"
)

// config holds the settings from the environment.
type config struct {
	// 8-byte fields first (alignment).
	LeaseDuration   time.Duration
	RenewDeadline   time.Duration
	RetryPeriod     time.Duration
	ResyncInterval  time.Duration
	ShutdownDelay   time.Duration
	HostPattern     *regexp.Regexp
	NamespaceLabels labels.Selector
	BypassCIDRs     []netip.Prefix

	ListenAddr        string
	NamespaceSelector string
	InstanceLabel     string
	SecretName        string
	URLTemplate       string
	Secret            string
	SharedUser        string
	SharedPassword    string
	LeaseName         string
	PodName           string
	PodNamespace      string
	PodIP             string
	ListenPort        string

	PasswordLength int
	DefaultEnabled bool
	AllowUnsigned  bool
	LeaderElection bool
}

const defaultHostPattern = `^(?P<instance>[a-z0-9]([a-z0-9-]*[a-z0-9])?)\.`

// loadConfig reads the configuration from getenv.
func loadConfig(getenv func(string) string) (config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	cfg := config{
		ListenAddr:        get("LISTEN_ADDR", ":8080"),
		NamespaceSelector: get("NAMESPACE_SELECTOR", "managed-by=k8s-stack-manager"),
		InstanceLabel:     get("INSTANCE_LABEL", "k8s-stack-manager.io/instance-name"),
		SecretName:        get("SECRET_NAME", "stack-basic-auth"),
		URLTemplate:       get("URL_TEMPLATE", ""),
		Secret:            getenv("STACK_ACCESS_SECRET"),
		LeaseName:         get("LEASE_NAME", "stack-access"),
		PodName:           get("POD_NAME", ""),
		PodNamespace:      get("POD_NAMESPACE", ""),
		PodIP:             get("POD_IP", ""),
		AllowUnsigned:     strings.EqualFold(get("ALLOW_UNSIGNED", ""), "true"),
	}

	var err error
	if cfg.DefaultEnabled, err = parseBool(get("DEFAULT_ENABLED", "true")); err != nil {
		return config{}, fmt.Errorf("DEFAULT_ENABLED: %w", err)
	}
	if cfg.LeaderElection, err = parseBool(get("LEADER_ELECTION_ENABLED", "true")); err != nil {
		return config{}, fmt.Errorf("LEADER_ELECTION_ENABLED: %w", err)
	}
	if cfg.PasswordLength, err = strconv.Atoi(get("PASSWORD_LENGTH", "24")); err != nil || cfg.PasswordLength < 16 || cfg.PasswordLength > 128 {
		return config{}, errors.New("PASSWORD_LENGTH must be a number from 16 to 128")
	}

	durations := []struct {
		key string
		def string
		dst *time.Duration
	}{
		{"LEASE_DURATION", "15s", &cfg.LeaseDuration},
		{"RENEW_DEADLINE", "10s", &cfg.RenewDeadline},
		{"RETRY_PERIOD", "2s", &cfg.RetryPeriod},
		{"RESYNC_INTERVAL", "10m", &cfg.ResyncInterval},
		{"SHUTDOWN_DELAY", "5s", &cfg.ShutdownDelay},
	}
	for _, d := range durations {
		v, perr := time.ParseDuration(get(d.key, d.def))
		if perr != nil || v < 0 {
			return config{}, fmt.Errorf("%s must be a duration such as 10s", d.key)
		}
		*d.dst = v
	}
	if cfg.ResyncInterval < time.Minute {
		return config{}, errors.New("RESYNC_INTERVAL must be at least 1m")
	}

	if cfg.HostPattern, err = regexp.Compile(get("HOST_PATTERN", defaultHostPattern)); err != nil {
		return config{}, fmt.Errorf("HOST_PATTERN: %w", err)
	}
	if cfg.HostPattern.SubexpIndex("instance") < 0 {
		return config{}, errors.New("HOST_PATTERN needs a named group (?P<instance>...)")
	}
	if cfg.NamespaceLabels, err = labels.Parse(cfg.NamespaceSelector); err != nil {
		return config{}, fmt.Errorf("NAMESPACE_SELECTOR: %w", err)
	}
	if cfg.NamespaceLabels.Empty() {
		// An empty selector would match every namespace of the cluster.
		return config{}, errors.New("NAMESPACE_SELECTOR must not be empty")
	}
	if cfg.BypassCIDRs, err = parseCIDRs(getenv("BYPASS_CIDRS")); err != nil {
		return config{}, fmt.Errorf("BYPASS_CIDRS: %w", err)
	}
	if cfg.URLTemplate != "" && !strings.Contains(cfg.URLTemplate, "{instance}") {
		return config{}, errors.New("URL_TEMPLATE must contain {instance}")
	}
	if _, port, perr := splitListenAddr(cfg.ListenAddr); perr != nil {
		return config{}, fmt.Errorf("LISTEN_ADDR: %w", perr)
	} else {
		cfg.ListenPort = port
	}

	// A Secret made from a file often ends with a newline.
	if v := strings.TrimRight(getenv("SHARED_CREDENTIALS"), "\r\n"); v != "" {
		user, pass, ok := strings.Cut(v, ":")
		// Never echo the value: it is a password.
		if !ok || user == "" || len(pass) < 16 {
			return config{}, errors.New("SHARED_CREDENTIALS must be user:password with a password of at least 16 bytes")
		}
		if strings.TrimSpace(user) != user || strings.TrimSpace(pass) != pass {
			return config{}, errors.New("SHARED_CREDENTIALS must not have spaces at the start or end of the user or the password")
		}
		cfg.SharedUser, cfg.SharedPassword = user, pass
	}

	if cfg.Secret == "" && !cfg.AllowUnsigned {
		return config{}, errors.New("STACK_ACCESS_SECRET is not set; set ALLOW_UNSIGNED=true to accept unsigned requests")
	}
	if cfg.LeaderElection {
		if cfg.PodName == "" || cfg.PodNamespace == "" || cfg.PodIP == "" {
			return config{}, errors.New("leader election needs POD_NAME, POD_NAMESPACE and POD_IP (downward API); set LEADER_ELECTION_ENABLED=false for one replica")
		}
		// client-go adds up to 20% jitter to the retry period. The watchdog
		// checks every RETRY_PERIOD/2, so it ends a term at most
		// RENEW_DEADLINE + RETRY_PERIOD/2 after the last renew; that must be
		// before another replica can take the Lease.
		if cfg.RetryPeriod <= 0 || cfg.LeaseDuration <= cfg.RenewDeadline+cfg.RetryPeriod/2 ||
			cfg.RenewDeadline <= time.Duration(leaderelection.JitterFactor*float64(cfg.RetryPeriod)) {
			return config{}, errors.New("timings must be LEASE_DURATION > RENEW_DEADLINE + RETRY_PERIOD/2 and RENEW_DEADLINE > 1.2 x RETRY_PERIOD > 0")
		}
	}
	return cfg, nil
}

// identity is the Lease holder identity: the pod name and the address where
// the other replicas send write actions.
func (c config) identity() string {
	return c.PodName + "@" + c.PodIP
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean", s)
}

func parseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", part)
			}
			part = addr.String() + "/" + strconv.Itoa(addr.BitLen())
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", part)
		}
		if p.Bits() == 0 {
			// A /0 range would turn the password off for everybody.
			return nil, fmt.Errorf("%q matches every address", part)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func splitListenAddr(addr string) (host, port string, err error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", errors.New("must be host:port or :port")
	}
	port = addr[i+1:]
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", "", errors.New("has no valid port")
	}
	return addr[:i], port, nil
}
