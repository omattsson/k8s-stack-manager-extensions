package main

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, c config)
	}{
		{
			name: "defaults",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false"},
			check: func(t *testing.T, c config) {
				if c.SecretName != "stack-basic-auth" || c.InstanceLabel != "k8s-stack-manager.io/instance-name" {
					t.Errorf("unexpected defaults: %+v", c)
				}
				if !c.DefaultEnabled || c.PasswordLength != 24 || c.ListenPort != "8080" {
					t.Errorf("unexpected defaults: enabled=%v len=%d port=%s", c.DefaultEnabled, c.PasswordLength, c.ListenPort)
				}
				if len(c.BypassCIDRs) != 0 {
					t.Errorf("bypass should be empty, got %v", c.BypassCIDRs)
				}
			},
		},
		{
			name:    "missing hmac secret",
			env:     map[string]string{"LEADER_ELECTION_ENABLED": "false"},
			wantErr: "STACK_ACCESS_SECRET",
		},
		{
			name: "unsigned allowed",
			env:  map[string]string{"ALLOW_UNSIGNED": "true", "LEADER_ELECTION_ENABLED": "false"},
		},
		{
			name:    "leader election needs pod info",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s"},
			wantErr: "POD_NAME",
		},
		{
			name: "leader election with pod info",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "POD_NAME": "p-1", "POD_NAMESPACE": "extensions", "POD_IP": "10.0.0.5"},
			check: func(t *testing.T, c config) {
				if c.identity() != "p-1@10.0.0.5" {
					t.Errorf("identity = %q", c.identity())
				}
			},
		},
		{
			name:    "bad timings",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "POD_NAME": "p", "POD_NAMESPACE": "n", "POD_IP": "10.0.0.5", "LEASE_DURATION": "5s", "RENEW_DEADLINE": "10s"},
			wantErr: "LEASE_DURATION",
		},
		{
			name: "bypass single IP and range",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "BYPASS_CIDRS": "198.51.100.7, 203.0.113.0/24,2001:db8::/32"},
			check: func(t *testing.T, c config) {
				got := []string{}
				for _, p := range c.BypassCIDRs {
					got = append(got, p.String())
				}
				if strings.Join(got, ",") != "198.51.100.7/32,203.0.113.0/24,2001:db8::/32" {
					t.Errorf("bypass = %v", got)
				}
			},
		},
		{
			name:    "bypass everything is refused",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "BYPASS_CIDRS": "0.0.0.0/0"},
			wantErr: "every address",
		},
		{
			name:    "bypass not an address",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "BYPASS_CIDRS": "office"},
			wantErr: "BYPASS_CIDRS",
		},
		{
			name:    "host pattern without group",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "HOST_PATTERN": `^([a-z]+)\.`},
			wantErr: "named group",
		},
		{
			name:    "url template without placeholder",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "URL_TEMPLATE": "https://example.com"},
			wantErr: "{instance}",
		},
		{
			name:    "short password",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "PASSWORD_LENGTH": "8"},
			wantErr: "PASSWORD_LENGTH",
		},
		{
			name:    "bad listen address",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "LISTEN_ADDR": "8080"},
			wantErr: "LISTEN_ADDR",
		},
		{
			name: "shared credentials",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": "ci:shared-password-1234:with-colon"},
			check: func(t *testing.T, c config) {
				if c.SharedUser != "ci" || c.SharedPassword != "shared-password-1234:with-colon" {
					t.Errorf("shared = %q / %q", c.SharedUser, c.SharedPassword)
				}
			},
		},
		{
			name:    "shared credentials without a colon",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": "shared-password-12345678"},
			wantErr: "SHARED_CREDENTIALS",
		},
		{
			name:    "shared credentials with a short password",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": "ci:123456789012345"},
			wantErr: "at least 16",
		},
		{
			name: "shared credentials with exactly 16 bytes and a trailing newline",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": "ci:1234567890123456\n"},
			check: func(t *testing.T, c config) {
				if c.SharedPassword != "1234567890123456" {
					t.Errorf("password = %q", c.SharedPassword)
				}
			},
		},
		{
			name:    "shared credentials with a space at the end",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": "ci:1234567890123456 "},
			wantErr: "spaces",
		},
		{
			name:    "shared credentials without a user",
			env:     map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "SHARED_CREDENTIALS": " :shared-password-1234"},
			wantErr: "SHARED_CREDENTIALS",
		},
		{
			name: "default disabled",
			env:  map[string]string{"STACK_ACCESS_SECRET": "s", "LEADER_ELECTION_ENABLED": "false", "DEFAULT_ENABLED": "false"},
			check: func(t *testing.T, c config) {
				if c.DefaultEnabled {
					t.Error("DefaultEnabled should be false")
				}
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := loadConfig(func(k string) string { return tt.env[k] })
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				if v := tt.env["SHARED_CREDENTIALS"]; v != "" && strings.Contains(err.Error(), v) {
					t.Fatal("the error holds the shared credentials")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := generatePassword(24)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 24 {
			t.Fatalf("len = %d", len(pw))
		}
		for _, r := range pw {
			if !strings.ContainsRune(passwordAlphabet, r) {
				t.Fatalf("character %q is not in the alphabet", r)
			}
		}
		if seen[pw] {
			t.Fatal("duplicate password")
		}
		seen[pw] = true
	}
	if _, err := generatePassword(0); err == nil {
		t.Fatal("length 0 should fail")
	}
}
