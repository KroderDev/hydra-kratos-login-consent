package config

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func TestConfigExternalRedirect(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)

	redirect, err := cfg.ExternalRedirect(domain.FlowLogin, "opaque-handle", "csrf-token")
	if err != nil {
		t.Fatalf("ExternalRedirect: %v", err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := parsed.Query().Get("flow"); got != "login" {
		t.Fatalf("flow = %q, want login", got)
	}
	if got := parsed.Query().Get("transaction"); got != "opaque-handle" {
		t.Fatalf("transaction = %q, want opaque-handle", got)
	}
	if got := parsed.Query().Get("csrf"); got != "csrf-token" {
		t.Fatalf("csrf = %q, want csrf-token", got)
	}
	if got := parsed.Query().Get("return_to"); got != "https://provider.example/login/callback" {
		t.Fatalf("return_to = %q, want login callback", got)
	}

	if _, err := cfg.ExternalRedirect(domain.FlowLogin, "", "csrf-token"); !errors.Is(err, domain.ErrInvalidTransaction) {
		t.Fatalf("empty transaction error = %v, want invalid transaction", err)
	}
}

func TestConfigExternalConsentRedirect(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	redirect, err := cfg.ExternalConsentRedirect("opaque-handle", "csrf-token", "Example Client", []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("ExternalConsentRedirect: %v", err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := parsed.Query().Get("client_name"); got != "Example Client" {
		t.Fatalf("client_name = %q, want Example Client", got)
	}
	if got := parsed.Query().Get("scope"); got != "openid profile" {
		t.Fatalf("scope = %q, want openid profile", got)
	}
}

func TestConfigOriginAllowed(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "exact origin", origin: "https://ui.example", want: true},
		{name: "path is rejected", origin: "https://ui.example/login", want: false},
		{name: "query is rejected", origin: "https://ui.example?x=1", want: false},
		{name: "wrong host is rejected", origin: "https://evil.example", want: false},
		{name: "wrong scheme is rejected", origin: "http://ui.example", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cfg.OriginAllowed(tt.origin); got != tt.want {
				t.Fatalf("OriginAllowed(%q) = %t, want %t", tt.origin, got, tt.want)
			}
		})
	}
}

func TestConfigValidateRejectsUnsafeClientURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
	}{
		{name: "relative redirect", uri: "/callback"},
		{name: "fragment redirect", uri: "https://client.example/callback#fragment"},
		{name: "non-http scheme", uri: "ftp://client.example/callback"},
		{name: "userinfo", uri: "https://user@client.example/callback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			cfg.Clients["example-client"] = Client{
				ID:                  "example-client",
				AllowedRedirectURIs: []string{tt.uri},
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate returned nil for unsafe client URL")
			}
		})
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	parse := func(raw string) *url.URL {
		value, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URL: %v", err)
		}
		return value
	}
	return Config{
		ListenAddress:       ":8080",
		ProviderURL:         parse("https://provider.example"),
		ExternalUIURL:       parse("https://ui.example/login"),
		HydraAdminURL:       parse("https://hydra.example"),
		HydraPublicURL:      parse("https://hydra.example"),
		KratosPublicURL:     parse("https://kratos.example"),
		KratosSessionCookie: "ory_kratos_session",
		RequiredAAL:         "aal2",
		TransactionTTL:      time.Minute,
		Clients: map[string]Client{
			"example-client": {
				ID:                  "example-client",
				AllowedRedirectURIs: []string{"https://client.example/callback"},
			},
		},
	}
}
