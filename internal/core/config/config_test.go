package config

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
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
	returnTo := parsed.Query().Get("return_to")
	callback, err := url.Parse(returnTo)
	if err != nil {
		t.Fatalf("parse return_to: %v", err)
	}
	if got := callback.Path; got != "/login/callback" {
		t.Fatalf("return_to path = %q, want /login/callback", got)
	}
	if got := callback.Query().Get("csrf"); got != "csrf-token" {
		t.Fatalf("return_to csrf = %q, want csrf-token", got)
	}
	if got := callback.Query().Get("transaction"); got != "opaque-handle" {
		t.Fatalf("return_to transaction = %q, want opaque-handle", got)
	}
	if got := callback.Query().Get("flow"); got != "login" {
		t.Fatalf("return_to flow = %q, want login", got)
	}
	if strings.Contains(parsed.RawQuery, "%2526") {
		t.Fatal("return_to was double-encoded")
	}
	if !strings.Contains(parsed.RawQuery, "%26transaction%3D") || !strings.Contains(parsed.RawQuery, "%26flow%3D") {
		t.Fatalf("return_to nested query was not encoded in the outer URL: %q", parsed.RawQuery)
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

func TestConfigValidateRequiresHTTPSOutsideDevelopment(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.Environment = "production"
	cfg.ProviderURL, _ = url.Parse("http://provider.example")
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted an HTTP provider URL in production")
	}
}

func TestConfigValidateAllowsLoopbackHTTPClientURLsOutsideDevelopment(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.Environment = "production"
	client := cfg.Clients["example-client"]
	client.AllowedRedirectURIs = []string{"http://localhost:3000/callback"}
	client.AllowedPostLogoutRedirects = []string{"http://[::1]:3000/"}
	cfg.Clients["example-client"] = client

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected loopback HTTP client URLs: %v", err)
	}
}

func TestConfigValidateRejectsNonLoopbackHTTPClientURLsOutsideDevelopment(t *testing.T) {
	t.Parallel()

	for _, uri := range []string{
		"http://client.example/callback",
		"http://127.0.0.2:3000/callback",
		"http://localhost.example/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			cfg.Environment = "production"
			client := cfg.Clients["example-client"]
			client.AllowedRedirectURIs = []string{uri}
			cfg.Clients["example-client"] = client

			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted a non-loopback HTTP client URL")
			}
		})
	}
}

func TestConfigValidateRejectsLongTransactionTTL(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.TransactionTTL = MaxTransactionTTL + time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a transaction TTL above the maximum")
	}
}

func TestConfigEffectiveMaxPendingTransactionsUsesBoundedDefault(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	if got := cfg.EffectiveMaxPendingTransactions(); got != DefaultMaxPendingTransactions {
		t.Fatalf("default max pending = %d, want %d", got, DefaultMaxPendingTransactions)
	}
	cfg.MaxPendingTransactions = 42
	if got := cfg.EffectiveMaxPendingTransactions(); got != 42 {
		t.Fatalf("configured max pending = %d, want 42", got)
	}
}

func TestConfigExternalUIOriginAndRedirectValidation(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	if got := cfg.ExternalUIOrigin(); got != "https://ui.example" {
		t.Fatalf("external UI origin = %q, want https://ui.example", got)
	}
	for _, flow := range []domain.Flow{domain.FlowLogin, domain.FlowConsent, domain.FlowLogout, domain.Flow("unknown")} {
		if got := cfg.CallbackURL(flow); got == "" {
			t.Fatalf("callback URL for %q is empty", flow)
		}
	}
	for name, args := range map[string][2]string{
		"empty csrf":        {"opaque", ""},
		"empty transaction": {"", "csrf"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := cfg.ExternalRedirect(domain.FlowLogin, args[0], args[1]); !errors.Is(err, domain.ErrInvalidTransaction) {
				t.Fatalf("error = %v, want invalid transaction", err)
			}
		})
	}
}

func TestConfigValidateRejectsInvalidCoreSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing listen address", mutate: func(cfg *Config) { cfg.ListenAddress = "" }},
		{name: "missing session cookie", mutate: func(cfg *Config) { cfg.KratosSessionCookie = "" }},
		{name: "unsupported assurance", mutate: func(cfg *Config) { cfg.RequiredAAL = "aal0" }},
		{name: "zero transaction ttl", mutate: func(cfg *Config) { cfg.TransactionTTL = 0 }},
		{name: "negative pending limit", mutate: func(cfg *Config) { cfg.MaxPendingTransactions = -1 }},
		{name: "client key mismatch", mutate: func(cfg *Config) {
			cfg.Clients["wrong-key"] = cfg.Clients["example-client"]
			delete(cfg.Clients, "example-client")
		}},
		{name: "duplicate audiences", mutate: func(cfg *Config) {
			client := cfg.Clients["example-client"]
			client.AllowedAudiences = []string{"api", "api"}
			cfg.Clients["example-client"] = client
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate returned nil for invalid configuration")
			}
		})
	}
}

func TestConfigValidatePolicyBackend(t *testing.T) {
	t.Parallel()

	parse := func(raw string) *url.URL {
		value, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse policy URL: %v", err)
		}
		return value
	}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "defaults to static", mutate: func(_ *Config) {}},
		{name: "rejects unknown backend", mutate: func(cfg *Config) { cfg.PolicyBackend = "database" }, wantErr: true},
		{name: "requires http URL", mutate: func(cfg *Config) { cfg.PolicyBackend = PolicyBackendHTTP }, wantErr: true},
		{name: "requires https outside development", mutate: func(cfg *Config) {
			cfg.Environment = "production"
			cfg.PolicyBackend = PolicyBackendHTTP
			cfg.PolicyURL = parse("http://policy.example/v1/authorize")
		}, wantErr: true},
		{name: "rejects query", mutate: func(cfg *Config) {
			cfg.PolicyBackend = PolicyBackendHTTP
			cfg.PolicyURL = parse("https://policy.example/v1/authorize?tenant=one")
		}, wantErr: true},
		{name: "accepts http backend", mutate: func(cfg *Config) {
			cfg.PolicyBackend = PolicyBackendHTTP
			cfg.PolicyURL = parse("http://policy.example/v1/authorize")
		}, wantErr: false},
		{name: "accepts secure production backend", mutate: func(cfg *Config) {
			cfg.Environment = "production"
			cfg.PolicyBackend = PolicyBackendHTTP
			cfg.PolicyURL = parse("https://policy.example/v1/authorize")
		}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			tt.mutate(&cfg)
			if err := cfg.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateClaimAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  map[string][]string
		wantErr bool
	}{
		{name: "unallowlisted scope", claims: map[string][]string{"role": {"admin"}}, wantErr: true},
		{name: "blank claim name", claims: map[string][]string{"": nil}, wantErr: true},
		{name: "reserved protocol claim", claims: map[string][]string{"sub": nil}, wantErr: true},
		{name: "duplicate required scopes", claims: map[string][]string{"role": {"openid", "openid"}}, wantErr: true},
		{name: "allowed scope", claims: map[string][]string{"role": {"openid"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			client := cfg.Clients["example-client"]
			client.AllowedScopes = []string{"openid"}
			client.AllowedIDTokenClaims = tt.claims
			cfg.Clients["example-client"] = client
			if err := cfg.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateRejectsOIDCIdentityMappingErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "invalid pointer",
			mutate: func(cfg *Config) {
				cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{"role": {Source: "traits/role", Type: "string"}}
			},
		},
		{
			name: "reserved claim",
			mutate: func(cfg *Config) {
				cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{"sub": {Source: "/traits/id", Type: "string"}}
			},
		},
		{
			name: "unsupported type",
			mutate: func(cfg *Config) {
				cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{"role": {Source: "/traits/role", Type: "binary"}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig(t)
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate returned nil for invalid identity claim mappings")
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
