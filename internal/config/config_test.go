package config

import (
	"testing"
	"time"
)

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadDefaultsAndClientIDs(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ALLOWED_CLIENTS", `{"example-client":{"allowed_redirect_uris":["https://client.example/callback"]}}`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddress != ":8080" {
		t.Fatalf("ListenAddress = %q, want :8080", cfg.ListenAddress)
	}
	if cfg.RequiredAAL != "aal2" {
		t.Fatalf("RequiredAAL = %q, want aal2", cfg.RequiredAAL)
	}
	if cfg.PolicyBackend != PolicyBackendStatic || cfg.PolicyURL != nil {
		t.Fatalf("policy config = %#v, want static defaults", cfg)
	}
	client, ok := cfg.Clients["example-client"]
	if !ok || client.ID != "example-client" {
		t.Fatalf("client = %#v, want client ID populated from map key", client)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadRejectsInvalidTransactionTTL(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("TRANSACTION_TTL", "not-a-duration")

	if _, err := Load(); err == nil {
		t.Fatal("Load returned nil for invalid transaction TTL")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadRequiresURLs(t *testing.T) {
	t.Setenv("PUBLIC_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load returned nil without PUBLIC_URL")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadParsesConfiguredValues(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("LISTEN_ADDR", "127.0.0.1:9090")
	t.Setenv("ENVIRONMENT", " TEST ")
	t.Setenv("TRANSACTION_TTL", "30s")
	t.Setenv("MAX_PENDING_TRANSACTIONS", "17")
	t.Setenv("REQUIRED_AAL", "aal1")
	t.Setenv("KRATOS_SESSION_COOKIE", "custom_session")
	t.Setenv("ALLOWED_CLIENTS", `{"client":{"allowed_redirect_uris":["https://client.example/callback"]}}`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" || cfg.Environment != "test" || cfg.TransactionTTL != 30*time.Second || cfg.MaxPendingTransactions != 17 || cfg.RequiredAAL != "aal1" || cfg.KratosSessionCookie != "custom_session" {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadParsesHTTPPolicyConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("POLICY_BACKEND", " HTTP ")
	t.Setenv("POLICY_URL", "http://policy.example/v1/authorize")
	t.Setenv("POLICY_AUTH_TOKEN", " policy-secret ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PolicyBackend != PolicyBackendHTTP || cfg.PolicyURL == nil || cfg.PolicyURL.String() != "http://policy.example/v1/authorize" {
		t.Fatalf("policy config = %#v", cfg)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadRequiresHTTPPolicyURL(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("POLICY_BACKEND", "http")

	if _, err := Load(); err == nil {
		t.Fatal("Load accepted HTTP policy backend without POLICY_URL")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadRejectsUnsupportedPolicyBackend(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("POLICY_BACKEND", "database")

	if _, err := Load(); err == nil {
		t.Fatal("Load accepted an unsupported policy backend")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestLoadRejectsMalformedConfiguredValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "pending transactions", key: "MAX_PENDING_TRANSACTIONS", value: "not-an-int"},
		{name: "allowed clients", key: "ALLOWED_CLIENTS", value: "{"},
		{name: "unsupported URL scheme", key: "PUBLIC_URL", value: "ftp://provider.example"},
		{name: "malformed policy URL", key: "POLICY_URL", value: "%gh"},
		{name: "unsupported policy URL scheme", key: "POLICY_URL", value: "ftp://policy.example/v1/authorize"},
		//nolint:gosec // Credential-shaped input is intentional malformed configuration coverage.
		{name: "policy URL credentials", key: "POLICY_URL", value: "https://user:" + "pw" + "@policy.example/v1/authorize"},
		{name: "policy URL fragment", key: "POLICY_URL", value: "https://policy.example/v1/authorize#fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(tt.key, tt.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load accepted malformed configuration")
			}
		})
	}
}

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PUBLIC_URL", "https://provider.example")
	t.Setenv("EXTERNAL_UI_URL", "https://ui.example/login")
	t.Setenv("HYDRA_ADMIN_URL", "https://hydra.example")
	t.Setenv("HYDRA_PUBLIC_URL", "https://hydra.example")
	t.Setenv("KRATOS_PUBLIC_URL", "https://kratos.example")
	t.Setenv("ALLOWED_CLIENTS", "")
	t.Setenv("TRANSACTION_TTL", "")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("REQUIRED_AAL", "")
	t.Setenv("KRATOS_SESSION_COOKIE", "")
	t.Setenv("ENVIRONMENT", "")
	t.Setenv("POLICY_BACKEND", "")
	t.Setenv("POLICY_URL", "")
	t.Setenv("POLICY_AUTH_TOKEN", "")
}
