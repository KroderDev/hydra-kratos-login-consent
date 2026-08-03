package config

import (
	"testing"
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
}
