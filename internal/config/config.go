// Package config loads deployment configuration from environment variables.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	coreconfig "github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
)

// Client is an alias for the core configuration client contract.
type Client = coreconfig.Client

// Config is an alias for the validated core configuration.
type Config = coreconfig.Config

// PolicyBackend is an alias for the validated policy backend contract.
type PolicyBackend = coreconfig.PolicyBackend

const (
	PolicyBackendStatic = coreconfig.PolicyBackendStatic
	PolicyBackendHTTP   = coreconfig.PolicyBackendHTTP
)

// Load reads and validates provider configuration from environment variables.
func Load() (coreconfig.Config, error) {
	providerURL, err := requiredURL("PUBLIC_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}
	externalUIURL, err := requiredURL("EXTERNAL_UI_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}
	hydraAdminURL, err := requiredURL("HYDRA_ADMIN_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}
	hydraPublicURL, err := requiredURL("HYDRA_PUBLIC_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}
	kratosPublicURL, err := requiredURL("KRATOS_PUBLIC_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}

	ttl := coreconfig.DefaultTransactionTTL
	if value := strings.TrimSpace(os.Getenv("TRANSACTION_TTL")); value != "" {
		ttl, err = time.ParseDuration(value)
		if err != nil {
			return coreconfig.Config{}, fmt.Errorf("parse transaction_ttl: %w", err)
		}
	}
	maxPendingTransactions := coreconfig.DefaultMaxPendingTransactions
	if value := strings.TrimSpace(os.Getenv("MAX_PENDING_TRANSACTIONS")); value != "" {
		maxPendingTransactions, err = strconv.Atoi(value)
		if err != nil {
			return coreconfig.Config{}, fmt.Errorf("parse max_pending_transactions: %w", err)
		}
	}
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	if environment == "" {
		environment = "development"
	}
	policyBackend := strings.ToLower(strings.TrimSpace(os.Getenv("POLICY_BACKEND")))
	if policyBackend == "" {
		policyBackend = string(coreconfig.PolicyBackendStatic)
	}
	policyURL, err := optionalURL("POLICY_URL")
	if err != nil {
		return coreconfig.Config{}, err
	}
	identityClaimMappings, err := identity.ParseJSON(
		os.Getenv("OIDC_IDENTITY_CLAIM_MAPPINGS"),
		(coreconfig.Config{Environment: environment}).IsSecureEnvironment(),
	)
	if err != nil {
		return coreconfig.Config{}, fmt.Errorf("parse oidc_identity_claim_mappings: %w", err)
	}

	clients := map[string]coreconfig.Client{}
	if raw := strings.TrimSpace(os.Getenv("ALLOWED_CLIENTS")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &clients); err != nil {
			return coreconfig.Config{}, fmt.Errorf("parse allowed_clients: %w", err)
		}
	}
	for id, client := range clients {
		if client.ID == "" {
			client.ID = id
			clients[id] = client
		}
	}

	cfg := coreconfig.Config{
		ListenAddress:             envOrDefault("LISTEN_ADDR", ":8080"),
		Environment:               environment,
		ProviderURL:               providerURL,
		ExternalUIURL:             externalUIURL,
		HydraAdminURL:             hydraAdminURL,
		HydraPublicURL:            hydraPublicURL,
		KratosPublicURL:           kratosPublicURL,
		KratosSessionCookie:       envOrDefault("KRATOS_SESSION_COOKIE", "ory_kratos_session"),
		RequiredAAL:               envOrDefault("REQUIRED_AAL", "aal2"),
		TransactionTTL:            ttl,
		MaxPendingTransactions:    maxPendingTransactions,
		Clients:                   clients,
		PolicyBackend:             coreconfig.PolicyBackend(policyBackend),
		PolicyURL:                 policyURL,
		OIDCIdentityClaimMappings: identityClaimMappings,
	}
	if err := cfg.Validate(); err != nil {
		return coreconfig.Config{}, err
	}
	return cfg, nil
}

func requiredURL(name string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https", name)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an origin URL without credentials or fragments", name)
	}
	return parsed, nil
}

func optionalURL(name string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https", name)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials or fragments", name)
	}
	return parsed, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
