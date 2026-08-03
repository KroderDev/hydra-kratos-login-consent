// Package config contains validated configuration consumed by the application core.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

// Client contains deployment-owned allowlists for one OAuth client.
type Client struct {
	ID                         string              `json:"id,omitempty"`
	AllowedRedirectURIs        []string            `json:"allowed_redirect_uris"`
	AllowedPostLogoutRedirects []string            `json:"allowed_post_logout_redirect_uris"`
	AllowedScopes              []string            `json:"allowed_scopes"`
	SkipConsent                bool                `json:"skip_consent"`
	AllowedIDTokenClaims       map[string][]string `json:"allowed_id_token_claims"`
	AllowedAccessTokenClaims   map[string][]string `json:"allowed_access_token_claims"`
}

// Config contains validated provider configuration.
type Config struct {
	ListenAddress       string
	ProviderURL         *url.URL
	ExternalUIURL       *url.URL
	HydraAdminURL       *url.URL
	HydraPublicURL      *url.URL
	KratosPublicURL     *url.URL
	KratosSessionCookie string
	RequiredAAL         string
	TransactionTTL      time.Duration
	Clients             map[string]Client
}

// Validate rejects unsafe or incomplete provider configuration.
func (c Config) Validate() error {
	if c.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	if err := validateURL(c.ProviderURL, "provider URL"); err != nil {
		return err
	}
	if err := validateURL(c.ExternalUIURL, "external UI URL"); err != nil {
		return err
	}
	if err := validateURL(c.HydraAdminURL, "Hydra admin URL"); err != nil {
		return err
	}
	if err := validateURL(c.HydraPublicURL, "Hydra public URL"); err != nil {
		return err
	}
	if err := validateURL(c.KratosPublicURL, "Kratos public URL"); err != nil {
		return err
	}
	if c.KratosSessionCookie == "" {
		return fmt.Errorf("kratos session cookie is required")
	}
	if c.RequiredAAL != "" && !domain.AALAtLeast(c.RequiredAAL, c.RequiredAAL) {
		return fmt.Errorf("unsupported required aal %q", c.RequiredAAL)
	}
	if c.TransactionTTL <= 0 {
		return fmt.Errorf("transaction TTL must be positive")
	}
	for id, client := range c.Clients {
		if client.ID != id {
			return fmt.Errorf("client map key %q does not match client id %q", id, client.ID)
		}
		if len(client.AllowedRedirectURIs) == 0 {
			return fmt.Errorf("client %q has no allowed redirect uris", id)
		}
		for _, value := range append(append([]string{}, client.AllowedRedirectURIs...), client.AllowedPostLogoutRedirects...) {
			if err := validateAbsoluteURL(value); err != nil {
				return fmt.Errorf("client %q: %w", id, err)
			}
		}
	}
	return nil
}

// Client returns the configured client policy for id.
func (c Config) Client(id string) (Client, bool) {
	client, ok := c.Clients[id]
	return client, ok
}

// ExternalRedirect builds a fixed-origin external UI handoff URL.
func (c Config) ExternalRedirect(flow domain.Flow, transaction, csrfToken string) (string, error) {
	if transaction == "" || csrfToken == "" {
		return "", domain.ErrInvalidTransaction
	}
	redirect := *c.ExternalUIURL
	query := redirect.Query()
	query.Set("flow", string(flow))
	query.Set("transaction", transaction)
	query.Set("csrf", csrfToken)
	query.Set("return_to", c.CallbackURL(flow))
	redirect.RawQuery = query.Encode()
	return redirect.String(), nil
}

// ExternalConsentRedirect adds safe consent display data to an external UI handoff.
func (c Config) ExternalConsentRedirect(transaction, csrfToken, clientName string, scopes []string) (string, error) {
	redirect, err := c.ExternalRedirect(domain.FlowConsent, transaction, csrfToken)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("client_name", clientName)
	query.Set("scope", strings.Join(scopes, " "))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// CallbackURL returns the provider callback for a configured flow.
func (c Config) CallbackURL(flow domain.Flow) string {
	path := "/login/callback"
	if flow == domain.FlowConsent {
		path = "/consent"
	}
	base := *c.ProviderURL
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}

// ExternalUIOrigin returns the scheme and authority trusted for browser POSTs.
func (c Config) ExternalUIOrigin() string {
	if c.ExternalUIURL == nil {
		return ""
	}
	return (&url.URL{Scheme: c.ExternalUIURL.Scheme, Host: c.ExternalUIURL.Host}).String()
}

// OriginAllowed reports whether value exactly matches the external UI origin.
func (c Config) OriginAllowed(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	return parsed.Scheme == c.ExternalUIURL.Scheme && parsed.Host == c.ExternalUIURL.Host
}

func validateURL(value *url.URL, name string) error {
	if value == nil {
		return fmt.Errorf("%s is required", name)
	}
	if value.Scheme != "http" && value.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if value.Host == "" || value.User != nil || value.Fragment != "" {
		return fmt.Errorf("%s must be an origin URL without credentials or fragments", name)
	}
	return nil
}

func validateAbsoluteURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("invalid absolute URL %q", value)
	}
	return nil
}
