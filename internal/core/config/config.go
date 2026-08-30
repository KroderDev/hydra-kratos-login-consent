// Package config contains validated configuration consumed by the application core.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
)

// Client contains deployment-owned allowlists for one OAuth client.
type Client struct {
	ID                         string              `json:"id,omitempty"`
	AllowedRedirectURIs        []string            `json:"allowed_redirect_uris"`
	AllowedPostLogoutRedirects []string            `json:"allowed_post_logout_redirect_uris"`
	AllowedScopes              []string            `json:"allowed_scopes"`
	AllowedAudiences           []string            `json:"allowed_audiences"`
	SkipConsent                bool                `json:"skip_consent"`
	AllowedIDTokenClaims       map[string][]string `json:"allowed_id_token_claims"`
	AllowedAccessTokenClaims   map[string][]string `json:"allowed_access_token_claims"`
}

// PolicyBackend identifies the authorization policy implementation.
type PolicyBackend string

const (
	PolicyBackendStatic PolicyBackend = "static"
	PolicyBackendHTTP   PolicyBackend = "http"
)

// Config contains validated provider configuration.
type Config struct {
	ListenAddress             string
	Environment               string
	ProviderURL               *url.URL
	ExternalUIURL             *url.URL
	HydraAdminURL             *url.URL
	HydraPublicURL            *url.URL
	KratosPublicURL           *url.URL
	KratosSessionCookie       string
	RequiredAAL               string
	TransactionTTL            time.Duration
	MaxPendingTransactions    int
	MaxChallengeLength        int
	Clients                   map[string]Client
	PolicyBackend             PolicyBackend
	PolicyURL                 *url.URL
	OIDCIdentityClaimMappings identity.ClaimMappings
}

const (
	DefaultTransactionTTL         = 5 * time.Minute
	MaxTransactionTTL             = 15 * time.Minute
	DefaultMaxPendingTransactions = 10_000
	DefaultMaxChallengeLength     = 2048
	MaxChallengeLengthLimit       = 4096
)

// Validate rejects unsafe or incomplete provider configuration.
func (c Config) Validate() error {
	if c.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	secureTransport := c.secureTransportRequired()
	if err := validateURL(c.ProviderURL, "provider URL", secureTransport); err != nil {
		return err
	}
	if err := validateURL(c.ExternalUIURL, "external UI URL", secureTransport); err != nil {
		return err
	}
	if err := validateURL(c.HydraAdminURL, "Hydra admin URL", secureTransport); err != nil {
		return err
	}
	if err := validateURL(c.HydraPublicURL, "Hydra public URL", secureTransport); err != nil {
		return err
	}
	if err := validateURL(c.KratosPublicURL, "Kratos public URL", secureTransport); err != nil {
		return err
	}
	if c.KratosSessionCookie == "" {
		return fmt.Errorf("kratos session cookie is required")
	}
	if c.RequiredAAL != "" && !domain.AALAtLeast(c.RequiredAAL, c.RequiredAAL) {
		return fmt.Errorf("unsupported required aal %q", c.RequiredAAL)
	}
	if c.TransactionTTL <= 0 || c.TransactionTTL > MaxTransactionTTL {
		return fmt.Errorf("transaction TTL must be between 1s and %s", MaxTransactionTTL)
	}
	if c.MaxPendingTransactions < 0 {
		return fmt.Errorf("max pending transactions cannot be negative")
	}
	if c.MaxChallengeLength < 0 || c.MaxChallengeLength > MaxChallengeLengthLimit {
		return fmt.Errorf("max challenge length must be between 0 and %d", MaxChallengeLengthLimit)
	}
	if err := c.OIDCIdentityClaimMappings.Validate(c.IsSecureEnvironment()); err != nil {
		return fmt.Errorf("validate oidc identity claim mappings: %w", err)
	}
	policyBackend := c.PolicyBackend
	if policyBackend == "" {
		policyBackend = PolicyBackendStatic
	}
	if policyBackend != PolicyBackendStatic && policyBackend != PolicyBackendHTTP {
		return fmt.Errorf("unsupported policy backend %q: want static or http", policyBackend)
	}
	if policyBackend == PolicyBackendHTTP {
		if err := validateURL(c.PolicyURL, "policy URL", secureTransport); err != nil {
			return err
		}
		if c.PolicyURL.RawQuery != "" {
			return fmt.Errorf("policy URL must not contain a query")
		}
	}
	for id, client := range c.Clients {
		if client.ID != id {
			return fmt.Errorf("client map key %q does not match client id %q", id, client.ID)
		}
		if len(client.AllowedRedirectURIs) == 0 {
			return fmt.Errorf("client %q has no allowed redirect uris", id)
		}
		for _, value := range client.AllowedRedirectURIs {
			if err := validateAbsoluteURL(value, secureTransport, true); err != nil {
				return fmt.Errorf("client %q: %w", id, err)
			}
		}
		for _, value := range client.AllowedPostLogoutRedirects {
			if err := validateAbsoluteURL(value, secureTransport, true); err != nil {
				return fmt.Errorf("client %q: %w", id, err)
			}
		}
		if hasDuplicates(client.AllowedAudiences) {
			return fmt.Errorf("client %q has duplicate allowed audiences", id)
		}
		for _, audience := range client.AllowedAudiences {
			if strings.TrimSpace(audience) == "" {
				return fmt.Errorf("client %q has an empty allowed audience", id)
			}
		}
		if err := validateClaimAllowlist(id, client.AllowedIDTokenClaims, client.AllowedScopes); err != nil {
			return err
		}
		if err := validateClaimAllowlist(id, client.AllowedAccessTokenClaims, client.AllowedScopes); err != nil {
			return err
		}
	}
	return nil
}

// EffectiveMaxPendingTransactions returns the configured quota or the bounded
// default used by callers that construct Config directly.
func (c Config) EffectiveMaxPendingTransactions() int {
	if c.MaxPendingTransactions <= 0 {
		return DefaultMaxPendingTransactions
	}
	return c.MaxPendingTransactions
}

// EffectiveMaxChallengeLength returns the configured challenge limit or the
// default used by callers that construct Config directly.
func (c Config) EffectiveMaxChallengeLength() int {
	if c.MaxChallengeLength <= 0 {
		return DefaultMaxChallengeLength
	}
	return c.MaxChallengeLength
}

func (c Config) secureTransportRequired() bool {
	environment := strings.ToLower(strings.TrimSpace(c.Environment))
	return environment != "" && environment != "development" && environment != "test"
}

// IsSecureEnvironment reports whether production transport and credential
// requirements apply to this configuration.
func (c Config) IsSecureEnvironment() bool {
	return c.secureTransportRequired()
}

// Client returns the configured client policy for id.
func (c Config) Client(id string) (Client, bool) {
	client, ok := c.Clients[id]
	return client, ok
}

// ExternalRedirect builds a fixed-origin external UI handoff URL.
func (c Config) ExternalRedirect(flow domain.Flow, transaction, csrfToken string) (string, error) {
	if (flow != domain.FlowLogin && flow != domain.FlowConsent && flow != domain.FlowLogout) || transaction == "" || csrfToken == "" {
		return "", domain.ErrInvalidTransaction
	}
	callback := c.callbackURL(flow)
	callback.RawQuery = url.Values{
		"flow":        {string(flow)},
		"transaction": {transaction},
		"csrf":        {csrfToken},
	}.Encode()

	redirect := *c.ExternalUIURL
	redirect.RawQuery = url.Values{
		"flow":        {string(flow)},
		"transaction": {transaction},
		"csrf":        {csrfToken},
		"return_to":   {callback.String()},
	}.Encode()
	return redirect.String(), nil
}

// ExternalConsentRedirect adds safe consent display data to an external UI handoff.
func (c Config) ExternalConsentRedirect(transaction, csrfToken, clientName string, scopes []string) (string, error) {
	if transaction == "" || csrfToken == "" {
		return "", domain.ErrInvalidTransaction
	}
	callback := c.callbackURL(domain.FlowConsent)
	callback.RawQuery = url.Values{
		"flow":        {string(domain.FlowConsent)},
		"transaction": {transaction},
		"csrf":        {csrfToken},
	}.Encode()

	redirect := *c.ExternalUIURL
	query := url.Values{
		"flow":        {string(domain.FlowConsent)},
		"transaction": {transaction},
		"csrf":        {csrfToken},
		"return_to":   {callback.String()},
	}
	if clientName != "" {
		query.Set("client_name", clientName)
	}
	if len(scopes) > 0 {
		query.Set("scope", strings.Join(scopes, " "))
	}
	redirect.RawQuery = query.Encode()
	return redirect.String(), nil
}

// CallbackURL returns the provider callback for a configured flow.
func (c Config) CallbackURL(flow domain.Flow) string {
	return c.callbackURL(flow).String()
}

func (c Config) callbackURL(flow domain.Flow) *url.URL {
	var path string
	switch flow {
	case domain.FlowLogin:
		path = "/login/callback"
	case domain.FlowConsent:
		path = "/consent"
	case domain.FlowLogout:
		path = "/logout"
	default:
		path = "/login/callback"
	}
	base := *c.ProviderURL
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = ""
	base.Fragment = ""
	return &base
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

func validateURL(value *url.URL, name string, requireHTTPS bool) error {
	if value == nil {
		return fmt.Errorf("%s is required", name)
	}
	if value.Scheme != "http" && value.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if requireHTTPS && value.Scheme != "https" {
		return fmt.Errorf("%s must use https outside development and test", name)
	}
	if value.Host == "" || value.User != nil || value.Fragment != "" {
		return fmt.Errorf("%s must be an origin URL without credentials or fragments", name)
	}
	return nil
}

// validateAbsoluteURL validates an absolute HTTP(S) URL and optionally requires HTTPS,
// while allowing HTTP URLs targeting loopback addresses when loopback redirects are enabled.
// It returns an error for invalid URLs or URLs that do not meet the transport requirement.
func validateAbsoluteURL(value string, requireHTTPS, allowLoopbackHTTP bool) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("invalid absolute URL %q", value)
	}
	if requireHTTPS && parsed.Scheme != "https" && (!allowLoopbackHTTP || !isLoopbackHTTPURL(parsed)) {
		return fmt.Errorf("invalid non-https URL %q outside development and test", value)
	}
	return nil
}

// isLoopbackHTTPURL reports whether value uses HTTP and targets the loopback address 127.0.0.1 or ::1.
func isLoopbackHTTPURL(value *url.URL) bool {
	if value.Scheme != "http" {
		return false
	}
	switch value.Hostname() {
	case "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// hasDuplicates reports whether the slice contains any repeated string.
func hasDuplicates(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

// validateClaimAllowlist validates claim names and their required scopes for a client.
// It returns an error if a claim name is empty or reserved, required scopes are duplicated,
// or a required scope is empty or absent from the client's allowed scopes.
func validateClaimAllowlist(clientID string, claims map[string][]string, allowedScopes []string) error {
	for name, requiredScopes := range claims {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("client %q has an empty claim name", clientID)
		}
		if identity.IsReservedClaim(name) {
			return fmt.Errorf("client %q claim %q is reserved by OAuth or OIDC", clientID, name)
		}
		if hasDuplicates(requiredScopes) {
			return fmt.Errorf("client %q has duplicate required scopes for claim %q", clientID, name)
		}
		for _, scope := range requiredScopes {
			if strings.TrimSpace(scope) == "" || !containsString(allowedScopes, scope) {
				return fmt.Errorf("client %q claim %q requires an unallowlisted scope %q", clientID, name, scope)
			}
		}
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
