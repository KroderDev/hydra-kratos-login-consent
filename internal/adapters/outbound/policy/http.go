package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

const (
	contractVersion  = "v1"
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 1 << 20
)

// HTTP evaluates authorization through the versioned remote policy contract.
type HTTP struct {
	endpoint   *url.URL
	httpClient *http.Client
	token      string
}

var _ ports.Policy = (*HTTP)(nil)

// NewHTTP creates an HTTP policy adapter for a versioned authorization endpoint.
func NewHTTP(endpoint *url.URL, httpClient *http.Client, token string) (*HTTP, error) {
	if endpoint == nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return nil, fmt.Errorf("policy URL must be an absolute HTTP URL without credentials, query, or fragment")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	baseURL := *endpoint
	return &HTTP{endpoint: &baseURL, httpClient: &client, token: strings.TrimSpace(token)}, nil
}

// AuthorizeLogin evaluates a login request against the remote policy service.
func (c *HTTP) AuthorizeLogin(ctx context.Context, input ports.PolicyInput) (bool, error) {
	decision, err := c.authorize(ctx, "login", input)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// AuthorizeConsent evaluates a consent request against the remote policy service.
func (c *HTTP) AuthorizeConsent(ctx context.Context, input ports.PolicyInput) (ports.ConsentDecision, error) {
	return c.authorize(ctx, "consent", input)
}

func (c *HTTP) authorize(ctx context.Context, operation string, input ports.PolicyInput) (ports.ConsentDecision, error) {
	payload := policyRequest{
		Version:            contractVersion,
		Operation:          operation,
		Subject:            input.Subject,
		ClientID:           input.ClientID,
		RequestedScopes:    contractStrings(input.RequestedScopes),
		GrantedScopes:      contractStrings(input.GrantedScopes),
		RequestedAudiences: contractStrings(input.RequestedAudiences),
		AAL:                input.AAL,
		AMR:                contractStrings(input.AMR),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: encode policy request", domain.ErrUpstream)
	}
	if len(encoded) > maxRequestBytes {
		return ports.ConsentDecision{}, fmt.Errorf("%w: policy request is too large", domain.ErrUpstream)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: create policy request", domain.ErrUpstream)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: policy request failed: %w", domain.ErrUpstream, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_ = drain(response.Body)
		return ports.ConsentDecision{}, fmt.Errorf("%w: policy returned status %d", domain.ErrUpstream, response.StatusCode)
	}

	var result policyResponse
	if err := decodeResponse(response.Body, &result); err != nil {
		return ports.ConsentDecision{}, err
	}
	decision, err := result.decision(input)
	if err != nil {
		return ports.ConsentDecision{}, err
	}
	return decision, nil
}

type policyRequest struct {
	Version            string   `json:"version"`
	Operation          string   `json:"operation"`
	Subject            string   `json:"subject"`
	ClientID           string   `json:"client_id"`
	RequestedScopes    []string `json:"requested_scopes"`
	GrantedScopes      []string `json:"granted_scopes"`
	RequestedAudiences []string `json:"requested_audiences"`
	AAL                string   `json:"aal"`
	AMR                []string `json:"amr"`
}

type policyResponse struct {
	Version          *string         `json:"version"`
	Allowed          *bool           `json:"allowed"`
	GrantedScopes    *[]string       `json:"granted_scopes"`
	GrantedAudiences *[]string       `json:"granted_audiences"`
	Claims           *claimsResponse `json:"claims"`
}

type claimsResponse struct {
	IDToken     map[string]any `json:"id_token"`
	AccessToken map[string]any `json:"access_token"`
}

func (r policyResponse) decision(input ports.PolicyInput) (ports.ConsentDecision, error) {
	if r.Version == nil || *r.Version != contractVersion || r.Allowed == nil || r.GrantedScopes == nil || r.GrantedAudiences == nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: malformed policy response", domain.ErrUpstream)
	}
	if err := validateValues(*r.GrantedScopes); err != nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: malformed policy scopes", domain.ErrUpstream)
	}
	if err := validateValues(*r.GrantedAudiences); err != nil {
		return ports.ConsentDecision{}, fmt.Errorf("%w: malformed policy audiences", domain.ErrUpstream)
	}
	if !*r.Allowed {
		if len(*r.GrantedScopes) != 0 || len(*r.GrantedAudiences) != 0 || claimsPresent(r.Claims) {
			return ports.ConsentDecision{}, fmt.Errorf("%w: denied policy response contains grants or claims", domain.ErrUpstream)
		}
		return ports.ConsentDecision{}, nil
	}
	if !subset(*r.GrantedScopes, input.GrantedScopes) || !subset(*r.GrantedAudiences, input.RequestedAudiences) {
		return ports.ConsentDecision{}, fmt.Errorf("%w: policy response expands requested grants", domain.ErrUpstream)
	}
	return ports.ConsentDecision{
		Allowed:          true,
		GrantedScopes:    append([]string(nil), (*r.GrantedScopes)...),
		GrantedAudiences: append([]string(nil), (*r.GrantedAudiences)...),
		Claims:           claimsFromResponse(r.Claims),
	}, nil
}

func claimsFromResponse(value *claimsResponse) domain.Claims {
	if value == nil {
		return domain.Claims{}
	}
	return domain.Claims{IDToken: value.IDToken, AccessToken: value.AccessToken}
}

func claimsPresent(value *claimsResponse) bool {
	return value != nil && (len(value.IDToken) != 0 || len(value.AccessToken) != 0)
}

func validateValues(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("empty value")
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate value")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func subset(values, allowed []string) bool {
	for _, value := range values {
		if !containsValue(allowed, value) {
			return false
		}
	}
	return true
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func contractStrings(source []string) []string {
	if len(source) == 0 {
		return []string{}
	}
	return cloneStrings(source)
}

func decodeResponse(body io.Reader, output *policyResponse) error {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read policy response", domain.ErrUpstream)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("%w: policy response is too large", domain.ErrUpstream)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("%w: decode policy response", domain.ErrUpstream)
	}
	return nil
}

func drain(body io.Reader) error {
	if _, err := io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes)); err != nil {
		return fmt.Errorf("%w: drain policy response", domain.ErrUpstream)
	}
	return nil
}
