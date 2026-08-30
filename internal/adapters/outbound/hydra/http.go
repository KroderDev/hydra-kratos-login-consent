// Package hydra adapts the private Hydra administration API to provider ports.
package hydra

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

const maxResponseBytes = 1 << 20

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	token      string
}

var _ ports.LoginProvider = (*Client)(nil)
var _ ports.ConsentProvider = (*Client)(nil)
var _ ports.LogoutProvider = (*Client)(nil)
var _ ports.Readiness = (*Client)(nil)

// New creates a Hydra admin HTTP adapter.
func New(baseURL *url.URL, httpClient *http.Client, token string) (*Client, error) {
	if baseURL == nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("hydra admin url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{baseURL: baseURL, httpClient: &client, token: token}, nil
}

// GetLoginRequest retrieves a Hydra login challenge.
func (c *Client) GetLoginRequest(ctx context.Context, challenge string) (domain.LoginRequest, error) {
	var response loginResponse
	if err := c.doJSON(ctx, http.MethodGet, "/admin/oauth2/auth/requests/login", url.Values{"login_challenge": {challenge}}, nil, &response); err != nil {
		return domain.LoginRequest{}, err
	}
	return domain.LoginRequest{
		Challenge:    response.Challenge,
		Client:       response.Client.domain(),
		Skip:         response.Skip,
		Subject:      response.Subject,
		RequestedAAL: response.requestedAAL(),
	}, nil
}

// AcceptLogin accepts a validated Hydra login challenge.
func (c *Client) AcceptLogin(ctx context.Context, challenge string, acceptance ports.LoginAcceptance) (string, error) {
	body := acceptLoginRequest{
		Subject:     acceptance.Subject,
		ACR:         acceptance.ACR,
		AMR:         acceptance.AMR,
		Remember:    acceptance.Remember,
		RememberFor: acceptance.RememberFor,
	}
	var response redirectResponse
	if err := c.doJSON(ctx, http.MethodPut, "/admin/oauth2/auth/requests/login/accept", url.Values{"login_challenge": {challenge}}, body, &response); err != nil {
		return "", err
	}
	return response.RedirectTo, nil
}

// RejectLogin rejects a Hydra login challenge with a safe OAuth error.
func (c *Client) RejectLogin(ctx context.Context, challenge string, rejection ports.Rejection) (string, error) {
	return c.reject(ctx, "/admin/oauth2/auth/requests/login/reject", "login_challenge", challenge, rejection)
}

// GetConsentRequest retrieves a Hydra consent challenge.
func (c *Client) GetConsentRequest(ctx context.Context, challenge string) (domain.ConsentRequest, error) {
	var response consentResponse
	if err := c.doJSON(ctx, http.MethodGet, "/admin/oauth2/auth/requests/consent", url.Values{"consent_challenge": {challenge}}, nil, &response); err != nil {
		return domain.ConsentRequest{}, err
	}
	return domain.ConsentRequest{
		Challenge:         response.Challenge,
		Client:            response.Client.domain(),
		Subject:           response.Subject,
		RequestedScopes:   response.RequestedScope,
		RequestedAudience: response.RequestedAccessTokenAudience,
		Skip:              response.Skip,
	}, nil
}

// AcceptConsent accepts a validated Hydra consent challenge.
func (c *Client) AcceptConsent(ctx context.Context, challenge string, acceptance ports.ConsentAcceptance) (string, error) {
	body := acceptConsentRequest{
		GrantScope:               acceptance.GrantScopes,
		GrantAccessTokenAudience: acceptance.GrantAudience,
		Remember:                 acceptance.Remember,
		RememberFor:              acceptance.RememberFor,
		Session:                  tokenSession{AccessToken: acceptance.Session.AccessToken, IDToken: acceptance.Session.IDToken},
	}
	var response redirectResponse
	if err := c.doJSON(ctx, http.MethodPut, "/admin/oauth2/auth/requests/consent/accept", url.Values{"consent_challenge": {challenge}}, body, &response); err != nil {
		return "", err
	}
	return response.RedirectTo, nil
}

// RejectConsent rejects a Hydra consent challenge with a safe OAuth error.
func (c *Client) RejectConsent(ctx context.Context, challenge string, rejection ports.Rejection) (string, error) {
	return c.reject(ctx, "/admin/oauth2/auth/requests/consent/reject", "consent_challenge", challenge, rejection)
}

// GetLogoutRequest retrieves a Hydra logout challenge.
func (c *Client) GetLogoutRequest(ctx context.Context, challenge string) (domain.LogoutRequest, error) {
	var response logoutResponse
	if err := c.doJSON(ctx, http.MethodGet, "/admin/oauth2/auth/requests/logout", url.Values{"logout_challenge": {challenge}}, nil, &response); err != nil {
		return domain.LogoutRequest{}, err
	}
	postLogoutRedirectURI, err := postLogoutRedirect(response.RequestURL)
	if err != nil {
		return domain.LogoutRequest{}, err
	}
	return domain.LogoutRequest{
		Challenge:             response.Challenge,
		Client:                response.Client.domain(),
		Subject:               response.Subject,
		SessionID:             response.SessionID,
		RequestURL:            response.RequestURL,
		PostLogoutRedirectURI: postLogoutRedirectURI,
	}, nil
}

// AcceptLogout accepts a validated Hydra logout challenge.
func (c *Client) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	var response redirectResponse
	if err := c.doJSON(ctx, http.MethodPut, "/admin/oauth2/auth/requests/logout/accept", url.Values{"logout_challenge": {challenge}}, nil, &response); err != nil {
		return "", err
	}
	return response.RedirectTo, nil
}

// RejectLogout rejects a Hydra logout challenge.
func (c *Client) RejectLogout(ctx context.Context, challenge string, _ ports.Rejection) (string, error) {
	if err := c.doJSON(ctx, http.MethodPut, "/admin/oauth2/auth/requests/logout/reject", url.Values{"logout_challenge": {challenge}}, nil, nil); err != nil {
		return "", err
	}
	return "", nil
}

// Ready checks the Hydra admin health endpoint.
func (c *Client) Ready(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodGet, "/health/ready", nil, nil, nil)
}

func (c *Client) reject(ctx context.Context, path, challengeName, challenge string, rejection ports.Rejection) (string, error) {
	var response redirectResponse
	if err := c.doJSON(ctx, http.MethodPut, path, url.Values{challengeName: {challenge}}, rejection, &response); err != nil {
		return "", err
	}
	return response.RedirectTo, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any, output any) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawQuery = query.Encode()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: encode hydra request", domain.ErrUpstream)
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), payload)
	if err != nil {
		return fmt.Errorf("%w: create hydra request", domain.ErrUpstream)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: hydra request failed: %w", domain.ErrUpstream, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if err := drain(response.Body); err != nil {
			return err
		}
		return fmt.Errorf("%w: hydra returned status %d", domain.ErrUpstream, response.StatusCode)
	}
	if output == nil {
		return drain(response.Body)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(output); err != nil {
		_ = drain(response.Body)
		return fmt.Errorf("%w: decode hydra response", domain.ErrUpstream)
	}
	return drain(response.Body)
}

func drain(body io.Reader) error {
	if _, err := io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes)); err != nil {
		return fmt.Errorf("%w: drain upstream response", domain.ErrUpstream)
	}
	return nil
}

type loginResponse struct {
	Challenge   string         `json:"challenge"`
	Client      clientResponse `json:"client"`
	Skip        bool           `json:"skip"`
	Subject     string         `json:"subject"`
	OIDCContext *oidcContext   `json:"oidc_context"`
}

func (r loginResponse) requestedAAL() string {
	if r.OIDCContext == nil || len(r.OIDCContext.ACRValues) == 0 {
		return ""
	}
	return r.OIDCContext.ACRValues[0]
}

type oidcContext struct {
	ACRValues []string `json:"acr_values"`
}

type consentResponse struct {
	Challenge                    string         `json:"challenge"`
	Client                       clientResponse `json:"client"`
	Subject                      string         `json:"subject"`
	RequestedScope               []string       `json:"requested_scope"`
	RequestedAccessTokenAudience []string       `json:"requested_access_token_audience"`
	Skip                         bool           `json:"skip"`
}

type logoutResponse struct {
	Challenge  string         `json:"challenge"`
	Client     clientResponse `json:"client"`
	Subject    string         `json:"subject"`
	SessionID  string         `json:"sid"`
	RequestURL string         `json:"request_url"`
}

type clientResponse struct {
	ID                     string   `json:"client_id"`
	Name                   string   `json:"client_name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	SkipConsent            bool     `json:"skip_consent"`
}

func (c clientResponse) domain() domain.Client {
	return domain.Client{
		ID:                     c.ID,
		Name:                   c.Name,
		RedirectURIs:           append([]string(nil), c.RedirectURIs...),
		PostLogoutRedirectURIs: append([]string(nil), c.PostLogoutRedirectURIs...),
		SkipConsent:            c.SkipConsent,
	}
}

type redirectResponse struct {
	RedirectTo string `json:"redirect_to"`
}

type acceptLoginRequest struct {
	Subject     string   `json:"subject"`
	ACR         string   `json:"acr,omitempty"`
	AMR         []string `json:"amr,omitempty"`
	Remember    bool     `json:"remember,omitempty"`
	RememberFor int64    `json:"remember_for,omitempty"`
}

type acceptConsentRequest struct {
	GrantScope               []string     `json:"grant_scope"`
	GrantAccessTokenAudience []string     `json:"grant_access_token_audience,omitempty"`
	Remember                 bool         `json:"remember,omitempty"`
	RememberFor              int64        `json:"remember_for,omitempty"`
	Session                  tokenSession `json:"session,omitempty"`
}

type tokenSession struct {
	AccessToken map[string]any `json:"access_token,omitempty"`
	IDToken     map[string]any `json:"id_token,omitempty"`
}

func postLogoutRedirect(requestURL string) (string, error) {
	if requestURL == "" {
		return "", nil
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("%w: parse hydra logout request", domain.ErrUpstream)
	}
	values, ok := parsed.Query()["post_logout_redirect_uri"]
	if !ok {
		return "", nil
	}
	if len(values) != 1 || values[0] == "" {
		return "", domain.ErrInvalidRedirect
	}
	return values[0], nil
}
