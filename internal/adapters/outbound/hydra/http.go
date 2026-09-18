// Package hydra adapts the private Hydra administration API to provider ports.
package hydra

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	hydraapi "github.com/ory/hydra-client-go/v26"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

type Client struct {
	api *hydraapi.APIClient
}

var _ ports.LoginProvider = (*Client)(nil)
var _ ports.ConsentProvider = (*Client)(nil)
var _ ports.LogoutProvider = (*Client)(nil)
var _ ports.Readiness = (*Client)(nil)

// New creates a Hydra admin SDK adapter. Generated SDK types never leave this
// package; callers receive only provider-owned domain and port values.
func New(baseURL *url.URL, httpClient *http.Client, token string) (*Client, error) {
	if baseURL == nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.User != nil || baseURL.Fragment != "" {
		return nil, fmt.Errorf("hydra admin url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	configuration := hydraapi.NewConfiguration()
	configuration.Servers = hydraapi.ServerConfigurations{{URL: strings.TrimRight(baseURL.String(), "/")}}
	configuration.HTTPClient = &client
	if token != "" {
		configuration.AddDefaultHeader("Authorization", "Bearer "+token)
	}
	return &Client{api: hydraapi.NewAPIClient(configuration)}, nil
}

// GetLoginRequest retrieves a Hydra login challenge and preserves its requested
// prompt, max_age, and ACR values for application-level validation.
func (c *Client) GetLoginRequest(ctx context.Context, challenge string) (domain.LoginRequest, error) {
	response, httpResponse, err := c.api.OAuth2API.GetOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		Execute()
	defer closeResponse(httpResponse)
	if err != nil {
		return domain.LoginRequest{}, upstreamError(err)
	}
	if response == nil {
		return domain.LoginRequest{}, upstreamError(fmt.Errorf("empty login response"))
	}
	prompt, maxAge, err := parseOIDCRequestURL(response.RequestUrl)
	if err != nil {
		return domain.LoginRequest{}, err
	}
	acrValues := requestedACRValues(response.OidcContext)
	return domain.LoginRequest{
		Challenge:          response.Challenge,
		Client:             clientDomain(response.Client),
		Skip:               response.Skip,
		Subject:            response.Subject,
		RequestedAAL:       firstValue(acrValues),
		RequestedACRValues: acrValues,
		Prompt:             prompt,
		MaxAge:             maxAge,
	}, nil
}

// AcceptLogin accepts a validated Hydra login challenge.
func (c *Client) AcceptLogin(ctx context.Context, challenge string, acceptance ports.LoginAcceptance) (string, error) {
	request := hydraapi.NewAcceptOAuth2LoginRequest(acceptance.Subject)
	if acceptance.ACR != "" {
		request.SetAcr(acceptance.ACR)
	}
	if len(acceptance.AMR) > 0 {
		request.SetAmr(append([]string(nil), acceptance.AMR...))
	}
	if acceptance.Remember {
		request.SetRemember(true)
	}
	if acceptance.RememberFor != 0 {
		request.SetRememberFor(acceptance.RememberFor)
	}
	response, httpResponse, err := c.api.OAuth2API.AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		AcceptOAuth2LoginRequest(*request).
		Execute()
	defer closeResponse(httpResponse)
	return redirectResponse(response, err)
}

// RejectLogin rejects a validated Hydra login challenge with a safe OAuth error.
func (c *Client) RejectLogin(ctx context.Context, challenge string, rejection ports.Rejection) (string, error) {
	request := rejectionRequest(rejection)
	response, httpResponse, err := c.api.OAuth2API.RejectOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		RejectOAuth2Request(*request).
		Execute()
	defer closeResponse(httpResponse)
	return redirectResponse(response, err)
}

// GetConsentRequest retrieves a Hydra consent challenge and preserves its
// requested prompt, scopes, and access-token audiences.
func (c *Client) GetConsentRequest(ctx context.Context, challenge string) (domain.ConsentRequest, error) {
	response, httpResponse, err := c.api.OAuth2API.GetOAuth2ConsentRequest(ctx).
		ConsentChallenge(challenge).
		Execute()
	defer closeResponse(httpResponse)
	if err != nil {
		return domain.ConsentRequest{}, upstreamError(err)
	}
	if response == nil {
		return domain.ConsentRequest{}, upstreamError(fmt.Errorf("empty consent response"))
	}
	prompt, _, err := parseOIDCRequestURL(response.GetRequestUrl())
	if err != nil {
		return domain.ConsentRequest{}, err
	}
	return domain.ConsentRequest{
		Challenge:         response.Challenge,
		Client:            clientDomain(response.GetClient()),
		Subject:           response.GetSubject(),
		RequestedScopes:   append([]string(nil), response.RequestedScope...),
		RequestedAudience: append([]string(nil), response.RequestedAccessTokenAudience...),
		Skip:              response.GetSkip(),
		Prompt:            prompt,
	}, nil
}

// AcceptConsent accepts a validated Hydra consent challenge.
func (c *Client) AcceptConsent(ctx context.Context, challenge string, acceptance ports.ConsentAcceptance) (string, error) {
	session := hydraapi.NewAcceptOAuth2ConsentRequestSession()
	session.SetAccessToken(acceptance.Session.AccessToken)
	session.SetIdToken(acceptance.Session.IDToken)
	if len(acceptance.Session.UserInfo) > 0 {
		// The generated v26 SDK has no typed UserInfo session field, so the
		// dedicated userinfo claims travel through the additional-properties
		// escape hatch and are omitted entirely when no claims are allowed.
		session.AdditionalProperties = map[string]interface{}{"userinfo": acceptance.Session.UserInfo}
	}
	request := hydraapi.NewAcceptOAuth2ConsentRequest()
	request.SetGrantScope(append([]string(nil), acceptance.GrantScopes...))
	if len(acceptance.GrantAudience) > 0 {
		request.SetGrantAccessTokenAudience(append([]string(nil), acceptance.GrantAudience...))
	}
	request.SetSession(*session)
	if acceptance.Remember {
		request.SetRemember(true)
	}
	if acceptance.RememberFor != 0 {
		request.SetRememberFor(acceptance.RememberFor)
	}
	response, httpResponse, err := c.api.OAuth2API.AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(challenge).
		AcceptOAuth2ConsentRequest(*request).
		Execute()
	defer closeResponse(httpResponse)
	return redirectResponse(response, err)
}

// RejectConsent rejects a validated Hydra consent challenge with a safe OAuth error.
func (c *Client) RejectConsent(ctx context.Context, challenge string, rejection ports.Rejection) (string, error) {
	request := rejectionRequest(rejection)
	response, httpResponse, err := c.api.OAuth2API.RejectOAuth2ConsentRequest(ctx).
		ConsentChallenge(challenge).
		RejectOAuth2Request(*request).
		Execute()
	defer closeResponse(httpResponse)
	return redirectResponse(response, err)
}

// GetLogoutRequest retrieves a Hydra logout challenge.
func (c *Client) GetLogoutRequest(ctx context.Context, challenge string) (domain.LogoutRequest, error) {
	response, httpResponse, err := c.api.OAuth2API.GetOAuth2LogoutRequest(ctx).
		LogoutChallenge(challenge).
		Execute()
	defer closeResponse(httpResponse)
	if err != nil {
		return domain.LogoutRequest{}, upstreamError(err)
	}
	if response == nil {
		return domain.LogoutRequest{}, upstreamError(fmt.Errorf("empty logout response"))
	}
	requestURL := response.GetRequestUrl()
	postLogoutRedirectURI, err := postLogoutRedirect(requestURL)
	if err != nil {
		return domain.LogoutRequest{}, err
	}
	return domain.LogoutRequest{
		Challenge:             response.GetChallenge(),
		Client:                clientDomain(response.GetClient()),
		Subject:               response.GetSubject(),
		SessionID:             response.GetSid(),
		RequestURL:            requestURL,
		PostLogoutRedirectURI: postLogoutRedirectURI,
	}, nil
}

// AcceptLogout accepts a validated Hydra logout challenge.
func (c *Client) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	response, httpResponse, err := c.api.OAuth2API.AcceptOAuth2LogoutRequest(ctx).
		LogoutChallenge(challenge).
		Execute()
	defer closeResponse(httpResponse)
	return redirectResponse(response, err)
}

// RejectLogout rejects a validated Hydra logout challenge.
func (c *Client) RejectLogout(ctx context.Context, challenge string, _ ports.Rejection) (string, error) {
	httpResponse, err := c.api.OAuth2API.RejectOAuth2LogoutRequest(ctx).
		LogoutChallenge(challenge).
		Execute()
	defer closeResponse(httpResponse)
	if err != nil {
		return "", upstreamError(err)
	}
	return "", nil
}

// Ready checks the Hydra admin health endpoint.
func (c *Client) Ready(ctx context.Context) error {
	_, httpResponse, err := c.api.MetadataAPI.IsReady(ctx).Execute()
	defer closeResponse(httpResponse)
	if err != nil {
		return upstreamError(err)
	}
	return nil
}

func redirectResponse(response *hydraapi.OAuth2RedirectTo, err error) (string, error) {
	if err != nil {
		return "", upstreamError(err)
	}
	if response == nil || response.RedirectTo == "" {
		return "", upstreamError(fmt.Errorf("empty redirect response"))
	}
	return response.RedirectTo, nil
}

func rejectionRequest(rejection ports.Rejection) *hydraapi.RejectOAuth2Request {
	request := hydraapi.NewRejectOAuth2Request()
	if rejection.Error != "" {
		request.SetError(rejection.Error)
	}
	if rejection.ErrorDescription != "" {
		request.SetErrorDescription(rejection.ErrorDescription)
	}
	return request
}

func requestedACRValues(oidcContext *hydraapi.OAuth2ConsentRequestOpenIDConnectContext) []string {
	if oidcContext == nil {
		return nil
	}
	return append([]string(nil), oidcContext.AcrValues...)
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// parseOIDCRequestURL extracts a single prompt and nonnegative max_age from
// Hydra's original authorization URL. Malformed values return ErrUpstream.
func parseOIDCRequestURL(requestURL string) (string, *int64, error) {
	if requestURL == "" {
		return "", nil, nil
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", nil, upstreamError(fmt.Errorf("parse oidc request url"))
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", nil, upstreamError(fmt.Errorf("parse oidc request query"))
	}
	promptValues, ok := query["prompt"]
	prompt := ""
	if ok {
		if len(promptValues) != 1 || strings.TrimSpace(promptValues[0]) == "" {
			return "", nil, upstreamError(fmt.Errorf("invalid oidc prompt"))
		}
		prompt = strings.TrimSpace(promptValues[0])
	}
	maxAgeValues, ok := query["max_age"]
	if !ok {
		return prompt, nil, nil
	}
	if len(maxAgeValues) != 1 {
		return "", nil, upstreamError(fmt.Errorf("invalid oidc max_age"))
	}
	maxAge, err := strconv.ParseInt(strings.TrimSpace(maxAgeValues[0]), 10, 64)
	if err != nil || maxAge < 0 {
		return "", nil, upstreamError(fmt.Errorf("invalid oidc max_age"))
	}
	return prompt, &maxAge, nil
}

func clientDomain(client hydraapi.OAuth2Client) domain.Client {
	return domain.Client{
		ID:                     client.GetClientId(),
		Name:                   client.GetClientName(),
		RedirectURIs:           append([]string(nil), client.RedirectUris...),
		PostLogoutRedirectURIs: append([]string(nil), client.PostLogoutRedirectUris...),
		SkipConsent:            client.GetSkipConsent(),
	}
}

func upstreamError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: hydra request failed: %w", domain.ErrUpstream, err)
}

func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
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
