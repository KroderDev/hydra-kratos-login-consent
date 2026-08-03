// Package kratos adapts the Kratos public session API to provider ports.
package kratos

import (
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
}

var _ ports.Kratos = (*Client)(nil)
var _ ports.Readiness = (*Client)(nil)

// New creates a Kratos public session HTTP adapter.
func New(baseURL *url.URL, httpClient *http.Client) (*Client, error) {
	if baseURL == nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("kratos public url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{baseURL: baseURL, httpClient: &client}, nil
}

// ValidateSession asks Kratos to validate opaque browser credentials.
func (c *Client) ValidateSession(ctx context.Context, credentials ports.SessionCredentials) (domain.Session, error) {
	if credentials.CookieValue == "" && credentials.Token == "" {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/sessions/whoami"
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return domain.Session{}, fmt.Errorf("%w: create kratos request", domain.ErrUpstream)
	}
	if credentials.CookieName != "" && credentials.CookieValue != "" {
		request.AddCookie(&http.Cookie{
			Name:     credentials.CookieName,
			Value:    credentials.CookieValue,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	if credentials.Token != "" {
		request.Header.Set("Authorization", "Bearer "+credentials.Token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return domain.Session{}, fmt.Errorf("%w: kratos request failed", domain.ErrUpstream)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if err := drain(response.Body); err != nil {
			return domain.Session{}, err
		}
		return domain.Session{}, fmt.Errorf("%w: kratos returned status %d", domain.ErrUpstream, response.StatusCode)
	}
	var payload sessionResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(&payload); err != nil {
		return domain.Session{}, fmt.Errorf("%w: decode kratos response", domain.ErrUpstream)
	}
	if !payload.Active || payload.Identity.ID == "" {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	return domain.Session{Subject: payload.Identity.ID, AAL: payload.AAL, AMR: payload.AMR()}, nil
}

// Ready checks the Kratos public health endpoint.
func (c *Client) Ready(ctx context.Context) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/health/ready"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: create kratos readiness request", domain.ErrUpstream)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: kratos readiness request failed", domain.ErrUpstream)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: kratos returned readiness status %d", domain.ErrUpstream, response.StatusCode)
	}
	return nil
}

type sessionResponse struct {
	Active                bool                   `json:"active"`
	AAL                   string                 `json:"authenticator_assurance_level"`
	AuthenticationMethods []authenticationMethod `json:"authentication_methods"`
	Identity              struct {
		ID string `json:"id"`
	} `json:"identity"`
}

func (s sessionResponse) AMR() []string {
	methods := make([]string, 0, len(s.AuthenticationMethods))
	for _, method := range s.AuthenticationMethods {
		if method.Method != "" {
			methods = append(methods, method.Method)
		}
	}
	return methods
}

type authenticationMethod struct {
	Method string `json:"method"`
}

func drain(body io.Reader) error {
	if _, err := io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes)); err != nil {
		return fmt.Errorf("%w: drain upstream response", domain.ErrUpstream)
	}
	return nil
}
