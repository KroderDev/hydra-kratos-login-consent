package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestHTTPAuthorizeConsentSendsVersionedRequest(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/authorize" {
			t.Errorf("request = %s %s, want POST /v1/authorize", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer policy-secret" {
			t.Errorf("authorization = %q, want bearer token", got)
		}
		var request policyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode policy request: %v", err)
			return
		}
		if request.Version != contractVersion || request.Operation != "consent" || request.Subject != "operator-1" || request.ClientID != "client-1" {
			t.Errorf("request identity = %#v", request)
		}
		if !equalStrings(request.RequestedScopes, []string{"openid", "profile"}) || !equalStrings(request.GrantedScopes, []string{"openid"}) {
			t.Errorf("request scopes = %#v/%#v", request.RequestedScopes, request.GrantedScopes)
		}
		if !equalStrings(request.RequestedAudiences, []string{"api"}) || request.AAL != "aal2" || !equalStrings(request.AMR, []string{"pwd", "totp"}) {
			t.Errorf("request assurance = %#v/%q/%#v", request.RequestedAudiences, request.AAL, request.AMR)
		}
		writePolicyJSON(t, w, map[string]any{
			"version":           contractVersion,
			"allowed":           true,
			"granted_scopes":    []string{"openid"},
			"granted_audiences": []string{"api"},
			"claims":            map[string]any{"id_token": map[string]any{"email": "operator@example.com"}},
		})
	}))
	defer server.Close()

	endpoint := mustURL(t, server.URL+"/v1/authorize")
	client, err := NewHTTP(endpoint, server.Client(), "policy-secret")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	decision, err := client.AuthorizeConsent(context.Background(), ports.PolicyInput{
		Subject:            "operator-1",
		ClientID:           "client-1",
		RequestedScopes:    []string{"openid", "profile"},
		GrantedScopes:      []string{"openid"},
		RequestedAudiences: []string{"api"},
		AAL:                "aal2",
		AMR:                []string{"pwd", "totp"},
	})
	if err != nil {
		t.Fatalf("authorize consent: %v", err)
	}
	if !decision.Allowed || !equalStrings(decision.GrantedScopes, []string{"openid"}) || !equalStrings(decision.GrantedAudiences, []string{"api"}) {
		t.Fatalf("decision = %#v", decision)
	}
	if got := decision.Claims.IDToken["email"]; got != "operator@example.com" {
		t.Fatalf("email claim = %#v, want operator@example.com", got)
	}
}

func TestHTTPAuthorizeLoginSendsEmptyGrantLists(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode policy request: %v", err)
			return
		}
		for _, name := range []string{"requested_scopes", "granted_scopes", "requested_audiences", "amr"} {
			values, ok := request[name].([]any)
			if !ok || len(values) != 0 {
				t.Errorf("%s = %#v, want empty array", name, request[name])
			}
		}
		writePolicyJSON(t, w, map[string]any{
			"version":           contractVersion,
			"allowed":           true,
			"granted_scopes":    []string{},
			"granted_audiences": []string{},
		})
	}))
	defer server.Close()

	client, err := NewHTTP(mustURL(t, server.URL+"/v1/authorize"), server.Client(), "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	allowed, err := client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"})
	if err != nil {
		t.Fatalf("authorize login: %v", err)
	}
	if !allowed {
		t.Fatal("login was denied")
	}
}

func TestHTTPPolicyAuthorizationMatrix(t *testing.T) {
	t.Parallel()

	bearer := "fixture-policy-bearer"
	tests := []struct {
		name          string
		operation     string
		input         ports.PolicyInput
		wantAllowed   bool
		wantScopes    []string
		wantAudiences []string
	}{
		{
			name:      "approved login",
			operation: "login",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-1", AAL: "aal2", AMR: []string{"pwd", "totp"},
			},
			wantAllowed: true,
		},
		{
			name:      "unknown subject denied",
			operation: "login",
			input: ports.PolicyInput{
				Subject: "operator-2", ClientID: "client-1", AAL: "aal2", AMR: []string{"pwd", "totp"},
			},
		},
		{
			name:      "unknown client denied",
			operation: "login",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-2", AAL: "aal2", AMR: []string{"pwd", "totp"},
			},
		},
		{
			name:      "approved consent reduces grants",
			operation: "consent",
			input: ports.PolicyInput{
				Subject:            "operator-1",
				ClientID:           "client-1",
				RequestedScopes:    []string{"openid", "profile"},
				GrantedScopes:      []string{"openid", "profile"},
				RequestedAudiences: []string{"api", "reports"},
				AAL:                "aal2",
				AMR:                []string{"pwd", "totp"},
			},
			wantAllowed:   true,
			wantScopes:    []string{"openid"},
			wantAudiences: []string{"api"},
		},
		{
			name:      "unauthorized scope denied",
			operation: "consent",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-1", RequestedScopes: []string{"admin"},
				GrantedScopes: []string{"admin"}, AAL: "aal2", AMR: []string{"pwd", "totp"},
			},
		},
		{
			name:      "unauthorized audience denied",
			operation: "consent",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-1", RequestedAudiences: []string{"admin-api"},
				AAL: "aal2", AMR: []string{"pwd", "totp"},
			},
		},
		{
			name:      "insufficient aal denied",
			operation: "login",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-1", AAL: "aal1", AMR: []string{"pwd", "totp"},
			},
		},
		{
			name:      "insufficient amr denied",
			operation: "login",
			input: ports.PolicyInput{
				Subject: "operator-1", ClientID: "client-1", AAL: "aal2", AMR: []string{"pwd"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newPolicyHTTPFixture(t, func(request policyRequest) policyHTTPFixtureResponse {
				allowed := request.Subject == "operator-1" && request.ClientID == "client-1" &&
					request.AAL == "aal2" && equalStrings(request.AMR, []string{"pwd", "totp"})
				if containsValue(request.GrantedScopes, "admin") || containsValue(request.RequestedAudiences, "admin-api") {
					allowed = false
				}
				if !allowed {
					return policyHTTPFixtureResponse{body: policyDecisionBody(false, nil, nil)}
				}
				if request.Operation == "login" {
					return policyHTTPFixtureResponse{body: policyDecisionBody(true, nil, nil)}
				}
				return policyHTTPFixtureResponse{
					body: policyDecisionBody(true, firstValue(request.GrantedScopes), firstValue(request.RequestedAudiences)),
				}
			})
			client, err := NewHTTP(mustURL(t, fixture.server.URL+"/v1/authorize"), fixture.server.Client(), bearer)
			if err != nil {
				t.Fatalf("create policy client: %v", err)
			}

			var allowed bool
			var decision ports.ConsentDecision
			switch tt.operation {
			case "login":
				allowed, err = client.AuthorizeLogin(context.Background(), tt.input)
			case "consent":
				decision, err = client.AuthorizeConsent(context.Background(), tt.input)
				allowed = decision.Allowed
			default:
				t.Fatalf("unsupported operation %q", tt.operation)
			}
			if err != nil {
				t.Fatalf("authorize %s: %v", tt.operation, err)
			}
			if allowed != tt.wantAllowed {
				t.Fatalf("allowed = %t, want %t", allowed, tt.wantAllowed)
			}
			request := fixture.requestAt(t, 0)
			if request.Version != contractVersion || request.Operation != tt.operation || request.Subject != tt.input.Subject || request.ClientID != tt.input.ClientID {
				t.Fatalf("request context = %#v, want version/operation/identity %q/%q/%q/%q", request, contractVersion, tt.operation, tt.input.Subject, tt.input.ClientID)
			}
			if !equalStrings(request.RequestedScopes, tt.input.RequestedScopes) || !equalStrings(request.GrantedScopes, tt.input.GrantedScopes) || !equalStrings(request.RequestedAudiences, tt.input.RequestedAudiences) || request.AAL != tt.input.AAL || !equalStrings(request.AMR, tt.input.AMR) {
				t.Fatalf("request authorization context = %#v, want scopes/audiences/aal/amr from %#v", request, tt.input)
			}
			if got := fixture.authorizationAt(t, 0); got != "Bearer "+bearer {
				t.Fatalf("authorization header = %q, want policy bearer token", got)
			}
			if tt.operation == "consent" && tt.wantAllowed {
				if !equalStrings(decision.GrantedScopes, tt.wantScopes) || !equalStrings(decision.GrantedAudiences, tt.wantAudiences) {
					t.Fatalf("decision grants = %#v/%#v, want %#v/%#v", decision.GrantedScopes, decision.GrantedAudiences, tt.wantScopes, tt.wantAudiences)
				}
				if decision.Claims.IDToken["email"] != "operator@example.com" || decision.Claims.AccessToken["tenant"] != "tenant-a" {
					t.Fatalf("decision claims = %#v, want application claims", decision.Claims)
				}
			}
			if tt.operation == "consent" && !tt.wantAllowed && (len(decision.GrantedScopes) != 0 || len(decision.GrantedAudiences) != 0 || len(decision.Claims.IDToken) != 0 || len(decision.Claims.AccessToken) != 0) {
				t.Fatalf("denied decision returned grants or claims: %#v", decision)
			}
		})
	}
}

func TestHTTPPolicyDeniedDecisionIsFailClosed(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writePolicyJSON(t, w, map[string]any{
			"version":           contractVersion,
			"allowed":           false,
			"granted_scopes":    []string{},
			"granted_audiences": []string{},
		})
	}))
	defer server.Close()
	client, err := NewHTTP(mustURL(t, server.URL), server.Client(), "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}

	decision, err := client.AuthorizeConsent(context.Background(), ports.PolicyInput{GrantedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("authorize consent: %v", err)
	}
	if decision.Allowed || len(decision.GrantedScopes) != 0 || len(decision.Claims.IDToken) != 0 {
		t.Fatalf("denied decision = %#v", decision)
	}
}

func TestHTTPPolicyRejectsMalformedAndUnsafeResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code int
	}{
		{name: "server failure", body: `upstream-secret`, code: http.StatusBadGateway},
		{name: "missing version", body: `{"allowed":true,"granted_scopes":[],"granted_audiences":[]}`, code: http.StatusOK},
		{name: "invalid json", body: `{`, code: http.StatusOK},
		{name: "denied with claims", body: `{"version":"v1","allowed":false,"granted_scopes":[],"granted_audiences":[],"claims":{"id_token":{"role":"admin"}}}`, code: http.StatusOK},
		{name: "expanded scope", body: `{"version":"v1","allowed":true,"granted_scopes":["admin"],"granted_audiences":[]}`, code: http.StatusOK},
		{name: "empty scope", body: `{"version":"v1","allowed":true,"granted_scopes":[""],"granted_audiences":[]}`, code: http.StatusOK},
		{name: "empty audience", body: `{"version":"v1","allowed":true,"granted_scopes":[],"granted_audiences":[""]}`, code: http.StatusOK},
		{name: "duplicate audience", body: `{"version":"v1","allowed":true,"granted_scopes":[],"granted_audiences":["api","api"]}`, code: http.StatusOK},
		{name: "oversized body", body: strings.Repeat("x", maxResponseBytes+1), code: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.code)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client, err := NewHTTP(mustURL(t, server.URL), server.Client(), "policy-auth-secret")
			if err != nil {
				t.Fatalf("create policy client: %v", err)
			}
			_, err = client.AuthorizeConsent(context.Background(), ports.PolicyInput{GrantedScopes: []string{"openid"}})
			if !errors.Is(err, domain.ErrUpstream) {
				t.Fatalf("error = %v, want upstream error", err)
			}
			if strings.Contains(err.Error(), "upstream-secret") {
				t.Fatal("upstream response body was exposed in error")
			}
			if strings.Contains(err.Error(), "policy-auth-secret") {
				t.Fatal("policy credential was exposed in error")
			}
		})
	}
}

func TestHTTPPolicyRejectsRedirects(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writePolicyJSON(t, w, map[string]any{
			"version":           contractVersion,
			"allowed":           true,
			"granted_scopes":    []string{},
			"granted_audiences": []string{},
		})
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client, err := NewHTTP(mustURL(t, server.URL), server.Client(), "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	if _, err := client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"}); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
}

func TestHTTPPolicyMapsTimeoutToUpstreamError(t *testing.T) {
	t.Parallel()

	endpoint := mustURL(t, "https://policy.example/v1/authorize")
	client, err := NewHTTP(endpoint, &http.Client{Transport: errorRoundTripper{err: context.DeadlineExceeded}}, "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	if _, err := client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"}); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
}

func TestHTTPPolicyMapsConnectionFailureToUpstreamError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close()
	client, err := NewHTTP(mustURL(t, endpoint+"/v1/authorize"), &http.Client{Timeout: time.Second}, "connection-secret")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	_, err = client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"})
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
	if strings.Contains(err.Error(), "connection-secret") {
		t.Fatal("policy credential was exposed in connection failure")
	}
}

func TestHTTPPolicyMapsContextCancellationToUpstreamError(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	canceled := make(chan struct{})
	client, err := NewHTTP(
		mustURL(t, "https://policy.example/v1/authorize"),
		&http.Client{Transport: cancellationRoundTripper{started: started, canceled: canceled}},
		"timeout-secret",
	)
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, requestErr := client.AuthorizeLogin(ctx, ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"})
		result <- requestErr
	}()
	select {
	case <-started:
	case <-result:
		t.Fatal("policy request completed before reaching the fixture")
	case <-time.After(time.Second):
		t.Fatal("policy request did not reach the fixture")
	}
	cancel()
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("canceled policy request did not return")
	}
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("policy fixture did not observe request cancellation")
	}
	if strings.Contains(err.Error(), "timeout-secret") {
		t.Fatal("policy credential was exposed in cancellation failure")
	}
}

func TestNewHTTPUsesBoundedDefaultClient(t *testing.T) {
	t.Parallel()

	client, err := NewHTTP(mustURL(t, "https://policy.example/v1/authorize"), nil, "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	if client.httpClient == nil || client.httpClient.Timeout != 10*time.Second {
		t.Fatalf("default HTTP client = %#v, want a 10 second timeout", client.httpClient)
	}
}

func TestHTTPPolicyRejectsOversizedRequest(t *testing.T) {
	t.Parallel()

	client, err := NewHTTP(
		mustURL(t, "https://policy.example/v1/authorize"),
		&http.Client{Transport: errorRoundTripper{err: errors.New("request should not be dispatched")}},
		"",
	)
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	_, err = client.AuthorizeLogin(context.Background(), ports.PolicyInput{
		Subject:  strings.Repeat("x", maxRequestBytes),
		ClientID: "client-1",
	})
	if !errors.Is(err, domain.ErrUpstream) || !strings.Contains(err.Error(), "request is too large") {
		t.Fatalf("error = %v, want oversized upstream error", err)
	}
}

func TestHTTPPolicyMapsResponseReadFailureToUpstreamError(t *testing.T) {
	t.Parallel()

	client, err := NewHTTP(mustURL(t, "https://policy.example/v1/authorize"), &http.Client{
		Transport: responseRoundTripper{response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       errorBody{err: errors.New("response read failed")},
		}},
	}, "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	if _, err := client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"}); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
}

func TestHTTPPolicyPreservesStatusWhenErrorBodyCannotDrain(t *testing.T) {
	t.Parallel()

	client, err := NewHTTP(mustURL(t, "https://policy.example/v1/authorize"), &http.Client{
		Transport: responseRoundTripper{response: &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       errorBody{err: errors.New("response drain failed")},
		}},
	}, "")
	if err != nil {
		t.Fatalf("create policy client: %v", err)
	}
	_, err = client.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"})
	if !errors.Is(err, domain.ErrUpstream) || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("error = %v, want status-preserving upstream error", err)
	}
}

func TestNewHTTPRejectsUnsafeEndpoints(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"ftp://policy.example/v1/authorize",
		"https://user:password@policy.example/v1/authorize",
		"https://policy.example/v1/authorize?token=secret",
		"https://policy.example/v1/authorize#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := NewHTTP(mustURL(t, raw), nil, ""); err == nil {
				t.Fatal("unsafe policy endpoint was accepted")
			}
		})
	}
}

func writePolicyJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("write policy response: %v", err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return value
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

type policyHTTPFixture struct {
	server        *httptest.Server
	mu            sync.Mutex
	requests      []policyRequest
	authorization []string
	decide        func(policyRequest) policyHTTPFixtureResponse
}

type policyHTTPFixtureResponse struct {
	status int
	body   any
	raw    string
}

func newPolicyHTTPFixture(t *testing.T, decide func(policyRequest) policyHTTPFixtureResponse) *policyHTTPFixture {
	t.Helper()
	fixture := &policyHTTPFixture{decide: decide}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *policyHTTPFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/authorize" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var request policyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, request)
	f.authorization = append(f.authorization, r.Header.Get("Authorization"))
	f.mu.Unlock()
	response := f.decide(request)
	if response.status == 0 {
		response.status = http.StatusOK
	}
	if response.raw != "" {
		w.WriteHeader(response.status)
		_, _ = io.WriteString(w, response.raw)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.status)
	_ = json.NewEncoder(w).Encode(response.body)
}

func (f *policyHTTPFixture) requestAt(t *testing.T, index int) policyRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if index < 0 || index >= len(f.requests) {
		t.Fatalf("policy requests = %d, want index %d", len(f.requests), index)
	}
	return f.requests[index]
}

func (f *policyHTTPFixture) authorizationAt(t *testing.T, index int) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if index < 0 || index >= len(f.authorization) {
		t.Fatalf("policy authorization headers = %d, want index %d", len(f.authorization), index)
	}
	return f.authorization[index]
}

func policyDecisionBody(allowed bool, scopes, audiences []string) map[string]any {
	if scopes == nil {
		scopes = []string{}
	}
	if audiences == nil {
		audiences = []string{}
	}
	response := map[string]any{
		"version":           contractVersion,
		"allowed":           allowed,
		"granted_scopes":    scopes,
		"granted_audiences": audiences,
	}
	if allowed {
		response["claims"] = map[string]any{
			"id_token":     map[string]any{"email": "operator@example.com"},
			"access_token": map[string]any{"tenant": "tenant-a"},
		}
	}
	return response
}

func firstValue(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return []string{values[0]}
}

type errorRoundTripper struct {
	err error
}

func (t errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

type cancellationRoundTripper struct {
	started  chan<- struct{}
	canceled chan<- struct{}
}

func (t cancellationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	close(t.started)
	<-request.Context().Done()
	close(t.canceled)
	return nil, request.Context().Err()
}

type responseRoundTripper struct {
	response *http.Response
}

func (t responseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return t.response, nil
}

type errorBody struct {
	err error
}

func (b errorBody) Read([]byte) (int, error) {
	return 0, b.err
}

func (errorBody) Close() error {
	return nil
}

var _ io.ReadCloser = errorBody{}
