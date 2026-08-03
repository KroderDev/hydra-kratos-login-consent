package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
			t.Fatalf("decode policy request: %v", err)
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
			t.Fatalf("decode policy request: %v", err)
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
			client, err := NewHTTP(mustURL(t, server.URL), server.Client(), "")
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
		t.Fatalf("write policy response: %v", err)
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

type errorRoundTripper struct {
	err error
}

func (t errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}
