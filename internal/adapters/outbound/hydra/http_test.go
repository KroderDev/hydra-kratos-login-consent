package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestClient_LoginRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/oauth2/auth/requests/login":
			if r.URL.Query().Get("login_challenge") != "login-challenge" {
				t.Fatalf("login challenge = %q, want login-challenge", r.URL.Query().Get("login_challenge"))
			}
			writeJSON(t, w, map[string]any{
				"challenge": "login-challenge",
				"client": map[string]any{
					"client_id":     "example-client",
					"client_name":   "Example Client",
					"redirect_uris": []string{"https://client.example/callback"},
				},
				"oidc_context": map[string]any{"acr_values": []string{"aal2"}},
				"skip":         false,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/login/accept":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode accept body: %v", err)
			}
			if body["subject"] != "operator-1" {
				t.Fatalf("accepted subject = %#v, want operator-1", body["subject"])
			}
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/oauth2/auth"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client(), "admin-token")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	login, err := client.GetLoginRequest(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("get login request: %v", err)
	}
	if login.Client.ID != "example-client" || login.RequestedAAL != "aal2" {
		t.Fatalf("login request = %#v, want example-client/aal2", login)
	}
	redirect, err := client.AcceptLogin(context.Background(), "login-challenge", ports.LoginAcceptance{Subject: "operator-1"})
	if err != nil {
		t.Fatalf("accept login: %v", err)
	}
	if redirect != "https://hydra.example/oauth2/auth" {
		t.Fatalf("redirect = %q, want Hydra redirect", redirect)
	}
}

func TestClient_LogoutRequestParsesReturnURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oauth2/auth/requests/logout" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{
			"challenge":   "logout-challenge",
			"request_url": "https://hydra.example/oauth2/sessions/logout?post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout",
			"client": map[string]any{
				"client_id":     "example-client",
				"redirect_uris": []string{"https://client.example/callback"},
			},
		})
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	request, err := client.GetLogoutRequest(context.Background(), "logout-challenge")
	if err != nil {
		t.Fatalf("get logout request: %v", err)
	}
	if request.PostLogoutRedirectURI != "https://client.example/logout" {
		t.Fatalf("post logout redirect = %q, want client logout URL", request.PostLogoutRedirectURI)
	}
}

func TestClient_ConsentAndLogoutRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			t.Errorf("authorization = %q, want bearer token", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/admin/oauth2/auth/requests/consent":
			writeJSON(t, w, map[string]any{
				"challenge": "consent-challenge",
				"client":    map[string]any{"client_id": "example-client", "client_name": "Example"},
				"subject":   "operator-1", "requested_scope": []string{"openid", "profile"},
				"requested_access_token_audience": []string{"api"}, "skip": true,
			})
		case "/admin/oauth2/auth/requests/consent/accept":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode consent body: %v", err)
			}
			got, ok := body["grant_scope"].([]any)
			if !ok || len(got) != 1 || got[0] != "openid" {
				t.Fatalf("grant_scope = %#v, want [openid]", got)
			}
			session, ok := body["session"].(map[string]any)
			idToken, idTokenOK := session["id_token"].(map[string]any)
			if !ok || !idTokenOK || idToken["email"] != "operator@example.com" {
				t.Fatalf("consent session = %#v, want Hydra ID-token email", body["session"])
			}
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/consent"})
		case "/admin/oauth2/auth/requests/consent/reject":
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/rejected"})
		case "/admin/oauth2/auth/requests/logout/accept":
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/logout"})
		case "/admin/oauth2/auth/requests/logout/reject", "/health/ready":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client(), "admin-token")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	consent, err := client.GetConsentRequest(context.Background(), "consent-challenge")
	if err != nil || consent.Subject != "operator-1" || !consent.Skip || len(consent.RequestedAudience) != 1 {
		t.Fatalf("consent = %#v, error = %v", consent, err)
	}
	redirect, err := client.AcceptConsent(context.Background(), "consent-challenge", ports.ConsentAcceptance{
		GrantScopes: []string{"openid"}, GrantAudience: []string{"api"},
		Session: domain.Claims{IDToken: map[string]any{"email": "operator@example.com"}},
	})
	if err != nil || redirect != "https://hydra.example/consent" {
		t.Fatalf("accept consent = %q, error = %v", redirect, err)
	}
	redirect, err = client.RejectConsent(context.Background(), "consent-challenge", ports.Rejection{Error: "access_denied"})
	if err != nil || redirect != "https://hydra.example/rejected" {
		t.Fatalf("reject consent = %q, error = %v", redirect, err)
	}
	redirect, err = client.AcceptLogout(context.Background(), "logout-challenge")
	if err != nil || redirect != "https://hydra.example/logout" {
		t.Fatalf("accept logout = %q, error = %v", redirect, err)
	}
	if _, err := client.RejectLogout(context.Background(), "logout-challenge", ports.Rejection{}); err != nil {
		t.Fatalf("reject logout: %v", err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestClient_UpstreamFailuresMapToErrUpstream(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream failure"))
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.GetConsentRequest(context.Background(), "challenge"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream error", err)
	}
}

func TestPostLogoutRedirectRejectsDuplicateValues(t *testing.T) {
	t.Parallel()

	if _, err := postLogoutRedirect("https://hydra.example/logout?post_logout_redirect_uri=a&post_logout_redirect_uri=b"); !errors.Is(err, domain.ErrInvalidRedirect) {
		t.Fatalf("error = %v, want invalid redirect", err)
	}
}

func TestClient_RejectionsAndAcceptLogout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/oauth2/auth/requests/login/reject",
			"/admin/oauth2/auth/requests/consent/reject",
			"/admin/oauth2/auth/requests/logout/reject",
			"/admin/oauth2/auth/requests/logout/accept":
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/callback"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	baseURL, _ := url.Parse(server.URL)
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	rejection := ports.Rejection{Error: "access_denied", ErrorDescription: "denied"}
	if redirect, err := client.RejectLogin(context.Background(), "c", rejection); err != nil || redirect != "https://hydra.example/callback" {
		t.Fatalf("RejectLogin error = %v, redirect = %q", err, redirect)
	}
	if redirect, err := client.RejectConsent(context.Background(), "c", rejection); err != nil || redirect != "https://hydra.example/callback" {
		t.Fatalf("RejectConsent error = %v, redirect = %q", err, redirect)
	}
	if _, err := client.RejectLogout(context.Background(), "c", rejection); err != nil {
		t.Fatalf("RejectLogout error = %v", err)
	}
	if redirect, err := client.AcceptLogout(context.Background(), "c"); err != nil || redirect != "https://hydra.example/callback" {
		t.Fatalf("AcceptLogout error = %v, redirect = %q", err, redirect)
	}
}

func TestClient_ErrorPaths(t *testing.T) {
	t.Parallel()

	// 500 status
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server500.Close()
	baseURL500, _ := url.Parse(server500.URL)
	client500, _ := New(baseURL500, server500.Client(), "")
	if _, err := client500.GetLoginRequest(context.Background(), "c"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("500 error = %v, want ErrUpstream", err)
	}

	// Bad JSON
	serverBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer serverBadJSON.Close()
	baseURLBadJSON, _ := url.Parse(serverBadJSON.URL)
	clientBadJSON, _ := New(baseURLBadJSON, serverBadJSON.Client(), "")
	if _, err := clientBadJSON.GetLoginRequest(context.Background(), "c"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("bad json error = %v, want ErrUpstream", err)
	}

	// Network failure (server closed)
	serverClosed := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	baseURLClosed, _ := url.Parse(serverClosed.URL)
	clientClosed, _ := New(baseURLClosed, serverClosed.Client(), "")
	serverClosed.Close()

	if _, err := clientClosed.GetLoginRequest(context.Background(), "c"); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("network failure error = %v, want ErrUpstream", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
