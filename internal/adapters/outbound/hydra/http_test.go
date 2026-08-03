package hydra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
