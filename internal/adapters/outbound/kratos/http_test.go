package kratos

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestClient_ValidateSession(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/sessions/whoami" {
			t.Fatalf("request = %s %s, want GET /sessions/whoami", r.Method, r.URL.Path)
		}
		cookie, err := r.Cookie("ory_kratos_session")
		if err != nil || cookie.Value != "session-value" {
			t.Fatalf("session cookie = %#v, want session-value", cookie)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"active":true,"authenticator_assurance_level":"aal2","authentication_methods":[{"method":"oidc"},{"method":"totp"}],"identity":{"id":"operator-1"}}`)); err != nil {
			t.Errorf("write session response: %v", err)
		}
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	session, err := client.ValidateSession(context.Background(), ports.SessionCredentials{
		CookieName:  "ory_kratos_session",
		CookieValue: "session-value",
	})
	if err != nil {
		t.Fatalf("validate session: %v", err)
	}
	if session.Subject != "operator-1" || session.AAL != "aal2" {
		t.Fatalf("session = %#v, want operator-1/aal2", session)
	}
	if len(session.AMR) != 2 || session.AMR[1] != "totp" {
		t.Fatalf("amr = %#v, want oidc/totp", session.AMR)
	}
}

func TestClient_ValidateSessionMapsUnauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client, err := New(baseURL, server.Client())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	_, err = client.ValidateSession(context.Background(), ports.SessionCredentials{Token: "session-token"})
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
}
