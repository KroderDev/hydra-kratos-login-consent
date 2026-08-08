package kratos

import (
	"bytes"
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
		if _, err := w.Write([]byte(`{"active":true,"authenticator_assurance_level":"aal2","authentication_methods":[{"method":"oidc"},{"method":"totp"}],"identity":{"id":"operator-1","traits":{"email":"operator@example.com","name":{"given":"Operator"}},"metadata_public":{"role":"reader"},"metadata_admin":{"secret":"must-not-be-retained"},"credentials":{"password":{"identifiers":["operator@example.com"]}}},"raw_cookie":"must-not-be-retained"}`)); err != nil {
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
	if session.IdentityTraits["email"] != "operator@example.com" {
		t.Fatalf("identity traits = %#v, want sanitized traits", session.IdentityTraits)
	}
	if session.IdentityMetadataPublic["role"] != "reader" {
		t.Fatalf("identity metadata = %#v, want public metadata", session.IdentityMetadataPublic)
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal sanitized session: %v", err)
	}
	if bytes.Contains(encoded, []byte("must-not-be-retained")) {
		t.Fatalf("sanitized session retained restricted identity data: %s", encoded)
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

func TestClient_ValidateSessionRejectsMissingCredentialsWithoutRequest(t *testing.T) {
	t.Parallel()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
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
	if _, err := client.ValidateSession(context.Background(), ports.SessionCredentials{}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
	if calls != 0 {
		t.Fatalf("request count = %d, want 0", calls)
	}
}

func TestClient_ValidateSessionBearerAndInactiveResponses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer session-token" {
			t.Errorf("authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false,"identity":{"id":""}}`))
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
	if _, err := client.ValidateSession(context.Background(), ports.SessionCredentials{Token: "session-token"}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
}

func TestClient_ReadyMapsFailureToUpstream(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if r := w.Header(); r.Get("Content-Type") != "" {
			t.Errorf("unexpected content type: %q", r.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusServiceUnavailable)
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
	if err := client.Ready(context.Background()); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("error = %v, want upstream", err)
	}
}
