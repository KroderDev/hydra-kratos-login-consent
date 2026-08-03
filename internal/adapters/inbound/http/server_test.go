package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/application"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestServer_LoginHandoffDoesNotExposeChallenge(t *testing.T) {
	t.Parallel()

	handler, hydra, _, _ := newTestHandler(t)
	hydra.login = domain.LoginRequest{
		Challenge: "login-secret",
		Client:    testClient(),
	}

	request := httptest.NewRequest(http.MethodGet, "/login?login_challenge=login-secret", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("login response did not contain a Location header")
	}
	if strings.Contains(location, "login-secret") {
		t.Fatal("login challenge was exposed to the external UI")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse external UI location: %v", err)
	}
	if parsed.Query().Get("transaction") == "" {
		t.Fatal("external UI location did not contain an opaque transaction")
	}
	if parsed.Query().Get("csrf") == "" {
		t.Fatal("external UI location did not contain a csrf token")
	}
}

func TestRememberOptionsAcceptsHTMLCheckboxValues(t *testing.T) {
	t.Parallel()

	remember, rememberFor, err := rememberOptions("on", "3600")
	if err != nil {
		t.Fatalf("rememberOptions: %v", err)
	}
	if !remember || rememberFor != 3600 {
		t.Fatalf("remember options = %t/%d, want true/3600", remember, rememberFor)
	}
}

func TestServer_LoginCallbackUsesKratosCookie(t *testing.T) {
	t.Parallel()

	handler, hydra, kratos, policy := newTestHandler(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	startRequest := httptest.NewRequest(http.MethodGet, "/login?login_challenge=login-challenge", nil)
	startRecorder := httptest.NewRecorder()
	handler.ServeHTTP(startRecorder, startRequest)
	if startRecorder.Code != http.StatusFound {
		t.Fatalf("start status = %d, want %d", startRecorder.Code, http.StatusFound)
	}
	parsed, err := url.Parse(startRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse start location: %v", err)
	}
	transaction := parsed.Query().Get("transaction")
	csrfToken := parsed.Query().Get("csrf")

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/login/callback?transaction="+url.QueryEscape(transaction)+"&csrf="+url.QueryEscape(csrfToken),
		nil,
	)
	callbackRequest.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "opaque-session"})
	callbackRecorder := httptest.NewRecorder()
	handler.ServeHTTP(callbackRecorder, callbackRequest)

	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d", callbackRecorder.Code, http.StatusFound)
	}
	if callbackRecorder.Header().Get("Location") != hydra.loginRedirect {
		t.Fatalf("callback location = %q, want %q", callbackRecorder.Header().Get("Location"), hydra.loginRedirect)
	}
	if kratos.credentials.CookieValue != "opaque-session" {
		t.Fatalf("Kratos cookie = %q, want opaque-session", kratos.credentials.CookieValue)
	}
}

func TestServer_ConsentRequiresExternalOrigin(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("transaction=opaque&decision=accept"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://attacker.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestServer_RejectsDuplicateChallengeQuery(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/login?login_challenge=one&login_challenge=two", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestServer_HealthResponseIncludesSecurityHeaders(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("health response is cacheable")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing content type protection header")
	}
}

func newTestHandler(t *testing.T) (http.Handler, *fakeHydra, *fakeKratos, *fakePolicy) {
	t.Helper()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	cfg := testConfig()
	hydra := &fakeHydra{
		loginRedirect:   "https://hydra.example/oauth2/auth/callback",
		consentRedirect: "https://hydra.example/oauth2/consent/callback",
		logoutRedirect:  "https://hydra.example/oauth2/logout/callback",
	}
	kratos := &fakeKratos{}
	policy := &fakePolicy{}
	service, err := application.NewService(cfg, application.Dependencies{
		Login:   hydra,
		Consent: hydra,
		Logout:  hydra,
		Kratos:  kratos,
		State:   state.NewMemoryStore(clock),
		Policy:  policy,
		Now:     clock,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	api, err := New(service, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("create api: %v", err)
	}
	return api.Handler(), hydra, kratos, policy
}

type fakeHydra struct {
	login           domain.LoginRequest
	loginRedirect   string
	consentRedirect string
	logoutRedirect  string
}

func (f *fakeHydra) GetLoginRequest(context.Context, string) (domain.LoginRequest, error) {
	return f.login, nil
}

func (f *fakeHydra) AcceptLogin(context.Context, string, ports.LoginAcceptance) (string, error) {
	return f.loginRedirect, nil
}

func (f *fakeHydra) RejectLogin(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/auth/rejected", nil
}

func (f *fakeHydra) GetConsentRequest(context.Context, string) (domain.ConsentRequest, error) {
	return domain.ConsentRequest{}, nil
}

func (f *fakeHydra) AcceptConsent(context.Context, string, ports.ConsentAcceptance) (string, error) {
	return f.consentRedirect, nil
}

func (f *fakeHydra) RejectConsent(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/consent/rejected", nil
}

func (f *fakeHydra) GetLogoutRequest(context.Context, string) (domain.LogoutRequest, error) {
	return domain.LogoutRequest{}, nil
}

func (f *fakeHydra) AcceptLogout(context.Context, string) (string, error) {
	return f.logoutRedirect, nil
}

func (f *fakeHydra) RejectLogout(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/logout/rejected", nil
}

type fakeKratos struct {
	session     domain.Session
	credentials ports.SessionCredentials
}

func (f *fakeKratos) ValidateSession(_ context.Context, credentials ports.SessionCredentials) (domain.Session, error) {
	f.credentials = credentials
	return f.session, nil
}

type fakePolicy struct {
	loginAllowed bool
}

func (f *fakePolicy) AuthorizeLogin(context.Context, string, string) (bool, error) {
	return f.loginAllowed, nil
}

func (f *fakePolicy) AuthorizeConsent(context.Context, string, string, []string) (ports.ConsentDecision, error) {
	return ports.ConsentDecision{}, nil
}

func testConfig() config.Config {
	providerURL, _ := url.Parse("https://provider.example")
	uiURL, _ := url.Parse("https://ui.example/login")
	hydraURL, _ := url.Parse("https://hydra.example")
	kratosURL, _ := url.Parse("https://kratos.example")
	return config.Config{
		ListenAddress:       ":8080",
		ProviderURL:         providerURL,
		ExternalUIURL:       uiURL,
		HydraAdminURL:       hydraURL,
		HydraPublicURL:      hydraURL,
		KratosPublicURL:     kratosURL,
		KratosSessionCookie: "ory_kratos_session",
		RequiredAAL:         "aal2",
		TransactionTTL:      5 * time.Minute,
		Clients: map[string]config.Client{
			"example-client": {
				ID:                         "example-client",
				AllowedRedirectURIs:        []string{"https://client.example/callback"},
				AllowedPostLogoutRedirects: []string{"https://client.example/logout"},
				AllowedScopes:              []string{"openid", "profile"},
			},
		},
	}
}

func testClient() domain.Client {
	return domain.Client{
		ID:           "example-client",
		RedirectURIs: []string{"https://client.example/callback"},
	}
}
