package http

import (
	"context"
	"errors"
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

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login?login_challenge=login-secret", nil)
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

func TestRememberOptionsRejectsUnboundedOrInconsistentValues(t *testing.T) {
	t.Parallel()

	for name, values := range map[string][2]string{
		"duration without remember": {"false", "60"},
		"duration above maximum":    {"true", "86401"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := rememberOptions(values[0], values[1]); !errors.Is(err, domain.ErrInvalidRemember) {
				t.Fatalf("rememberOptions error = %v, want invalid remember", err)
			}
		})
	}
}

func TestServer_LoginCallbackUsesKratosCookie(t *testing.T) {
	t.Parallel()

	handler, hydra, kratos, policy := newTestHandler(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	startRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login?login_challenge=login-challenge", nil)
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
	providerState := startRecorder.Result().Cookies()[0]

	callbackRequest := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/login/callback?transaction="+url.QueryEscape(transaction)+"&csrf="+url.QueryEscape(csrfToken),
		nil,
	)
	callbackRequest.AddCookie(&http.Cookie{
		Name:     "ory_kratos_session",
		Value:    "opaque-session",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	callbackRequest.AddCookie(providerState)
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

func TestServer_LoginCallbackRequiresBrowserStateCookie(t *testing.T) {
	t.Parallel()

	handler, hydra, kratos, policy := newTestHandler(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	startRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login?login_challenge=login-challenge", nil)
	startRecorder := httptest.NewRecorder()
	handler.ServeHTTP(startRecorder, startRequest)
	parsed, err := url.Parse(startRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse start location: %v", err)
	}
	callbackRequest := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/login/callback?transaction="+url.QueryEscape(parsed.Query().Get("transaction"))+"&csrf="+url.QueryEscape(parsed.Query().Get("csrf")),
		nil,
	)
	callbackRequest.AddCookie(&http.Cookie{
		Name:     "ory_kratos_session",
		Value:    "opaque-session",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	callbackRecorder := httptest.NewRecorder()
	handler.ServeHTTP(callbackRecorder, callbackRequest)

	if callbackRecorder.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want %d", callbackRecorder.Code, http.StatusBadRequest)
	}
	if hydra.loginAcceptance.Subject != "" {
		t.Fatal("login was accepted without the browser-state cookie")
	}
}

func TestServer_ConsentRequiresExternalOrigin(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader("transaction=opaque&decision=accept"))
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
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login?login_challenge=one&login_challenge=two", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestServer_HealthResponseIncludesSecurityHeaders(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
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

func TestServer_ConsentSubmitForwardsDecisionAndCookie(t *testing.T) {
	t.Parallel()

	handler, hydra, kratos, policy := newTestHandler(t)
	hydra.consent = domain.ConsentRequest{
		Challenge: "consent-challenge", Client: testClient(), Subject: "operator-1",
		RequestedScopes: []string{"openid", "profile"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.consentDecision = ports.ConsentDecision{Allowed: true, GrantedScopes: []string{"openid", "profile"}}

	start := httptest.NewRecorder()
	startRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/consent?consent_challenge=consent-challenge", nil)
	handler.ServeHTTP(start, startRequest)
	if start.Code != http.StatusFound {
		t.Fatalf("start status = %d, want found", start.Code)
	}
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	stateCookie := start.Result().Cookies()[0]
	form := url.Values{
		"transaction": {location.Query().Get("transaction")}, "csrf": {location.Query().Get("csrf")},
		"decision": {" ACCEPT "}, "grant_scope": {"openid profile"}, "remember": {"false"},
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://ui.example")
	request.AddCookie(stateCookie)
	request.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "opaque-session", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != hydra.consentRedirect {
		t.Fatalf("submit status/location = %d/%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if kratos.credentials.CookieValue != "opaque-session" {
		t.Fatalf("Kratos cookie = %q, want opaque-session", kratos.credentials.CookieValue)
	}
	if len(hydra.consentAcceptance.GrantScopes) != 2 {
		t.Fatalf("grant scopes = %#v, want two scopes", hydra.consentAcceptance.GrantScopes)
	}
}

func TestServer_LogoutSubmitAndReady(t *testing.T) {
	t.Parallel()

	handler, hydra, _, _ := newTestHandler(t)
	hydra.logout = domain.LogoutRequest{Challenge: "logout-challenge", Client: testClient()}
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/logout?logout_challenge=logout-challenge", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("logout start status = %d, want found", start.Code)
	}
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse logout location: %v", err)
	}
	form := url.Values{"transaction": {location.Query().Get("transaction")}, "csrf": {location.Query().Get("csrf")}}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://ui.example")
	request.AddCookie(start.Result().Cookies()[0])
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != hydra.logoutRedirect {
		t.Fatalf("logout submit status/location = %d/%q", recorder.Code, recorder.Header().Get("Location"))
	}
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ready"`) {
		t.Fatalf("ready response = %d/%q", ready.Code, ready.Body.String())
	}
}

func TestStatusForErrorAndPublicError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		status int
		public string
	}{
		{name: "bad request", err: domain.ErrInvalidForm, status: http.StatusBadRequest, public: "invalid_request"},
		{name: "forbidden", err: domain.ErrPolicyDenied, status: http.StatusForbidden, public: "access_denied"},
		{name: "unauthorized", err: domain.ErrUnauthenticated, status: http.StatusUnauthorized, public: "login_required"},
		{name: "upstream", err: domain.ErrUpstream, status: http.StatusBadGateway, public: "temporarily_unavailable"},
		{name: "rate limited", err: domain.ErrRateLimited, status: http.StatusTooManyRequests, public: "rate_limited"},
		{name: "unknown", err: errors.New("unexpected"), status: http.StatusInternalServerError, public: "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := statusForError(tt.err); got != tt.status {
				t.Fatalf("statusForError = %d, want %d", got, tt.status)
			}
			if got := publicError(tt.status); got != tt.public {
				t.Fatalf("publicError = %q, want %q", got, tt.public)
			}
		})
	}
}

func TestValidateRedirectTargetRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
	}{
		{name: "relative", target: "/relative"},
		{name: "non-http scheme", target: "ftp://example.com/path"},
		{name: "userinfo", target: "https://user@example.com/path"},
		{name: "fragment", target: "https://example.com/path#fragment"},
		{name: "header injection", target: "https://example.com/path\r\nX-Test: injected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateRedirectTarget(tt.target); !errors.Is(err, domain.ErrInvalidRedirect) {
				t.Fatalf("validateRedirectTarget(%q) = %v, want invalid redirect", tt.target, err)
			}
		})
	}
}

func TestRequestIDMiddlewarePreservesValidAndReplacesInvalidIDs(t *testing.T) {
	t.Parallel()

	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "valid", input: "request-123", want: "request-123"},
		{name: "empty", input: "", want: ""},
		{name: "control character", input: "bad\nvalue", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var contextID string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contextID = requestID(r.Context())
				w.WriteHeader(http.StatusNoContent)
			})
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			request.Header.Set("X-Request-ID", tt.input)
			recorder := httptest.NewRecorder()
			server.requestID(next).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want no content", recorder.Code)
			}
			got := recorder.Header().Get("X-Request-ID")
			if tt.want != "" && got != tt.want {
				t.Fatalf("response request ID = %q, want %q", got, tt.want)
			}
			if tt.want == "" && !validRequestID(got) {
				t.Fatalf("generated request ID = %q is invalid", got)
			}
			if contextID != got {
				t.Fatalf("context request ID = %q, response = %q", contextID, got)
			}
		})
	}
}

func TestSetBrowserStateCookieUsesSecureAttributesForHTTPS(t *testing.T) {
	t.Parallel()

	server := &Server{cfg: testConfig()}
	recorder := httptest.NewRecorder()
	server.setBrowserStateCookie(recorder, "state", "opaque-state")
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" {
		t.Fatalf("cookie attributes = %#v", cookie)
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
	login             domain.LoginRequest
	consent           domain.ConsentRequest
	logout            domain.LogoutRequest
	loginAcceptance   ports.LoginAcceptance
	consentAcceptance ports.ConsentAcceptance
	loginRedirect     string
	consentRedirect   string
	logoutRedirect    string
}

func (f *fakeHydra) GetLoginRequest(context.Context, string) (domain.LoginRequest, error) {
	return f.login, nil
}

func (f *fakeHydra) AcceptLogin(_ context.Context, _ string, acceptance ports.LoginAcceptance) (string, error) {
	f.loginAcceptance = acceptance
	return f.loginRedirect, nil
}

func (f *fakeHydra) RejectLogin(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/auth/rejected", nil
}

func (f *fakeHydra) GetConsentRequest(context.Context, string) (domain.ConsentRequest, error) {
	return f.consent, nil
}

func (f *fakeHydra) AcceptConsent(_ context.Context, _ string, acceptance ports.ConsentAcceptance) (string, error) {
	f.consentAcceptance = acceptance
	return f.consentRedirect, nil
}

func (f *fakeHydra) RejectConsent(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/consent/rejected", nil
}

func (f *fakeHydra) GetLogoutRequest(context.Context, string) (domain.LogoutRequest, error) {
	return f.logout, nil
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
	loginAllowed    bool
	consentDecision ports.ConsentDecision
}

func (f *fakePolicy) AuthorizeLogin(context.Context, ports.PolicyInput) (bool, error) {
	return f.loginAllowed, nil
}

func (f *fakePolicy) AuthorizeConsent(context.Context, ports.PolicyInput) (ports.ConsentDecision, error) {
	return f.consentDecision, nil
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
