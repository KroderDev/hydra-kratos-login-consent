package application

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestService_StartLoginAndCompleteLogin(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{
		Challenge: "login-challenge",
		Client:    testClient(),
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2", AMR: []string{"oidc", "totp"}}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	handle := transactionFromRedirect(t, started.URL)
	if handle == "" {
		t.Fatal("login redirect did not contain a transaction")
	}
	if containsString(started.URL, "login-challenge") {
		t.Fatal("login challenge leaked into external UI redirect")
	}

	completed, err := service.CompleteLogin(context.Background(), handle, loginInputFromRedirect(t, started.URL, ports.SessionCredentials{
		CookieName:  "ory_kratos_session",
		CookieValue: "opaque-session",
	}))
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}
	if completed.URL != "https://hydra.example/oauth2/auth/callback" {
		t.Fatalf("redirect = %q, want Hydra redirect", completed.URL)
	}
	if hydra.loginAcceptance.Subject != "operator-1" {
		t.Fatalf("accepted subject = %q, want operator-1", hydra.loginAcceptance.Subject)
	}
	if hydra.loginAcceptance.ACR != "aal2" {
		t.Fatalf("accepted acr = %q, want aal2", hydra.loginAcceptance.ACR)
	}
}

func TestService_CompleteLoginRejectsInvalidAssurance(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal1"}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	completed, err := service.CompleteLogin(
		context.Background(),
		transactionFromRedirect(t, started.URL),
		loginInputFromRedirect(t, started.URL, ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"}),
	)
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}
	if completed.URL != "https://hydra.example/oauth2/auth/rejected" {
		t.Fatalf("redirect = %q, want rejection redirect", completed.URL)
	}
	if hydra.loginAcceptance.Subject != "" {
		t.Fatal("login was accepted despite insufficient assurance")
	}
	if hydra.loginRejection.Error != "access_denied" {
		t.Fatalf("rejection error = %q, want access_denied", hydra.loginRejection.Error)
	}
}

func TestService_CompleteLoginRejectsInvalidCSRF(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}

	started, err := service.StartLogin(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	input := loginInputFromRedirect(t, started.URL, ports.SessionCredentials{})
	input.CSRFToken = "wrong-csrf-token"
	if _, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), input); !errors.Is(err, domain.ErrInvalidCSRF) {
		t.Fatalf("completion error = %v, want invalid csrf", err)
	}
	if hydra.loginAcceptance.Subject != "" {
		t.Fatal("login was accepted with an invalid csrf token")
	}
}

func TestService_TransactionIsSingleUse(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	handle := transactionFromRedirect(t, started.URL)
	credentials := ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"}
	input := loginInputFromRedirect(t, started.URL, credentials)
	if _, err := service.CompleteLogin(context.Background(), handle, input); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	if _, err := service.CompleteLogin(context.Background(), handle, input); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("second completion error = %v, want replay error", err)
	}
}

func TestService_ExpiredTransactionIsRejected(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, now := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	started, err := service.StartLogin(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	*now = now.Add(6 * time.Minute)
	if _, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), ports.LoginInput{}); !errors.Is(err, domain.ErrExpiredTransaction) {
		t.Fatalf("completion error = %v, want expired transaction", err)
	}
}

func TestService_StartLoginRejectsUnknownClient(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{
		Challenge: "login-challenge",
		Client: domain.Client{
			ID:           "unknown-client",
			RedirectURIs: []string{"https://client.example/callback"},
		},
	}

	if _, err := service.StartLogin(context.Background(), "login-challenge"); !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("start login error = %v, want invalid client", err)
	}
}

func TestService_ConsentReducesScopesAndFiltersClaims(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "profile"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.consentDecision = ports.ConsentDecision{
		Allowed: true,
		Claims: domain.Claims{
			IDToken: map[string]any{
				"email": "operator@example.com",
				"role":  "operator",
			},
		},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge")
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	handle := transactionFromRedirect(t, started.URL)
	completed, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction: handle,
		CSRFToken:   queryValue(t, started.URL, "csrf"),
		Decision:    "accept",
		GrantScopes: []string{"openid"},
		Credentials: ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"},
	})
	if err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	if completed.URL != "https://hydra.example/oauth2/consent/callback" {
		t.Fatalf("redirect = %q, want Hydra redirect", completed.URL)
	}
	if len(hydra.consentAcceptance.GrantScopes) != 1 || hydra.consentAcceptance.GrantScopes[0] != "openid" {
		t.Fatalf("granted scopes = %#v, want [openid]", hydra.consentAcceptance.GrantScopes)
	}
	if got := hydra.consentAcceptance.Session.IDToken["email"]; got != "operator@example.com" {
		t.Fatalf("email claim = %#v, want operator@example.com", got)
	}
	if _, exists := hydra.consentAcceptance.Session.IDToken["role"]; exists {
		t.Fatal("role claim was not filtered by scope policy")
	}
}

func TestService_ConsentRejectsUnrequestedScope(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid"},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge")
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	result, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"),
		Decision:    "accept",
		GrantScopes: []string{"admin"},
	})
	if err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	if result.URL != "https://hydra.example/oauth2/consent/rejected" {
		t.Fatalf("redirect = %q, want rejection redirect", result.URL)
	}
	if hydra.consentRejection.Error != "access_denied" {
		t.Fatalf("rejection error = %q, want access_denied", hydra.consentRejection.Error)
	}
}

func TestService_LogoutRejectsUnallowlistedReturnURL(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.logout = domain.LogoutRequest{
		Challenge:             "logout-challenge",
		Client:                testClient(),
		PostLogoutRedirectURI: "https://evil.example/callback",
	}

	if _, err := service.Logout(context.Background(), "logout-challenge"); !errors.Is(err, domain.ErrInvalidRedirect) {
		t.Fatalf("logout error = %v, want invalid redirect", err)
	}
	if hydra.logoutAccepted {
		t.Fatal("logout was accepted with an unallowlisted return URL")
	}
}

func newTestService(t *testing.T) (*Service, *fakeHydra, *fakeKratos, *fakePolicy, *time.Time) {
	t.Helper()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cfg := testConfig()
	hydra := &fakeHydra{
		loginRedirect:   "https://hydra.example/oauth2/auth/callback",
		consentRedirect: "https://hydra.example/oauth2/consent/callback",
		logoutRedirect:  "https://hydra.example/oauth2/logout/callback",
	}
	kratos := &fakeKratos{}
	policy := &fakePolicy{}
	clock := func() time.Time { return now }
	service, err := NewService(cfg, Dependencies{
		Login:   hydra,
		Consent: hydra,
		Logout:  hydra,
		Kratos:  kratos,
		State:   state.NewMemoryStore(clock),
		Policy:  policy,
		Now:     clock,
	})
	if err != nil {
		t.Fatalf("create test service: %v", err)
	}
	return service, hydra, kratos, policy, &now
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
				AllowedIDTokenClaims: map[string][]string{
					"email": nil,
					"role":  {"profile"},
				},
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

func transactionFromRedirect(t *testing.T, redirect string) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return parsed.Query().Get("transaction")
}

func queryValue(t *testing.T, redirect, name string) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return parsed.Query().Get(name)
}

func loginInputFromRedirect(t *testing.T, redirect string, credentials ports.SessionCredentials) ports.LoginInput {
	t.Helper()
	return ports.LoginInput{CSRFToken: queryValue(t, redirect, "csrf"), Credentials: credentials}
}

func containsString(value, expected string) bool {
	return len(value) >= len(expected) && strings.Contains(value, expected)
}

type fakeHydra struct {
	login             domain.LoginRequest
	consent           domain.ConsentRequest
	logout            domain.LogoutRequest
	loginAcceptance   ports.LoginAcceptance
	loginRejection    ports.Rejection
	consentAcceptance ports.ConsentAcceptance
	consentRejection  ports.Rejection
	logoutAccepted    bool
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

func (f *fakeHydra) RejectLogin(_ context.Context, _ string, rejection ports.Rejection) (string, error) {
	f.loginRejection = rejection
	return "https://hydra.example/oauth2/auth/rejected", nil
}

func (f *fakeHydra) GetConsentRequest(context.Context, string) (domain.ConsentRequest, error) {
	return f.consent, nil
}

func (f *fakeHydra) AcceptConsent(_ context.Context, _ string, acceptance ports.ConsentAcceptance) (string, error) {
	f.consentAcceptance = acceptance
	return f.consentRedirect, nil
}

func (f *fakeHydra) RejectConsent(_ context.Context, _ string, rejection ports.Rejection) (string, error) {
	f.consentRejection = rejection
	return "https://hydra.example/oauth2/consent/rejected", nil
}

func (f *fakeHydra) GetLogoutRequest(context.Context, string) (domain.LogoutRequest, error) {
	return f.logout, nil
}

func (f *fakeHydra) AcceptLogout(context.Context, string) (string, error) {
	f.logoutAccepted = true
	return f.logoutRedirect, nil
}

func (f *fakeHydra) RejectLogout(context.Context, string, ports.Rejection) (string, error) {
	return "https://hydra.example/oauth2/logout/rejected", nil
}

type fakeKratos struct {
	session domain.Session
	err     error
}

func (f *fakeKratos) ValidateSession(context.Context, ports.SessionCredentials) (domain.Session, error) {
	if f.err != nil {
		return domain.Session{}, f.err
	}
	return f.session, nil
}

type fakePolicy struct {
	loginAllowed    bool
	consentDecision ports.ConsentDecision
	loginErr        error
	consentErr      error
}

func (f *fakePolicy) AuthorizeLogin(context.Context, string, string) (bool, error) {
	return f.loginAllowed, f.loginErr
}

func (f *fakePolicy) AuthorizeConsent(context.Context, string, string, []string) (ports.ConsentDecision, error) {
	return f.consentDecision, f.consentErr
}
