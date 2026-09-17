package application

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestService_StartLoginPreservesOIDCRequestContext(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, now := newTestService(t)
	service.cfg.OIDCACRMappings = map[string]string{"urn:example:aal3": "aal3"}
	hydra.login = domain.LoginRequest{
		Challenge:          "login-challenge",
		Client:             testClient(),
		RequestedACRValues: []string{"urn:example:aal3", "aal2"},
		Prompt:             "login",
		MaxAge:             int64Pointer(60),
	}

	started, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	parsed, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := parsed.Query()
	if query.Get("force_reauth") != "true" || query.Get("max_age") != "60" || query.Get("aal") != "aal3" {
		t.Fatalf("handoff query = %q, want reauthentication, max_age, and aal3", parsed.RawQuery)
	}
	transaction, err := service.state.Get(context.Background(), query.Get("transaction"))
	if err != nil {
		t.Fatalf("get transaction: %v", err)
	}
	if transaction.RequestedACR != "urn:example:aal3" || transaction.RequestedAAL != "aal3" || transaction.Prompt != "login" ||
		transaction.MaxAge == nil || *transaction.MaxAge != 60 || !transaction.StartedAt.Equal(*now) {
		t.Fatalf("transaction = %#v, want preserved OIDC context", transaction)
	}
}

func TestService_StartLoginResolvesRequestedAALWithoutACRValues(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{
		Challenge:    "login-challenge",
		Client:       testClient(),
		RequestedAAL: "aal2",
	}

	started, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	parsed, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := parsed.Query()
	if query.Get("aal") != "aal2" {
		t.Fatalf("handoff aal = %q, want aal2", query.Get("aal"))
	}
	transaction, err := service.state.Get(context.Background(), query.Get("transaction"))
	if err != nil {
		t.Fatalf("get transaction: %v", err)
	}
	if transaction.RequestedAAL != "aal2" || transaction.RequestedACR != "aal2" {
		t.Fatalf("transaction = %#v, want aal2 derived from requested AAL", transaction)
	}
}

func TestService_StartLoginRejectsUnresolvableACRValues(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{
		Challenge:          "login-challenge",
		Client:             testClient(),
		RequestedACRValues: []string{"urn:example:unsupported"},
	}

	result, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
	if !errors.Is(err, domain.ErrInvalidAssurance) {
		t.Fatalf("StartLogin error = %v, want invalid assurance", err)
	}
	if result.URL != "" || hydra.loginRejection.Error != "" {
		t.Fatalf("result/rejection = %#v/%#v, want no state or rejection", result, hydra.loginRejection)
	}
}

func TestService_StartLoginRejectsUnsupportedPromptAndSilentInteraction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		prompt        string
		wantErr       error
		wantRejection string
	}{
		{name: "unsupported prompt", prompt: "unknown", wantErr: domain.ErrInvalidPrompt},
		{name: "consent prompt", prompt: "consent"},
		{name: "combined login and consent prompt", prompt: "login consent"},
		{name: "select account prompt", prompt: "select_account"},
		{name: "prompt none", prompt: "none", wantRejection: "login_required"},
		{name: "none cannot be combined", prompt: "none login", wantErr: domain.ErrInvalidPrompt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service, hydra, _, _, _ := newTestService(t)
			hydra.login = domain.LoginRequest{
				Challenge: "login-challenge",
				Client:    testClient(),
				Prompt:    tt.prompt,
			}
			result, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("StartLogin error = %v, want %v", err, tt.wantErr)
				}
				if hydra.loginRejection.Error != "" {
					t.Fatalf("unsupported prompt caused Hydra rejection = %#v", hydra.loginRejection)
				}
				return
			}
			if err != nil {
				t.Fatalf("StartLogin: %v", err)
			}
			if result.URL == "" || hydra.loginRejection.Error != tt.wantRejection {
				t.Fatalf("result/rejection = %#v/%#v, want %q", result, hydra.loginRejection, tt.wantRejection)
			}
		})
	}
}

func TestService_StartLoginUsesRequestedACRForAcceptance(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	service.cfg.RequiredAAL = "aal1"
	service.cfg.OIDCACRMappings = map[string]string{"urn:example:aal2": "aal2"}
	hydra.login = domain.LoginRequest{
		Challenge:          "login-challenge",
		Client:             testClient(),
		RequestedACRValues: []string{"urn:example:aal2"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2", AMR: []string{"password"}}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	_, err = service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{CookieValue: "opaque"}))
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if hydra.loginAcceptance.ACR != "urn:example:aal2" {
		t.Fatalf("accepted acr = %q, want requested custom ACR", hydra.loginAcceptance.ACR)
	}
}

func TestService_StartLoginRejectsNegativeMaxAge(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	negative := int64(-1)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient(), MaxAge: &negative}
	if _, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{}); !errors.Is(err, domain.ErrInvalidAssurance) {
		t.Fatalf("StartLogin error = %v, want invalid assurance", err)
	}
}

func TestService_CompleteLoginRejectsStaleFreshness(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, _, now := newTestService(t)
	service.cfg.RequiredAAL = "aal1"
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient(), Prompt: "login"}
	kratos.session = domain.Session{
		Subject:         "operator-1",
		AAL:             "aal1",
		AuthenticatedAt: now.Add(-time.Minute),
	}
	started, err := service.StartLogin(context.Background(), hydra.login.Challenge, ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	result, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{CookieValue: "opaque"}))
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if result.URL == "" || hydra.loginRejection.Error != "login_required" {
		t.Fatalf("result/rejection = %#v/%#v, want login_required", result, hydra.loginRejection)
	}
	if hydra.loginAcceptance.Subject != "" {
		t.Fatal("stale login was accepted")
	}
}

func TestValidateLoginFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 10, 0, time.UTC)
	start := now.Add(-5 * time.Second)
	tests := []struct {
		name        string
		transaction domain.Transaction
		session     domain.Session
		wantErr     bool
	}{
		{
			name:        "no requirement",
			transaction: domain.Transaction{StartedAt: start},
			session:     domain.Session{},
		},
		{
			name:        "missing authentication timestamp",
			transaction: domain.Transaction{Prompt: "login", StartedAt: start},
			wantErr:     true,
		},
		{
			name:        "prompt login after start",
			transaction: domain.Transaction{Prompt: "login", StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now},
		},
		{
			name:        "prompt login before start",
			transaction: domain.Transaction{Prompt: "login", StartedAt: start},
			session:     domain.Session{AuthenticatedAt: start},
			wantErr:     true,
		},
		{
			name:        "combined prompt login before start",
			transaction: domain.Transaction{Prompt: "login consent", StartedAt: start},
			session:     domain.Session{AuthenticatedAt: start},
			wantErr:     true,
		},
		{
			name:        "zero max age requires reauthentication",
			transaction: domain.Transaction{MaxAge: int64Pointer(0), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: start},
			wantErr:     true,
		},
		{
			name:        "zero max age after reauthentication",
			transaction: domain.Transaction{MaxAge: int64Pointer(0), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now},
		},
		{
			name:        "max age within limit",
			transaction: domain.Transaction{MaxAge: int64Pointer(10), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now.Add(-10 * time.Second)},
		},
		{
			name:        "fractional age rounds up",
			transaction: domain.Transaction{MaxAge: int64Pointer(10), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now.Add(-10*time.Second - time.Nanosecond)},
			wantErr:     true,
		},
		{
			name:        "future timestamp",
			transaction: domain.Transaction{MaxAge: int64Pointer(60), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now.Add(time.Second)},
			wantErr:     true,
		},
		{
			name:        "negative max age",
			transaction: domain.Transaction{MaxAge: int64Pointer(-1), StartedAt: start},
			session:     domain.Session{AuthenticatedAt: now},
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateLoginFreshness(tt.transaction, tt.session, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateLoginFreshness error = %v, want error: %t", err, tt.wantErr)
			}
		})
	}
}

func TestService_StartConsentValidatesPromptBeforeCreatingState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		prompt        string
		skip          bool
		skipConsent   bool
		wantErr       error
		wantRejection string
	}{
		{name: "login prompt already handled", prompt: "login"},
		{name: "consent prompt", prompt: "consent"},
		{name: "combined login and consent prompt", prompt: "login consent"},
		{name: "silent consent", prompt: "none", wantRejection: "consent_required"},
		{name: "silent consent with hydra skip", prompt: "none", skip: true},
		{name: "silent consent with client skip", prompt: "none", skipConsent: true},
		{name: "invalid silent combination", prompt: "none login", wantErr: domain.ErrInvalidPrompt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service, hydra, _, _, _ := newTestService(t)
			if tt.skipConsent {
				client := service.cfg.Clients["example-client"]
				client.SkipConsent = true
				service.cfg.Clients["example-client"] = client
			}
			hydra.consent = domain.ConsentRequest{
				Challenge:       "consent-challenge",
				Client:          testClient(),
				Subject:         "operator-1",
				RequestedScopes: []string{"openid"},
				Skip:            tt.skip,
				Prompt:          tt.prompt,
			}
			result, err := service.StartConsent(context.Background(), hydra.consent.Challenge, ports.ConsentStartInput{})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("StartConsent error = %v, want %v", err, tt.wantErr)
				}
				if result.URL != "" || hydra.consentRejection.Error != "" {
					t.Fatalf("unsupported prompt result/rejection = %#v/%#v", result, hydra.consentRejection)
				}
				return
			}
			if err != nil {
				t.Fatalf("StartConsent: %v", err)
			}
			if result.URL == "" || hydra.consentRejection.Error != tt.wantRejection {
				t.Fatalf("result/rejection = %#v/%#v, want %q", result, hydra.consentRejection, tt.wantRejection)
			}
		})
	}
}

func TestService_StartConsentMarksSkippedConsent(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid"},
		Skip:            true,
	}

	result, err := service.StartConsent(context.Background(), hydra.consent.Challenge, ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("StartConsent: %v", err)
	}
	if got := queryValue(t, result.URL, "skip_consent"); got != "true" {
		t.Fatalf("skip_consent = %q, want true", got)
	}
}

func TestParsePrompt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     string
		want      promptSet
		wantError bool
	}{
		{name: "empty", value: "", want: promptSet{}},
		{name: "all interactive prompts", value: "login consent select_account", want: promptSet{login: true, consent: true, selectAccount: true}},
		{name: "duplicate", value: "login login", wantError: true},
		{name: "none combination", value: "none consent", wantError: true},
		{name: "unknown", value: "account", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePrompt(tt.value)
			if (err != nil) != tt.wantError {
				t.Fatalf("parsePrompt(%q) error = %v, want error: %t", tt.value, err, tt.wantError)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parsePrompt(%q) = %#v, want %#v", tt.value, got, tt.want)
			}
		})
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}
