package application

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
	coreconfig "github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
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

	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
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

	completed, err := service.CompleteLogin(context.Background(), handle, loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{
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
	if policy.loginInput.AAL != "aal2" || !reflect.DeepEqual(policy.loginInput.AMR, []string{"oidc", "totp"}) {
		t.Fatalf("login policy input = %#v, want aal2 and oidc/totp", policy.loginInput)
	}
}

func TestService_CompleteLoginRejectsInvalidAssurance(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal1"}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	completed, err := service.CompleteLogin(
		context.Background(),
		transactionFromRedirect(t, started.URL),
		loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"}),
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

func TestService_CompleteLoginRejectsKratosFailure(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.err = errors.New("kratos unavailable")
	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	result, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{CookieValue: "opaque"}))
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}
	if result.URL != "https://hydra.example/oauth2/auth/rejected" || hydra.loginRejection.Error != "access_denied" {
		t.Fatalf("failure result = %#v, rejection = %#v", result, hydra.loginRejection)
	}
}

func TestService_StartLoginRejectsHydraChallengeMismatch(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "different-challenge", Client: testClient()}
	if _, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{}); !errors.Is(err, domain.ErrInvalidChallenge) {
		t.Fatalf("error = %v, want invalid challenge", err)
	}
}

func TestValidateChallenge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     string
		maxLength int
		want      error
	}{
		{
			name:      "empty",
			value:     "",
			maxLength: coreconfig.DefaultMaxChallengeLength,
			want:      domain.ErrInvalidChallenge,
		},
		{
			name:      "carriage return",
			value:     "challenge\r",
			maxLength: coreconfig.DefaultMaxChallengeLength,
			want:      domain.ErrInvalidChallenge,
		},
		{
			name:      "newline",
			value:     "challenge\n",
			maxLength: coreconfig.DefaultMaxChallengeLength,
			want:      domain.ErrInvalidChallenge,
		},
		{
			name:      "oversized",
			value:     strings.Repeat("a", coreconfig.DefaultMaxChallengeLength+1),
			maxLength: coreconfig.DefaultMaxChallengeLength,
			want:      domain.ErrInvalidChallenge,
		},
		{
			name:      "maximum length",
			value:     strings.Repeat("a", coreconfig.DefaultMaxChallengeLength),
			maxLength: coreconfig.DefaultMaxChallengeLength,
		},
		{
			name:      "configured length",
			value:     strings.Repeat("a", coreconfig.DefaultMaxChallengeLength+1),
			maxLength: coreconfig.DefaultMaxChallengeLength + 1,
		},
		{
			name:      "valid",
			value:     "login-challenge",
			maxLength: coreconfig.DefaultMaxChallengeLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateChallenge(tt.value, tt.maxLength); !errors.Is(err, tt.want) {
				t.Fatalf("validateChallenge(%q) error = %v, want %v", tt.value, err, tt.want)
			}
		})
	}
}

func TestService_CompleteLoginRejectsInvalidCSRF(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	input := loginInputFromRedirect(t, started.URL, started.BrowserState, ports.SessionCredentials{})
	input.CSRFToken = "wrong-csrf-token"
	if _, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), input); !errors.Is(err, domain.ErrInvalidCSRF) {
		t.Fatalf("completion error = %v, want invalid csrf", err)
	}
	if hydra.loginAcceptance.Subject != "" {
		t.Fatal("login was accepted with an invalid csrf token")
	}
	input.CSRFToken = queryValue(t, started.URL, "csrf")
	if _, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), input); err != nil {
		t.Fatalf("valid completion after invalid csrf: %v", err)
	}
}

func TestService_CompleteLoginRejectsUnboundBrowserState(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	input := loginInputFromRedirect(t, started.URL, "different-browser-state", ports.SessionCredentials{})
	if _, err := service.CompleteLogin(context.Background(), transactionFromRedirect(t, started.URL), input); !errors.Is(err, domain.ErrInvalidBrowserState) {
		t.Fatalf("completion error = %v, want invalid browser state", err)
	}
}

func TestService_CompleteConsentInvalidCSRFDoesNotConsume(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.consentDecision = ports.ConsentDecision{Allowed: true, GrantedScopes: []string{"openid"}}
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	input := ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    "wrong-csrf",
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid"},
		Credentials:  ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"},
	}
	if _, err := service.CompleteConsent(context.Background(), input); !errors.Is(err, domain.ErrInvalidCSRF) {
		t.Fatalf("invalid csrf error = %v, want invalid csrf", err)
	}
	input.CSRFToken = queryValue(t, started.URL, "csrf")
	if _, err := service.CompleteConsent(context.Background(), input); err != nil {
		t.Fatalf("valid consent after invalid csrf: %v", err)
	}
}

func TestService_TransactionIsSingleUse(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.login = domain.LoginRequest{Challenge: "login-challenge", Client: testClient()}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.loginAllowed = true

	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	handle := transactionFromRedirect(t, started.URL)
	credentials := ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"}
	input := loginInputFromRedirect(t, started.URL, started.BrowserState, credentials)
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
	started, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
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

	if _, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{}); !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("start login error = %v, want invalid client", err)
	}
}

func TestService_ConsentReducesScopesAndFiltersClaims(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge:         "consent-challenge",
		Client:            testClient(),
		Subject:           "operator-1",
		RequestedScopes:   []string{"openid", "profile"},
		RequestedAudience: []string{"api"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2", AMR: []string{"pwd", "totp"}}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:          true,
		GrantedScopes:    []string{"openid"},
		GrantedAudiences: []string{"api"},
		Claims: domain.Claims{
			IDToken: map[string]any{
				"email": "operator@example.com",
				"role":  "operator",
			},
			AccessToken: map[string]any{
				"api_role": "reader",
				"secret":   "not-allowlisted",
			},
		},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	handle := transactionFromRedirect(t, started.URL)
	completed, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  handle,
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid"},
		Credentials:  ports.SessionCredentials{CookieName: "ory_kratos_session", CookieValue: "opaque-session"},
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
	if got := hydra.consentAcceptance.Session.AccessToken["api_role"]; got != "reader" {
		t.Fatalf("api_role claim = %#v, want reader", got)
	}
	if _, exists := hydra.consentAcceptance.Session.AccessToken["secret"]; exists {
		t.Fatal("unallowlisted access-token claim was not filtered")
	}
	if !reflect.DeepEqual(policy.consentInput.RequestedScopes, []string{"openid", "profile"}) ||
		!reflect.DeepEqual(policy.consentInput.GrantedScopes, []string{"openid"}) ||
		!reflect.DeepEqual(policy.consentInput.RequestedAudiences, []string{"api"}) ||
		policy.consentInput.AAL != "aal2" || !reflect.DeepEqual(policy.consentInput.AMR, []string{"pwd", "totp"}) {
		t.Fatalf("consent policy input = %#v", policy.consentInput)
	}
}

func TestService_DerivesIdentityClaimsAfterPolicyApproval(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "profile", "email"}
	client.AllowedIDTokenClaims = map[string][]string{
		"email":          nil,
		"email_verified": {"email"},
		"name":           {"profile"},
		"picture":        {"profile"},
	}
	client.AllowedAccessTokenClaims = map[string][]string{"api_role": {"openid"}, "name": {"profile"}}
	service.cfg.Clients["example-client"] = client
	service.cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{
		"email": {
			Source: "/traits/email",
			Type:   "string",
			Format: "email",
		},
		"email_verified": {
			Source: "/traits/email_verified",
			Type:   "boolean",
		},
		"name": {
			Sources:   []string{"/traits/name/given", "/traits/name/family"},
			Transform: identity.TransformJoinSpace,
			Type:      "string",
		},
		"picture": {
			Source: "/metadata_public/picture",
			Type:   "string",
			Format: "uri",
		},
	}
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "profile", "email"},
	}
	kratos.session = domain.Session{
		Subject: "operator-1",
		AAL:     "aal2",
		IdentityTraits: map[string]any{
			"email": "identity@example.com",
			"name":  map[string]any{"given": "Identity", "family": "User"},
		},
		IdentityMetadataPublic: map[string]any{"picture": "https://images.example/avatar.png"},
	}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:       true,
		GrantedScopes: []string{"openid", "profile", "email"},
		Claims:        domain.Claims{IDToken: map[string]any{"email": "policy@example.com", "name": "policy name"}, AccessToken: map[string]any{"api_role": "reader"}},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	_, err = service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid", "profile", "email"},
		Credentials:  ports.SessionCredentials{CookieValue: "opaque-session"},
	})
	if err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	idToken := hydra.consentAcceptance.Session.IDToken
	if idToken["email"] != "identity@example.com" || idToken["name"] != "Identity User" {
		t.Fatalf("identity claims = %#v, want mapped values to win over policy", idToken)
	}
	if idToken["picture"] != "https://images.example/avatar.png" {
		t.Fatalf("picture claim = %#v, want mapped HTTPS URL", idToken["picture"])
	}
	if _, ok := idToken["email_verified"]; ok {
		t.Fatal("email_verified was inferred without a mapped source")
	}
	if got := hydra.consentAcceptance.Session.AccessToken["api_role"]; got != "reader" {
		t.Fatalf("policy access claim = %#v, want reader", got)
	}
	if got := hydra.consentAcceptance.Session.AccessToken["name"]; got != "Identity User" {
		t.Fatalf("explicitly allowlisted identity access claim = %#v, want Identity User", got)
	}
	if _, ok := hydra.consentAcceptance.Session.AccessToken["email"]; ok {
		t.Fatal("identity email was copied to the access token without an allowlist entry")
	}
}

func TestService_IdentityClaimsRequireEffectiveStandardScopes(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "profile", "email"}
	client.AllowedIDTokenClaims = map[string][]string{"email": nil, "name": nil}
	service.cfg.Clients["example-client"] = client
	service.cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{
		"email": {Source: "/traits/email", Type: "string", Format: "email"},
		"name":  {Source: "/traits/name", Type: "string"},
	}
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "profile", "email"},
	}
	kratos.session = domain.Session{
		Subject:        "operator-1",
		AAL:            "aal2",
		IdentityTraits: map[string]any{"email": "operator@example.com", "name": "Operator"},
	}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:       true,
		GrantedScopes: []string{"openid"},
	}
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	if _, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"), BrowserState: started.BrowserState,
		Decision: "accept", GrantScopes: []string{"openid"},
		Credentials: ports.SessionCredentials{CookieValue: "opaque-session"},
	}); err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	if len(hydra.consentAcceptance.Session.IDToken) != 0 {
		t.Fatalf("claims = %#v, want no email/profile claims without their scopes", hydra.consentAcceptance.Session.IDToken)
	}
}

func TestService_DoesNotDeriveIdentityClaimsWhenPolicyDenies(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "email"}
	client.AllowedIDTokenClaims = map[string][]string{"email": nil}
	service.cfg.Clients["example-client"] = client
	service.cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{
		"email": {Source: "/traits/email", Type: "string", Format: "email"},
	}
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "email"},
	}
	kratos.session = domain.Session{
		Subject:        "operator-1",
		AAL:            "aal2",
		IdentityTraits: map[string]any{"email": "operator@example.com"},
	}
	policy.consentDecision = ports.ConsentDecision{Allowed: false}
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	if _, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"), BrowserState: started.BrowserState,
		Decision: "accept", GrantScopes: []string{"openid", "email"},
		Credentials: ports.SessionCredentials{CookieValue: "opaque-session"},
	}); err != nil {
		t.Fatalf("complete denied consent: %v", err)
	}
	if hydra.consentAcceptance.Session.IDToken != nil {
		t.Fatalf("denied consent accepted claims: %#v", hydra.consentAcceptance.Session)
	}
}

func TestService_FilterClaimMapFiltersReservedAndMappedClaims(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "profile"}
	client.AllowedIDTokenClaims = map[string][]string{"sub": nil, "role": nil, "email": nil, "custom": nil}
	service.cfg.Clients["example-client"] = client
	service.cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{
		"email": {Source: "/traits/email", Type: "string", Format: "email"},
	}
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "profile"},
	}
	kratos.session = domain.Session{
		Subject:        "operator-1",
		AAL:            "aal2",
		IdentityTraits: map[string]any{"email": "identity@example.com"},
	}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:       true,
		GrantedScopes: []string{"openid", "profile"},
		Claims: domain.Claims{
			IDToken: map[string]any{
				"sub":    "should-be-filtered",
				"role":   "operator",
				"email":  "policy@example.com",
				"custom": "custom-value",
			},
		},
	}
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	_, err = service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid", "profile"},
		Credentials:  ports.SessionCredentials{CookieValue: "opaque-session"},
	})
	if err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	idToken := hydra.consentAcceptance.Session.IDToken
	if _, ok := idToken["sub"]; ok {
		t.Fatal("reserved claim sub was not filtered from policy claims")
	}
	if _, ok := idToken["email"]; ok {
		t.Fatal("identity-mapped policy claim email was not filtered")
	}
	if idToken["role"] != "operator" {
		t.Fatalf("allowed non-reserved policy claim = %#v, want operator", idToken["role"])
	}
	if idToken["custom"] != "custom-value" {
		t.Fatalf("non-allowlisted policy claim = %#v, want custom-value", idToken["custom"])
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

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	result, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"admin"},
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

func TestService_CompleteConsentRejectsPolicyFailure(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge: "consent-challenge", Client: testClient(), Subject: "operator-1",
		RequestedScopes: []string{"openid"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
	policy.consentErr = errors.New("policy backend unavailable")
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	result, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"), BrowserState: started.BrowserState,
		Decision: "accept", GrantScopes: []string{"openid"},
		Credentials: ports.SessionCredentials{CookieValue: "opaque"},
	})
	if err != nil {
		t.Fatalf("complete consent: %v", err)
	}
	if result.URL != "https://hydra.example/oauth2/consent/rejected" || hydra.consentRejection.Error != "temporarily_unavailable" {
		t.Fatalf("failure result = %#v, rejection = %#v", result, hydra.consentRejection)
	}
}

func TestService_CompleteConsentRejectsUnsafePolicyGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		decision ports.ConsentDecision
	}{
		{
			name: "expanded scope",
			decision: ports.ConsentDecision{
				Allowed:       true,
				GrantedScopes: []string{"profile"},
			},
		},
		{
			name: "expanded audience",
			decision: ports.ConsentDecision{
				Allowed:          true,
				GrantedScopes:    []string{"openid"},
				GrantedAudiences: []string{"other-api"},
			},
		},
		{
			name: "duplicate audience",
			decision: ports.ConsentDecision{
				Allowed:          true,
				GrantedScopes:    []string{"openid"},
				GrantedAudiences: []string{"api", "api"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service, hydra, kratos, policy, _ := newTestService(t)
			hydra.consent = domain.ConsentRequest{
				Challenge:         "consent-challenge",
				Client:            testClient(),
				Subject:           "operator-1",
				RequestedScopes:   []string{"openid"},
				RequestedAudience: []string{"api"},
			}
			kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2"}
			policy.consentDecision = tt.decision

			started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
			if err != nil {
				t.Fatalf("start consent: %v", err)
			}
			result, err := service.CompleteConsent(context.Background(), ConsentInput{
				Transaction:  transactionFromRedirect(t, started.URL),
				CSRFToken:    queryValue(t, started.URL, "csrf"),
				BrowserState: started.BrowserState,
				Decision:     "accept",
				GrantScopes:  []string{"openid"},
				Credentials:  ports.SessionCredentials{CookieValue: "opaque"},
			})
			if err != nil {
				t.Fatalf("complete consent: %v", err)
			}
			if result.URL != "https://hydra.example/oauth2/consent/rejected" || hydra.consentRejection.Error != "temporarily_unavailable" {
				t.Fatalf("result/rejection = %#v/%#v", result, hydra.consentRejection)
			}
			if hydra.consentAcceptance.GrantScopes != nil {
				t.Fatalf("consent was accepted with unsafe grants: %#v", hydra.consentAcceptance)
			}
		})
	}
}

func TestService_StartLoginRejectsPolicyFailureForSkippedLogin(t *testing.T) {
	t.Parallel()

	service, hydra, _, policy, _ := newTestService(t)
	service.cfg.RequiredAAL = ""
	hydra.login = domain.LoginRequest{
		Challenge: "login-challenge",
		Client:    testClient(),
		Skip:      true,
		Subject:   "operator-1",
	}
	policy.loginErr = domain.ErrUpstream

	result, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	if result.URL != "https://hydra.example/oauth2/auth/rejected" || hydra.loginRejection.Error != "temporarily_unavailable" {
		t.Fatalf("result/rejection = %#v/%#v", result, hydra.loginRejection)
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

	if _, err := service.StartLogout(context.Background(), "logout-challenge", ports.LogoutStartInput{}); !errors.Is(err, domain.ErrInvalidRedirect) {
		t.Fatalf("logout error = %v, want invalid redirect", err)
	}
	if hydra.logoutAccepted {
		t.Fatal("logout was accepted with an unallowlisted return URL")
	}
}

func TestService_StartLoginSkipsAuthenticationWhenHydraAlreadyAuthenticated(t *testing.T) {
	t.Parallel()

	service, hydra, _, policy, _ := newTestService(t)
	service.cfg.RequiredAAL = ""
	hydra.login = domain.LoginRequest{
		Challenge: "login-challenge",
		Client:    testClient(),
		Subject:   "operator-1",
		Skip:      true,
	}
	policy.loginAllowed = true

	result, err := service.StartLogin(context.Background(), "login-challenge", ports.LoginStartInput{})
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	if result.URL != hydra.loginRedirect || hydra.loginAcceptance.Subject != "operator-1" {
		t.Fatalf("skip result = %#v, acceptance = %#v", result, hydra.loginAcceptance)
	}
}

func TestService_CompleteConsentDenyConsumesTransaction(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.consent = domain.ConsentRequest{
		Challenge: "consent-challenge", Client: testClient(), Subject: "operator-1",
		RequestedScopes: []string{"openid"},
	}
	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	input := ConsentInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"), BrowserState: started.BrowserState,
		Decision: "deny",
	}
	result, err := service.CompleteConsent(context.Background(), input)
	if err != nil || result.URL != "https://hydra.example/oauth2/consent/rejected" {
		t.Fatalf("deny result = %#v, error = %v", result, err)
	}
	if hydra.consentRejection.Error != "access_denied" {
		t.Fatalf("rejection = %#v, want access_denied", hydra.consentRejection)
	}
	if _, err := service.CompleteConsent(context.Background(), input); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("replay error = %v, want replay", err)
	}
}

func TestService_CompleteLogoutAcceptsAndCannotReplay(t *testing.T) {
	t.Parallel()

	service, hydra, _, _, _ := newTestService(t)
	hydra.logout = domain.LogoutRequest{Challenge: "logout-challenge", Client: testClient()}
	started, err := service.StartLogout(context.Background(), "logout-challenge", ports.LogoutStartInput{})
	if err != nil {
		t.Fatalf("start logout: %v", err)
	}
	input := ports.LogoutInput{
		Transaction: transactionFromRedirect(t, started.URL),
		CSRFToken:   queryValue(t, started.URL, "csrf"), BrowserState: started.BrowserState,
	}
	result, err := service.CompleteLogout(context.Background(), input)
	if err != nil || result.URL != hydra.logoutRedirect || !hydra.logoutAccepted {
		t.Fatalf("logout result = %#v, error = %v, accepted = %t", result, err, hydra.logoutAccepted)
	}
	if _, err := service.CompleteLogout(context.Background(), input); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("replay error = %v, want replay", err)
	}
}

func TestNewServiceRequiresAllCoreDependencies(t *testing.T) {
	t.Parallel()

	base := Dependencies{
		Login: &fakeHydra{}, Consent: &fakeHydra{}, Logout: &fakeHydra{},
		Kratos: &fakeKratos{}, State: state.NewMemoryStore(time.Now), Policy: &fakePolicy{},
	}
	tests := []struct {
		name   string
		mutate func(*Dependencies)
	}{
		{name: "login", mutate: func(deps *Dependencies) { deps.Login = nil }},
		{name: "consent", mutate: func(deps *Dependencies) { deps.Consent = nil }},
		{name: "logout", mutate: func(deps *Dependencies) { deps.Logout = nil }},
		{name: "kratos", mutate: func(deps *Dependencies) { deps.Kratos = nil }},
		{name: "state", mutate: func(deps *Dependencies) { deps.State = nil }},
		{name: "policy", mutate: func(deps *Dependencies) { deps.Policy = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps := base
			tt.mutate(&deps)
			if _, err := NewService(testConfig(), deps); err == nil {
				t.Fatal("NewService accepted missing dependency")
			}
		})
	}
}

func TestServiceReadyStopsAtFirstFailure(t *testing.T) {
	t.Parallel()

	first := &fakeReadiness{err: domain.ErrUpstream}
	second := &fakeReadiness{}
	service, err := NewService(testConfig(), Dependencies{
		Login: &fakeHydra{}, Consent: &fakeHydra{}, Logout: &fakeHydra{},
		Kratos: &fakeKratos{}, State: state.NewMemoryStore(time.Now), Policy: &fakePolicy{},
		Readiness: []ports.Readiness{first, second},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Ready(context.Background()); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("Ready error = %v, want upstream", err)
	}
	if second.calls != 0 {
		t.Fatalf("second readiness checker calls = %d, want 0", second.calls)
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
				AllowedAccessTokenClaims: map[string][]string{
					"api_role": {"openid"},
				},
				AllowedAudiences: []string{"api"},
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

func loginInputFromRedirect(t *testing.T, redirect, browserState string, credentials ports.SessionCredentials) ports.LoginInput {
	t.Helper()
	return ports.LoginInput{CSRFToken: queryValue(t, redirect, "csrf"), BrowserState: browserState, Credentials: credentials}
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
	loginInput      ports.PolicyInput
	consentInput    ports.PolicyInput
}

type fakeReadiness struct {
	err   error
	calls int
}

func (f *fakeReadiness) Ready(context.Context) error {
	f.calls++
	return f.err
}

func (f *fakePolicy) AuthorizeLogin(_ context.Context, input ports.PolicyInput) (bool, error) {
	f.loginInput = input
	return f.loginAllowed, f.loginErr
}

func (f *fakePolicy) AuthorizeConsent(_ context.Context, input ports.PolicyInput) (ports.ConsentDecision, error) {
	f.consentInput = input
	return f.consentDecision, f.consentErr
}

func TestService_Security_CRLFResponseSplitting(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)

	crlfPayloads := []struct {
		name    string
		payload string
	}{
		{name: "crlf header injection", payload: "login-challenge\r\nSet-Cookie: evil=true"},
		{name: "carriage return alone", payload: "login-challenge\rLocation: https://attacker.com"},
		{name: "newline alone", payload: "login-challenge\nLocation: https://attacker.com"},
		{name: "url encoded crlf", payload: "login-challenge%0d%0aSet-Cookie:evil=true"},
		{name: "vertical tab", payload: "login-challenge\vSet-Cookie:evil=true"},
		{name: "form feed", payload: "login-challenge\fSet-Cookie:evil=true"},
	}

	for _, tt := range crlfPayloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if _, err := service.StartLogin(ctx, tt.payload, ports.LoginStartInput{}); !errors.Is(err, domain.ErrInvalidChallenge) {
				t.Fatalf("StartLogin(%q) error = %v, want %v", tt.payload, err, domain.ErrInvalidChallenge)
			}
			if _, err := service.StartConsent(ctx, tt.payload, ports.ConsentStartInput{}); !errors.Is(err, domain.ErrInvalidChallenge) {
				t.Fatalf("StartConsent(%q) error = %v, want %v", tt.payload, err, domain.ErrInvalidChallenge)
			}
			if _, err := service.StartLogout(ctx, tt.payload, ports.LogoutStartInput{}); !errors.Is(err, domain.ErrInvalidChallenge) {
				t.Fatalf("StartLogout(%q) error = %v, want %v", tt.payload, err, domain.ErrInvalidChallenge)
			}
		})
	}
}

func TestService_Security_OpenRedirectBypass(t *testing.T) {
	t.Parallel()

	cfg := testConfig()

	//nolint:gosec // Test fixture CSRF parameter values.
	invalidParams := []struct {
		name        string
		flow        domain.Flow
		transaction string
		csrfToken   string
	}{
		{name: "empty transaction", flow: domain.FlowLogin, transaction: "", csrfToken: "valid-csrf"},
		{name: "empty csrf", flow: domain.FlowLogin, transaction: "valid-tx", csrfToken: ""},
		{name: "invalid flow", flow: domain.Flow("invalid"), transaction: "valid-tx", csrfToken: "valid-csrf"},
	}

	for _, tt := range invalidParams {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := cfg.ExternalRedirect(tt.flow, tt.transaction, tt.csrfToken); !errors.Is(err, domain.ErrInvalidTransaction) {
				t.Fatalf("ExternalRedirect(%q, %q, %q) error = %v, want %v", tt.flow, tt.transaction, tt.csrfToken, err, domain.ErrInvalidTransaction)
			}
		})
	}

	// Verify that constructed redirects maintain strict host origin and do not permit scheme injection
	redirectURL, err := cfg.ExternalRedirect(domain.FlowLogin, "tx-123", "csrf-456")
	if err != nil {
		t.Fatalf("ExternalRedirect unexpected error: %v", err)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	if parsed.Scheme != cfg.ExternalUIURL.Scheme || parsed.Host != cfg.ExternalUIURL.Host {
		t.Fatalf("redirect URL origin = %s://%s, want %s://%s", parsed.Scheme, parsed.Host, cfg.ExternalUIURL.Scheme, cfg.ExternalUIURL.Host)
	}
}

func TestService_Security_ControlCharLogInjection(t *testing.T) {
	t.Parallel()

	logInjectionPayloads := []struct {
		name  string
		input string
	}{
		{name: "fake log line injection", input: "challenge-123\n[INFO] User elevated privileges to root"},
		{name: "ansi escape sequences", input: "challenge-123\x1b[31mRED_ALERT\x1b[0m"},
		{name: "null byte injection", input: "challenge-123\x00admin"},
	}

	for _, tt := range logInjectionPayloads {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := validateChallenge(tt.input, 2048); !errors.Is(err, domain.ErrInvalidChallenge) {
				t.Fatalf("validateChallenge(%q) error = %v, want %v", tt.input, err, domain.ErrInvalidChallenge)
			}
		})
	}
}
