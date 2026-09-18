package application

import (
	"context"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestService_UserInfoClaimsFilteredByAllowlistAndScope(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "profile", "phone"}
	client.AllowedUserInfoClaims = map[string][]string{
		"phone_number": {"phone"},
		"role":         {"profile"},
	}
	service.cfg.Clients["example-client"] = client
	hydra.consent = domain.ConsentRequest{
		Challenge:       "consent-challenge",
		Client:          testClient(),
		Subject:         "operator-1",
		RequestedScopes: []string{"openid", "profile", "phone"},
	}
	kratos.session = domain.Session{Subject: "operator-1", AAL: "aal2", AMR: []string{"pwd", "totp"}}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:       true,
		GrantedScopes: []string{"openid", "profile", "phone"},
		Claims: domain.Claims{
			IDToken:     map[string]any{"email": "policy@example.com"},
			AccessToken: map[string]any{"api_role": "reader"},
			UserInfo: map[string]any{
				"phone_number": "+15550100",
				"role":         "operator",
				"secret":       "not-allowlisted",
			},
		},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	if _, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid", "profile", "phone"},
		Credentials:  ports.SessionCredentials{CookieValue: "opaque-session"},
	}); err != nil {
		t.Fatalf("complete consent: %v", err)
	}

	session := hydra.consentAcceptance.Session
	if session.UserInfo["phone_number"] != "+15550100" || session.UserInfo["role"] != "operator" {
		t.Fatalf("userinfo claims = %#v, want allowlisted claims", session.UserInfo)
	}
	if _, exists := session.UserInfo["secret"]; exists {
		t.Fatal("unallowlisted userinfo claim was not filtered")
	}
	if _, exists := session.UserInfo["email"]; exists {
		t.Fatal("id_token claim was copied into userinfo")
	}
	if _, exists := session.UserInfo["api_role"]; exists {
		t.Fatal("access_token claim was copied into userinfo")
	}
	if _, exists := session.IDToken["phone_number"]; exists {
		t.Fatal("userinfo claim leaked into id_token")
	}
	if _, exists := session.AccessToken["phone_number"]; exists {
		t.Fatal("userinfo claim leaked into access_token")
	}
	if session.IDToken["email"] != "policy@example.com" || session.AccessToken["api_role"] != "reader" {
		t.Fatalf("existing destinations regressed: id_token=%#v access_token=%#v", session.IDToken, session.AccessToken)
	}
}

func TestService_UserInfoIdentityClaimsOverridePolicyClaimsWithinDestination(t *testing.T) {
	t.Parallel()

	service, hydra, kratos, policy, _ := newTestService(t)
	client := service.cfg.Clients["example-client"]
	client.AllowedScopes = []string{"openid", "email"}
	client.AllowedIDTokenClaims = nil
	client.AllowedAccessTokenClaims = nil
	client.AllowedUserInfoClaims = map[string][]string{"email": nil}
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
		IdentityTraits: map[string]any{"email": "identity@example.com"},
	}
	policy.consentDecision = ports.ConsentDecision{
		Allowed:       true,
		GrantedScopes: []string{"openid", "email"},
		Claims: domain.Claims{
			IDToken:  map[string]any{"email": "policy@example.com"},
			UserInfo: map[string]any{"email": "policy@example.com"},
		},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	if _, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid", "email"},
		Credentials:  ports.SessionCredentials{CookieValue: "opaque-session"},
	}); err != nil {
		t.Fatalf("complete consent: %v", err)
	}

	session := hydra.consentAcceptance.Session
	if session.UserInfo["email"] != "identity@example.com" {
		t.Fatalf("userinfo email = %#v, want the identity mapping to override the policy claim", session.UserInfo["email"])
	}
	if len(session.IDToken) != 0 || len(session.AccessToken) != 0 {
		t.Fatalf("identity claim leaked into unallowlisted destinations: id_token=%#v access_token=%#v", session.IDToken, session.AccessToken)
	}
}

func TestService_UserInfoClaimsRequireAllowlist(t *testing.T) {
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
		Allowed:       true,
		GrantedScopes: []string{"openid", "profile"},
		Claims: domain.Claims{
			IDToken:     map[string]any{"email": "policy@example.com"},
			AccessToken: map[string]any{"api_role": "reader"},
			UserInfo:    map[string]any{"phone_number": "+15550100"},
		},
	}

	started, err := service.StartConsent(context.Background(), "consent-challenge", ports.ConsentStartInput{})
	if err != nil {
		t.Fatalf("start consent: %v", err)
	}
	if _, err := service.CompleteConsent(context.Background(), ConsentInput{
		Transaction:  transactionFromRedirect(t, started.URL),
		CSRFToken:    queryValue(t, started.URL, "csrf"),
		BrowserState: started.BrowserState,
		Decision:     "accept",
		GrantScopes:  []string{"openid", "profile"},
		Credentials:  ports.SessionCredentials{CookieValue: "opaque-session"},
	}); err != nil {
		t.Fatalf("complete consent: %v", err)
	}

	session := hydra.consentAcceptance.Session
	if len(session.UserInfo) != 0 {
		t.Fatalf("userinfo claims = %#v, want none without a client allowlist", session.UserInfo)
	}
	if session.IDToken["email"] != "policy@example.com" || session.AccessToken["api_role"] != "reader" {
		t.Fatalf("existing destinations regressed: id_token=%#v access_token=%#v", session.IDToken, session.AccessToken)
	}
}

func TestFilterClaims_UserInfoDestinationIsolation(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.OIDCIdentityClaimMappings = identity.ClaimMappings{
		"email": {Source: "/traits/email", Type: "string", Format: "email"},
		"role":  {Source: "/metadata_public/role", Type: "string"},
	}
	service, err := NewService(cfg, Dependencies{
		Login:   &fakeHydra{},
		Consent: &fakeHydra{},
		Logout:  &fakeHydra{},
		Kratos:  &fakeKratos{},
		State:   state.NewMemoryStore(time.Now),
		Policy:  &fakePolicy{},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	session := domain.Session{
		IdentityTraits:         map[string]any{"email": "identity@example.com"},
		IdentityMetadataPublic: map[string]any{"role": "admin"},
	}
	client := config.Client{
		ID:                    "test-client",
		AllowedUserInfoClaims: map[string][]string{"email": {"email"}, "role": {"profile"}},
	}
	claims := service.filterClaims(client, domain.Claims{
		IDToken:  map[string]any{"email": "policy@example.com"},
		UserInfo: map[string]any{"email": "policy@example.com", "role": "policy-admin"},
	}, session, []string{"openid", "email", "profile"})
	if claims.UserInfo["email"] != "identity@example.com" || claims.UserInfo["role"] != "admin" {
		t.Fatalf("userinfo claims = %#v, want identity mappings to override policy claims", claims.UserInfo)
	}
	if len(claims.IDToken) != 0 || len(claims.AccessToken) != 0 {
		t.Fatalf("userinfo-only allowlist leaked into other destinations: %#v", claims)
	}

	scoped := service.filterClaims(client, domain.Claims{}, session, []string{"openid"})
	if len(scoped.UserInfo) != 0 {
		t.Fatalf("userinfo claims = %#v, want none without the effective standard scopes", scoped.UserInfo)
	}

	unallowlisted := service.filterClaims(config.Client{ID: "test-client"}, domain.Claims{
		UserInfo: map[string]any{"email": "policy@example.com"},
	}, session, []string{"openid", "email"})
	if len(unallowlisted.UserInfo) != 0 {
		t.Fatalf("userinfo claims = %#v, want none without a client allowlist", unallowlisted.UserInfo)
	}
}
