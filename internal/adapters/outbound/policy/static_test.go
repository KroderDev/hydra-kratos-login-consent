package policy

import (
	"context"
	"reflect"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestStaticAuthorization(t *testing.T) {
	t.Parallel()

	policy := NewStatic([]string{"operator-1"}, []string{"client-1"})
	tests := []struct {
		name     string
		subject  string
		clientID string
		want     bool
	}{
		{name: "subject and client allowed", subject: "operator-1", clientID: "client-1", want: true},
		{name: "unknown subject denied", subject: "operator-2", clientID: "client-1", want: false},
		{name: "unknown client denied", subject: "operator-1", clientID: "client-2", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, err := policy.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: tt.subject, ClientID: tt.clientID})
			if err != nil {
				t.Fatalf("AuthorizeLogin: %v", err)
			}
			if allowed != tt.want {
				t.Fatalf("allowed = %t, want %t", allowed, tt.want)
			}
		})
	}
}

func TestStaticEmptyClientAllowlistAllowsAnyClient(t *testing.T) {
	t.Parallel()

	policy := NewStatic([]string{"operator-1"}, nil)
	allowed, err := policy.AuthorizeLogin(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "any-client"})
	if err != nil {
		t.Fatalf("AuthorizeLogin: %v", err)
	}
	if !allowed {
		t.Fatal("empty client allowlist denied an allowed subject")
	}
}

func TestStaticConsentClonesClaims(t *testing.T) {
	t.Parallel()

	policy := NewStatic([]string{"operator-1"}, nil)
	policy.Claims = domain.Claims{IDToken: map[string]any{"email": "operator@example.com"}}

	decision, err := policy.AuthorizeConsent(context.Background(), ports.PolicyInput{Subject: "operator-1", ClientID: "client-1"})
	if err != nil {
		t.Fatalf("AuthorizeConsent: %v", err)
	}
	decision.Claims.IDToken["email"] = "changed"
	if got := policy.Claims.IDToken["email"]; got != "operator@example.com" {
		t.Fatalf("policy claim mutated through decision: %v", got)
	}
}

func TestStaticDeniedConsentDoesNotReturnClaims(t *testing.T) {
	t.Parallel()

	policy := NewStatic([]string{"operator-1"}, nil)
	policy.Claims = domain.Claims{IDToken: map[string]any{"role": "admin"}}
	decision, err := policy.AuthorizeConsent(context.Background(), ports.PolicyInput{
		Subject:  "operator-2",
		ClientID: "client-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeConsent: %v", err)
	}
	if decision.Allowed {
		t.Fatal("consent was allowed for an unknown subject")
	}
	if decision.Claims.IDToken != nil || decision.Claims.AccessToken != nil {
		t.Fatalf("denied decision returned claims: %#v", decision.Claims)
	}
}

func TestStaticConsentRequiresConfiguredSubjectScopes(t *testing.T) {
	t.Parallel()

	policy := NewStaticWithScopes(
		[]string{"operator-1"},
		[]string{"client-1"},
		map[string]map[string][]string{
			"operator-1": {"client-1": {"openid"}},
		},
		true,
	)
	decision, err := policy.AuthorizeConsent(context.Background(), ports.PolicyInput{
		Subject:       "operator-1",
		ClientID:      "client-1",
		GrantedScopes: []string{"profile"},
	})
	if err != nil {
		t.Fatalf("AuthorizeConsent: %v", err)
	}
	if decision.Allowed {
		t.Fatal("consent allowed for an unconfigured subject scope")
	}
}

func TestStaticConsentReturnsEffectiveGrants(t *testing.T) {
	t.Parallel()

	policy := NewStatic([]string{"operator-1"}, nil)
	decision, err := policy.AuthorizeConsent(context.Background(), ports.PolicyInput{
		Subject:            "operator-1",
		ClientID:           "client-1",
		GrantedScopes:      []string{"openid"},
		RequestedAudiences: []string{"api"},
	})
	if err != nil {
		t.Fatalf("AuthorizeConsent: %v", err)
	}
	if !decision.Allowed || !reflect.DeepEqual(decision.GrantedScopes, []string{"openid"}) || !reflect.DeepEqual(decision.GrantedAudiences, []string{"api"}) {
		t.Fatalf("decision = %#v", decision)
	}
}
