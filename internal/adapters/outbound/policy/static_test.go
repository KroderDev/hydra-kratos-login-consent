package policy

import (
	"context"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
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
			allowed, err := policy.AuthorizeLogin(context.Background(), tt.subject, tt.clientID)
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
	allowed, err := policy.AuthorizeLogin(context.Background(), "operator-1", "any-client")
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

	decision, err := policy.AuthorizeConsent(context.Background(), "operator-1", "client-1", nil)
	if err != nil {
		t.Fatalf("AuthorizeConsent: %v", err)
	}
	decision.Claims.IDToken["email"] = "changed"
	if got := policy.Claims.IDToken["email"]; got != "operator@example.com" {
		t.Fatalf("policy claim mutated through decision: %v", got)
	}
}
