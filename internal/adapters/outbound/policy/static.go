// Package policy contains policy adapters for local development and tests.
package policy

import (
	"context"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

// Static authorizes an explicit subject and optional client allowlist.
type Static struct {
	Subjects      map[string]struct{}
	Clients       map[string]struct{}
	SubjectScopes map[string]map[string]map[string]struct{}
	RequireScopes bool
	Claims        domain.Claims
}

var _ ports.Policy = (*Static)(nil)

// NewStatic creates a fail-closed static policy adapter.
func NewStatic(subjects, clients []string) *Static {
	return &Static{
		Subjects: toSet(subjects),
		Clients:  toSet(clients),
	}
}

// NewStaticWithScopes creates a static policy with optional subject/client
// scope rules. Production composition should require these rules explicitly.
func NewStaticWithScopes(subjects, clients []string, scopeRules map[string]map[string][]string, requireScopes bool) *Static {
	policy := NewStatic(subjects, clients)
	policy.SubjectScopes = toScopeSet(scopeRules)
	policy.RequireScopes = requireScopes
	return policy
}

// AuthorizeLogin evaluates the static subject and client allowlists.
func (p *Static) AuthorizeLogin(_ context.Context, input ports.PolicyInput) (bool, error) {
	return p.allowed(input.Subject, input.ClientID), nil
}

// AuthorizeConsent evaluates the same static policy for requested scopes.
func (p *Static) AuthorizeConsent(_ context.Context, input ports.PolicyInput) (ports.ConsentDecision, error) {
	allowed := p.allowed(input.Subject, input.ClientID)
	if allowed {
		for _, audience := range input.RequestedAudiences {
			if audience == "" {
				allowed = false
				break
			}
		}
	}
	if allowed && p.RequireScopes {
		clientScopes, ok := p.SubjectScopes[input.Subject][input.ClientID]
		if !ok {
			allowed = false
		}
		for _, scope := range input.GrantedScopes {
			if _, ok := clientScopes[scope]; !ok {
				allowed = false
				break
			}
		}
	}
	decision := ports.ConsentDecision{Allowed: allowed}
	if allowed {
		decision.GrantedScopes = cloneStrings(input.GrantedScopes)
		decision.GrantedAudiences = cloneStrings(input.RequestedAudiences)
		decision.Claims = cloneClaims(p.Claims)
	}
	return decision, nil
}

func (p *Static) allowed(subject, clientID string) bool {
	if _, ok := p.Subjects[subject]; !ok {
		return false
	}
	if len(p.Clients) == 0 {
		return true
	}
	_, ok := p.Clients[clientID]
	return ok
}

func toSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func toScopeSet(values map[string]map[string][]string) map[string]map[string]map[string]struct{} {
	result := make(map[string]map[string]map[string]struct{}, len(values))
	for subject, clients := range values {
		result[subject] = make(map[string]map[string]struct{}, len(clients))
		for client, scopes := range clients {
			result[subject][client] = toSet(scopes)
		}
	}
	return result
}

func cloneClaims(claims domain.Claims) domain.Claims {
	return domain.Claims{
		IDToken:     cloneMap(claims.IDToken),
		AccessToken: cloneMap(claims.AccessToken),
	}
}

func cloneMap(source map[string]any) map[string]any {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStrings(source []string) []string {
	if len(source) == 0 {
		return nil
	}
	return append([]string(nil), source...)
}
