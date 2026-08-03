// Package policy contains policy adapters for local development and tests.
package policy

import (
	"context"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

// Static authorizes an explicit subject and optional client allowlist.
type Static struct {
	Subjects map[string]struct{}
	Clients  map[string]struct{}
	Claims   domain.Claims
}

var _ ports.Policy = (*Static)(nil)

// NewStatic creates a fail-closed static policy adapter.
func NewStatic(subjects, clients []string) *Static {
	return &Static{
		Subjects: toSet(subjects),
		Clients:  toSet(clients),
	}
}

// AuthorizeLogin evaluates the static subject and client allowlists.
func (p *Static) AuthorizeLogin(_ context.Context, subject, clientID string) (bool, error) {
	return p.allowed(subject, clientID), nil
}

// AuthorizeConsent evaluates the same static policy for requested scopes.
func (p *Static) AuthorizeConsent(_ context.Context, subject, clientID string, _ []string) (ports.ConsentDecision, error) {
	return ports.ConsentDecision{Allowed: p.allowed(subject, clientID), Claims: cloneClaims(p.Claims)}, nil
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
