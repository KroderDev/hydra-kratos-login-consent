package ports

import (
	"context"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

// Provider is the driving port for the provider flows.
type Provider interface {
	StartLogin(context.Context, string) (RedirectResult, error)
	CompleteLogin(context.Context, string, LoginInput) (RedirectResult, error)
	StartConsent(context.Context, string) (RedirectResult, error)
	CompleteConsent(context.Context, ConsentInput) (RedirectResult, error)
	Logout(context.Context, string) (RedirectResult, error)
	Ready(context.Context) error
}

// RedirectResult contains a validated browser redirect target.
type RedirectResult struct {
	URL string
}

// ConsentInput contains the external UI's consent decision and browser proof.
type ConsentInput struct {
	Transaction string
	CSRFToken   string
	Decision    string
	GrantScopes []string
	Credentials SessionCredentials
	Remember    bool
	RememberFor int64
}

// LoginInput contains the external UI's login completion proof and options.
type LoginInput struct {
	CSRFToken   string
	Credentials SessionCredentials
	Remember    bool
	RememberFor int64
}

// LoginProvider completes Hydra login challenges.
type LoginProvider interface {
	GetLoginRequest(context.Context, string) (domain.LoginRequest, error)
	AcceptLogin(context.Context, string, LoginAcceptance) (string, error)
	RejectLogin(context.Context, string, Rejection) (string, error)
}

// ConsentProvider completes Hydra consent challenges.
type ConsentProvider interface {
	GetConsentRequest(context.Context, string) (domain.ConsentRequest, error)
	AcceptConsent(context.Context, string, ConsentAcceptance) (string, error)
	RejectConsent(context.Context, string, Rejection) (string, error)
}

// LogoutProvider completes Hydra logout challenges.
type LogoutProvider interface {
	GetLogoutRequest(context.Context, string) (domain.LogoutRequest, error)
	AcceptLogout(context.Context, string) (string, error)
	RejectLogout(context.Context, string, Rejection) (string, error)
}

// LoginAcceptance is the trusted result submitted to Hydra.
type LoginAcceptance struct {
	Subject     string
	ACR         string
	AMR         []string
	Remember    bool
	RememberFor int64
}

// ConsentAcceptance is the trusted consent result submitted to Hydra.
type ConsentAcceptance struct {
	GrantScopes   []string
	GrantAudience []string
	Session       domain.Claims
	Remember      bool
	RememberFor   int64
}

// Rejection is a safe OAuth error submitted to Hydra.
type Rejection struct {
	Error            string
	ErrorDescription string
}

// Kratos validates browser sessions through the Kratos public API.
type Kratos interface {
	ValidateSession(context.Context, SessionCredentials) (domain.Session, error)
}

// SessionCredentials contains opaque browser credentials for server-side validation.
type SessionCredentials struct {
	CookieName  string
	CookieValue string
	Token       string
}

// TransactionStore creates and atomically consumes short-lived transactions.
type TransactionStore interface {
	Create(context.Context, domain.Transaction) (string, error)
	Consume(context.Context, string) (domain.Transaction, error)
}

// Policy evaluates application authorization without owning protocol state.
type Policy interface {
	AuthorizeLogin(context.Context, string, string) (bool, error)
	AuthorizeConsent(context.Context, string, string, []string) (ConsentDecision, error)
}

// ConsentDecision is the policy result and candidate token claims.
type ConsentDecision struct {
	Allowed bool
	Claims  domain.Claims
}

// Readiness reports whether an external dependency can serve requests.
type Readiness interface {
	Ready(context.Context) error
}
