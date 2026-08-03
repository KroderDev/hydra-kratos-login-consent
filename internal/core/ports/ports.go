package ports

import (
	"context"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

// Provider is the driving port for the provider flows.
type Provider interface {
	StartLogin(context.Context, string, LoginStartInput) (RedirectResult, error)
	CompleteLogin(context.Context, string, LoginInput) (RedirectResult, error)
	StartConsent(context.Context, string, ConsentStartInput) (RedirectResult, error)
	CompleteConsent(context.Context, ConsentInput) (RedirectResult, error)
	StartLogout(context.Context, string, LogoutStartInput) (RedirectResult, error)
	CompleteLogout(context.Context, LogoutInput) (RedirectResult, error)
	Ready(context.Context) error
}

// RedirectResult contains a validated browser redirect target.
type RedirectResult struct {
	URL          string
	BrowserState string
}

// LoginStartInput contains browser proof used to bind a login transaction.
type LoginStartInput struct {
	BrowserState string
}

// ConsentInput contains the external UI's consent decision and browser proof.
type ConsentInput struct {
	Transaction  string
	CSRFToken    string
	BrowserState string
	Decision     string
	GrantScopes  []string
	Credentials  SessionCredentials
	Remember     bool
	RememberFor  int64
}

// ConsentStartInput contains browser proof used to bind a consent transaction.
type ConsentStartInput struct {
	BrowserState string
}

// LoginInput contains the external UI's login completion proof and options.
type LoginInput struct {
	CSRFToken    string
	BrowserState string
	Credentials  SessionCredentials
	Remember     bool
	RememberFor  int64
}

// LogoutStartInput contains browser proof used to bind a logout transaction.
type LogoutStartInput struct {
	BrowserState string
}

// LogoutInput contains the external UI's logout proof.
type LogoutInput struct {
	Transaction  string
	CSRFToken    string
	BrowserState string
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
	Get(context.Context, string) (domain.Transaction, error)
	Consume(context.Context, string) (domain.Transaction, error)
}

// Policy evaluates application authorization for scopes and audiences without
// owning protocol state.
type Policy interface {
	AuthorizeLogin(context.Context, string, string) (bool, error)
	AuthorizeConsent(context.Context, string, string, []string, []string) (ConsentDecision, error)
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
