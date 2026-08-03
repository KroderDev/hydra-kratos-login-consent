package domain

import (
	"strings"
	"time"
)

// Flow identifies the browser transaction being completed.
type Flow string

const (
	FlowLogin   Flow = "login"
	FlowConsent Flow = "consent"
)

// Client is the provider-owned subset of an OAuth client registration.
type Client struct {
	ID                     string
	Name                   string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	SkipConsent            bool
}

// LoginRequest is the Hydra login request needed by the provider flow.
type LoginRequest struct {
	Challenge    string
	Client       Client
	Skip         bool
	Subject      string
	RequestedAAL string
}

// ConsentRequest is the Hydra consent request needed by the provider flow.
type ConsentRequest struct {
	Challenge         string
	Client            Client
	Subject           string
	RequestedScopes   []string
	RequestedAudience []string
	Skip              bool
}

// LogoutRequest is the Hydra logout request needed by the provider flow.
type LogoutRequest struct {
	Challenge             string
	Client                Client
	Subject               string
	SessionID             string
	RequestURL            string
	PostLogoutRedirectURI string
}

// Session is the server-validated Kratos session identity and assurance.
type Session struct {
	Subject string
	AAL     string
	AMR     []string
}

// Claims contains claims that may be passed to Hydra token sessions.
type Claims struct {
	IDToken     map[string]any
	AccessToken map[string]any
}

// Transaction is short-lived state bound to one Hydra browser challenge.
type Transaction struct {
	Flow              Flow
	Challenge         string
	CSRFToken         string
	ClientID          string
	Subject           string
	RequestedScopes   []string
	RequestedAudience []string
	RequiredAAL       string
	ExpiresAt         time.Time
}

// AALAtLeast reports whether actual satisfies the configured assurance level.
func AALAtLeast(actual, required string) bool {
	if required == "" {
		return true
	}
	actualLevel, actualOK := aalLevel(actual)
	requiredLevel, requiredOK := aalLevel(required)
	return actualOK && requiredOK && actualLevel >= requiredLevel
}

// HigherAAL returns the stronger known assurance value.
func HigherAAL(first, second string) string {
	firstLevel, firstOK := aalLevel(first)
	secondLevel, secondOK := aalLevel(second)
	if !firstOK {
		return second
	}
	if !secondOK || firstLevel >= secondLevel {
		return first
	}
	return second
}

func aalLevel(value string) (int, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "aal") || len(value) != 4 {
		return 0, false
	}
	level := int(value[3] - '0')
	if level < 1 || level > 3 {
		return 0, false
	}
	return level, true
}
