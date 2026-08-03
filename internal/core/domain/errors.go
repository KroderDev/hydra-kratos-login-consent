package domain

import "errors"

// Expected flow and validation errors returned by application boundaries.
var (
	ErrInvalidChallenge      = errors.New("invalid challenge")
	ErrInvalidClient         = errors.New("invalid client")
	ErrInvalidRedirect       = errors.New("invalid redirect")
	ErrInvalidScope          = errors.New("invalid scope")
	ErrInvalidTransaction    = errors.New("invalid transaction")
	ErrExpiredTransaction    = errors.New("expired transaction")
	ErrReplay                = errors.New("replayed transaction")
	ErrUnauthenticated       = errors.New("unauthenticated")
	ErrInsufficientAssurance = errors.New("insufficient authenticator assurance")
	ErrPolicyDenied          = errors.New("policy denied")
	ErrInvalidDecision       = errors.New("invalid decision")
	ErrInvalidOrigin         = errors.New("invalid origin")
	ErrInvalidCSRF           = errors.New("invalid csrf token")
	ErrInvalidRemember       = errors.New("invalid remember setting")
	ErrUpstream              = errors.New("upstream dependency failure")
)
