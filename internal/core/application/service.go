package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

// Dependencies are the ports required by the provider flows.
type Dependencies struct {
	Login     ports.LoginProvider
	Consent   ports.ConsentProvider
	Logout    ports.LogoutProvider
	Kratos    ports.Kratos
	State     ports.TransactionStore
	Policy    ports.Policy
	Readiness []ports.Readiness
	Now       func() time.Time
}

// Service orchestrates Hydra, Kratos, state, and policy without owning their storage.
type Service struct {
	cfg       config.Config
	login     ports.LoginProvider
	consent   ports.ConsentProvider
	logout    ports.LogoutProvider
	kratos    ports.Kratos
	state     ports.TransactionStore
	policy    ports.Policy
	readiness []ports.Readiness
	now       func() time.Time
}

var _ ports.Provider = (*Service)(nil)

// RedirectResult is the application service's driving-port result.
type RedirectResult = ports.RedirectResult

// ConsentInput is the application service's driving-port input.
type ConsentInput = ports.ConsentInput

// LoginInput is the application service's login completion input.
type LoginInput = ports.LoginInput

// NewService validates configuration and wires the application ports.
func NewService(cfg config.Config, dependencies Dependencies) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if dependencies.Login == nil || dependencies.Consent == nil || dependencies.Logout == nil || dependencies.Kratos == nil || dependencies.State == nil || dependencies.Policy == nil {
		return nil, fmt.Errorf("all service dependencies are required")
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &Service{
		cfg:       cfg,
		login:     dependencies.Login,
		consent:   dependencies.Consent,
		logout:    dependencies.Logout,
		kratos:    dependencies.Kratos,
		state:     dependencies.State,
		policy:    dependencies.Policy,
		readiness: dependencies.Readiness,
		now:       dependencies.Now,
	}, nil
}

// StartLogin validates a Hydra login challenge and starts or completes login.
func (s *Service) StartLogin(ctx context.Context, challenge string) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.login.GetLoginRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != "" && request.Challenge != challenge {
		return RedirectResult{}, domain.ErrInvalidChallenge
	}
	client, err := s.validateClient(request.Client)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Subject == "" && request.Skip {
		return RedirectResult{}, domain.ErrUnauthenticated
	}

	requiredAAL := domain.HigherAAL(s.cfg.RequiredAAL, request.RequestedAAL)
	if request.Skip && requiredAAL == "" {
		allowed, err := s.policy.AuthorizeLogin(ctx, request.Subject, client.ID)
		if err != nil {
			return RedirectResult{}, err
		}
		if !allowed {
			return s.rejectLogin(ctx, challenge, "access_denied", "The login policy denied access.")
		}
		redirect, err := s.login.AcceptLogin(ctx, challenge, ports.LoginAcceptance{Subject: request.Subject})
		return s.hydraRedirect(redirect, err)
	}

	transaction := domain.Transaction{
		Flow:        domain.FlowLogin,
		Challenge:   challenge,
		ClientID:    client.ID,
		Subject:     request.Subject,
		RequiredAAL: requiredAAL,
		ExpiresAt:   s.now().Add(s.cfg.TransactionTTL),
	}
	transaction.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return RedirectResult{}, err
	}
	handle, err := s.state.Create(ctx, transaction)
	if err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.cfg.ExternalRedirect(domain.FlowLogin, handle, transaction.CSRFToken)
	return RedirectResult{URL: redirect}, err
}

// CompleteLogin consumes a login transaction and validates the Kratos session.
func (s *Service) CompleteLogin(ctx context.Context, handle string, input ports.LoginInput) (RedirectResult, error) {
	transaction, err := s.consume(ctx, handle, domain.FlowLogin)
	if err != nil {
		return RedirectResult{}, err
	}
	if err := validateCSRF(input.CSRFToken, transaction.CSRFToken); err != nil {
		return RedirectResult{}, err
	}
	if err := validateRemember(input.RememberFor); err != nil {
		return RedirectResult{}, err
	}
	session, err := s.kratos.ValidateSession(ctx, input.Credentials)
	if err != nil {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, err)
	}
	if transaction.Subject != "" && session.Subject != transaction.Subject {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, domain.ErrUnauthenticated)
	}
	if !domain.AALAtLeast(session.AAL, transaction.RequiredAAL) {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrInsufficientAssurance, domain.ErrInsufficientAssurance)
	}
	allowed, err := s.policy.AuthorizeLogin(ctx, session.Subject, transaction.ClientID)
	if err != nil {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrUpstream, err)
	}
	if !allowed {
		return s.rejectLogin(ctx, transaction.Challenge, "access_denied", "The login policy denied access.")
	}
	redirect, err := s.login.AcceptLogin(ctx, transaction.Challenge, ports.LoginAcceptance{
		Subject:     session.Subject,
		ACR:         session.AAL,
		AMR:         append([]string(nil), session.AMR...),
		Remember:    input.Remember,
		RememberFor: input.RememberFor,
	})
	return s.hydraRedirect(redirect, err)
}

// StartConsent validates a Hydra consent challenge and starts or completes consent.
func (s *Service) StartConsent(ctx context.Context, challenge string) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.consent.GetConsentRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != "" && request.Challenge != challenge {
		return RedirectResult{}, domain.ErrInvalidChallenge
	}
	client, err := s.validateClient(request.Client)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Subject == "" {
		return RedirectResult{}, domain.ErrUnauthenticated
	}
	if err := validateScopes(client, request.RequestedScopes); err != nil {
		return RedirectResult{}, err
	}
	if request.Skip || client.SkipConsent {
		return s.acceptConsentDecision(ctx, request, client, request.RequestedScopes, false, 0)
	}

	transaction := domain.Transaction{
		Flow:              domain.FlowConsent,
		Challenge:         challenge,
		ClientID:          client.ID,
		Subject:           request.Subject,
		RequestedScopes:   append([]string(nil), request.RequestedScopes...),
		RequestedAudience: append([]string(nil), request.RequestedAudience...),
		ExpiresAt:         s.now().Add(s.cfg.TransactionTTL),
	}
	transaction.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return RedirectResult{}, err
	}
	handle, err := s.state.Create(ctx, transaction)
	if err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.cfg.ExternalConsentRedirect(handle, transaction.CSRFToken, request.Client.Name, request.RequestedScopes)
	return RedirectResult{URL: redirect}, err
}

// CompleteConsent consumes a consent transaction and submits a policy-checked result.
func (s *Service) CompleteConsent(ctx context.Context, input ConsentInput) (RedirectResult, error) {
	transaction, err := s.consume(ctx, input.Transaction, domain.FlowConsent)
	if err != nil {
		return RedirectResult{}, err
	}
	if input.Decision != "accept" && input.Decision != "deny" {
		return RedirectResult{}, domain.ErrInvalidDecision
	}
	if err := validateCSRF(input.CSRFToken, transaction.CSRFToken); err != nil {
		return RedirectResult{}, err
	}
	if err := validateRemember(input.RememberFor); err != nil {
		return RedirectResult{}, err
	}
	if input.Decision == "deny" {
		return s.rejectConsent(ctx, transaction.Challenge, "access_denied", "The user denied access.")
	}
	if err := validateRequestedSubset(transaction.RequestedScopes, input.GrantScopes); err != nil {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidScope, err)
	}
	session, err := s.kratos.ValidateSession(ctx, input.Credentials)
	if err != nil {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, err)
	}
	if session.Subject != transaction.Subject {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, domain.ErrUnauthenticated)
	}
	client, ok := s.cfg.Client(transaction.ClientID)
	if !ok {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidClient, domain.ErrInvalidClient)
	}
	return s.acceptConsentDecision(ctx, domain.ConsentRequest{
		Challenge:         transaction.Challenge,
		Subject:           transaction.Subject,
		RequestedScopes:   transaction.RequestedScopes,
		RequestedAudience: transaction.RequestedAudience,
	}, client, input.GrantScopes, input.Remember, input.RememberFor)
}

// Logout validates a Hydra logout challenge and its post-logout redirect.
func (s *Service) Logout(ctx context.Context, challenge string) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.logout.GetLogoutRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != "" && request.Challenge != challenge {
		return RedirectResult{}, domain.ErrInvalidChallenge
	}
	client, err := s.validateClient(request.Client)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.PostLogoutRedirectURI != "" && !contains(client.AllowedPostLogoutRedirects, request.PostLogoutRedirectURI) {
		return RedirectResult{}, domain.ErrInvalidRedirect
	}
	redirect, err := s.logout.AcceptLogout(ctx, challenge)
	return s.hydraRedirect(redirect, err)
}

// Ready checks all configured dependency readiness ports.
func (s *Service) Ready(ctx context.Context) error {
	for _, checker := range s.readiness {
		if err := checker.Ready(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) consume(ctx context.Context, handle string, expectedFlow domain.Flow) (domain.Transaction, error) {
	if handle == "" || len(handle) > 256 {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	transaction, err := s.state.Consume(ctx, handle)
	if err != nil {
		return domain.Transaction{}, err
	}
	if transaction.Flow != expectedFlow || transaction.Challenge == "" || transaction.ClientID == "" || transaction.CSRFToken == "" {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	if !transaction.ExpiresAt.After(s.now()) {
		return domain.Transaction{}, domain.ErrExpiredTransaction
	}
	return transaction, nil
}

func (s *Service) validateClient(client domain.Client) (config.Client, error) {
	if client.ID == "" {
		return config.Client{}, domain.ErrInvalidClient
	}
	configured, ok := s.cfg.Client(client.ID)
	if !ok {
		return config.Client{}, domain.ErrInvalidClient
	}
	if len(client.RedirectURIs) == 0 {
		return config.Client{}, domain.ErrInvalidRedirect
	}
	for _, redirect := range client.RedirectURIs {
		if !contains(configured.AllowedRedirectURIs, redirect) {
			return config.Client{}, domain.ErrInvalidRedirect
		}
	}
	return configured, nil
}

func (s *Service) acceptConsentDecision(ctx context.Context, request domain.ConsentRequest, client config.Client, scopes []string, remember bool, rememberFor int64) (RedirectResult, error) {
	if err := validateRemember(rememberFor); err != nil {
		return RedirectResult{}, err
	}
	if err := validateRequestedSubset(request.RequestedScopes, scopes); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrInvalidScope, err)
	}
	decision, err := s.policy.AuthorizeConsent(ctx, request.Subject, client.ID, scopes)
	if err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrPolicyDenied, err)
	}
	if !decision.Allowed {
		return s.rejectConsent(ctx, request.Challenge, "access_denied", "The consent policy denied access.")
	}
	claims := s.filterClaims(client, decision.Claims, scopes)
	redirect, err := s.consent.AcceptConsent(ctx, request.Challenge, ports.ConsentAcceptance{
		GrantScopes:   append([]string(nil), scopes...),
		GrantAudience: append([]string(nil), request.RequestedAudience...),
		Session:       claims,
		Remember:      remember,
		RememberFor:   rememberFor,
	})
	return s.hydraRedirect(redirect, err)
}

func (s *Service) filterClaims(client config.Client, claims domain.Claims, scopes []string) domain.Claims {
	return domain.Claims{
		IDToken:     filterClaimMap(claims.IDToken, client.AllowedIDTokenClaims, scopes),
		AccessToken: filterClaimMap(claims.AccessToken, client.AllowedAccessTokenClaims, scopes),
	}
}

func (s *Service) rejectLogin(ctx context.Context, challenge, code, description string) (RedirectResult, error) {
	redirect, err := s.login.RejectLogin(ctx, challenge, ports.Rejection{Error: code, ErrorDescription: description})
	return s.hydraRedirect(redirect, err)
}

func (s *Service) rejectLoginFailure(ctx context.Context, challenge string, publicError, cause error) (RedirectResult, error) {
	code := "access_denied"
	if errors.Is(publicError, domain.ErrUpstream) || errors.Is(cause, domain.ErrUpstream) {
		code = "temporarily_unavailable"
	}
	result, err := s.rejectLogin(ctx, challenge, code, "The login could not be completed.")
	if err != nil {
		return RedirectResult{}, errors.Join(publicError, err)
	}
	return result, nil
}

func (s *Service) rejectConsent(ctx context.Context, challenge, code, description string) (RedirectResult, error) {
	redirect, err := s.consent.RejectConsent(ctx, challenge, ports.Rejection{Error: code, ErrorDescription: description})
	return s.hydraRedirect(redirect, err)
}

func (s *Service) rejectConsentFailure(ctx context.Context, challenge string, publicError, cause error) (RedirectResult, error) {
	code := "access_denied"
	if errors.Is(publicError, domain.ErrUpstream) || errors.Is(cause, domain.ErrUpstream) {
		code = "temporarily_unavailable"
	}
	result, err := s.rejectConsent(ctx, challenge, code, "The consent could not be completed.")
	if err != nil {
		return RedirectResult{}, errors.Join(publicError, err)
	}
	return result, nil
}

func (s *Service) hydraRedirect(target string, upstreamErr error) (RedirectResult, error) {
	if upstreamErr != nil {
		return RedirectResult{}, upstreamErr
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return RedirectResult{}, domain.ErrInvalidRedirect
	}
	if parsed.Scheme != s.cfg.HydraPublicURL.Scheme || parsed.Host != s.cfg.HydraPublicURL.Host {
		return RedirectResult{}, domain.ErrInvalidRedirect
	}
	basePath := strings.TrimRight(s.cfg.HydraPublicURL.Path, "/")
	if basePath != "" && parsed.Path != basePath && !strings.HasPrefix(parsed.Path, basePath+"/") {
		return RedirectResult{}, domain.ErrInvalidRedirect
	}
	return RedirectResult{URL: target}, nil
}

func validateChallenge(value string) error {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n") {
		return domain.ErrInvalidChallenge
	}
	return nil
}

func validateScopes(client config.Client, scopes []string) error {
	if hasDuplicates(scopes) {
		return domain.ErrInvalidScope
	}
	for _, scope := range scopes {
		if scope == "" || !contains(client.AllowedScopes, scope) {
			return domain.ErrInvalidScope
		}
	}
	return nil
}

func validateRequestedSubset(requested, granted []string) error {
	if hasDuplicates(granted) {
		return domain.ErrInvalidScope
	}
	for _, scope := range granted {
		if !contains(requested, scope) {
			return domain.ErrInvalidScope
		}
	}
	return nil
}

func filterClaimMap(source map[string]any, allowed map[string][]string, scopes []string) map[string]any {
	if len(source) == 0 || len(allowed) == 0 {
		return nil
	}
	result := make(map[string]any)
	for name, value := range source {
		requiredScopes, ok := allowed[name]
		if ok && subset(requiredScopes, scopes) {
			result[name] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func subset(required, values []string) bool {
	for _, value := range required {
		if !contains(values, value) {
			return false
		}
	}
	return true
}

func hasDuplicates(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func newOpaqueToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate transaction csrf token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validateCSRF(actual, expected string) error {
	if actual == "" || expected == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return domain.ErrInvalidCSRF
	}
	return nil
}

func validateRemember(rememberFor int64) error {
	if rememberFor < 0 {
		return domain.ErrInvalidRemember
	}
	return nil
}
