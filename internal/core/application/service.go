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
	"sync"
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
	admission *transactionAdmission
}

var _ ports.Provider = (*Service)(nil)

// RedirectResult is the application service's driving-port result.
type RedirectResult = ports.RedirectResult

// ConsentInput is the application service's driving-port input.
type ConsentInput = ports.ConsentInput

// LoginInput is the application service's login completion input.
type LoginInput = ports.LoginInput

// LogoutInput is the application service's logout completion input.
type LogoutInput = ports.LogoutInput

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
		admission: newTransactionAdmission(cfg.EffectiveMaxPendingTransactions(), dependencies.Now),
	}, nil
}

// StartLogin validates a Hydra login challenge and starts or completes login.
func (s *Service) StartLogin(ctx context.Context, challenge string, input ports.LoginStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.login.GetLoginRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != challenge {
		return RedirectResult{}, domain.ErrInvalidChallenge
	}
	client, err := s.validateClient(request.Client)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Subject == "" && request.Skip {
		return RedirectResult{}, domain.ErrUnauthenticated
	}

	if request.RequestedAAL != "" && !domain.SupportedAAL(request.RequestedAAL) {
		return RedirectResult{}, domain.ErrInvalidAssurance
	}
	requiredAAL := domain.HigherAAL(s.cfg.RequiredAAL, request.RequestedAAL)
	if request.Skip && requiredAAL == "" {
		allowed, err := s.policy.AuthorizeLogin(ctx, ports.PolicyInput{
			Subject:  request.Subject,
			ClientID: client.ID,
		})
		if err != nil {
			return s.rejectLoginFailure(ctx, challenge, domain.ErrUpstream, err)
		}
		if !allowed {
			return s.rejectLogin(ctx, challenge, "access_denied", "The login policy denied access.")
		}
		redirect, err := s.login.AcceptLogin(ctx, challenge, ports.LoginAcceptance{Subject: request.Subject})
		return s.hydraRedirect(redirect, err)
	}

	transaction := domain.Transaction{
		Flow:         domain.FlowLogin,
		Challenge:    challenge,
		ClientID:     client.ID,
		Subject:      request.Subject,
		RequestedAAL: request.RequestedAAL,
		RequiredAAL:  requiredAAL,
		ExpiresAt:    s.now().Add(s.cfg.TransactionTTL),
	}
	transaction.BrowserState, err = s.startBrowserState(input.BrowserState)
	if err != nil {
		return RedirectResult{}, err
	}
	transaction.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return RedirectResult{}, err
	}
	handle, err := s.createTransaction(ctx, transaction)
	if err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.cfg.ExternalRedirect(domain.FlowLogin, handle, transaction.CSRFToken)
	return RedirectResult{URL: redirect, BrowserState: transaction.BrowserState}, err
}

// CompleteLogin consumes a login transaction and validates the Kratos session.
func (s *Service) CompleteLogin(ctx context.Context, handle string, input ports.LoginInput) (RedirectResult, error) {
	transaction, err := s.load(ctx, handle, domain.FlowLogin, input.CSRFToken, input.BrowserState)
	if err != nil {
		return RedirectResult{}, err
	}
	if err := validateRemember(input.Remember, input.RememberFor); err != nil {
		return RedirectResult{}, err
	}
	if _, err := s.consume(ctx, handle); err != nil {
		return RedirectResult{}, err
	}
	session, err := s.kratos.ValidateSession(ctx, input.Credentials)
	if err != nil {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, err)
	}
	if transaction.Subject != "" && session.Subject != transaction.Subject {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrUnauthenticated, domain.ErrUnauthenticated)
	}
	if !domain.AALAtLeast(session.AAL, domain.HigherAAL(s.cfg.RequiredAAL, transaction.RequestedAAL)) {
		return s.rejectLoginFailure(ctx, transaction.Challenge, domain.ErrInsufficientAssurance, domain.ErrInsufficientAssurance)
	}
	allowed, err := s.policy.AuthorizeLogin(ctx, ports.PolicyInput{
		Subject:  session.Subject,
		ClientID: transaction.ClientID,
		AAL:      session.AAL,
		AMR:      append([]string(nil), session.AMR...),
	})
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
func (s *Service) StartConsent(ctx context.Context, challenge string, input ports.ConsentStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.consent.GetConsentRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != challenge {
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
	if err := validateAudiences(client, request.RequestedAudience); err != nil {
		return RedirectResult{}, err
	}
	transaction := domain.Transaction{
		Flow:              domain.FlowConsent,
		Challenge:         challenge,
		ClientID:          client.ID,
		Subject:           request.Subject,
		RequestedScopes:   append([]string(nil), request.RequestedScopes...),
		RequestedAudience: append([]string(nil), request.RequestedAudience...),
		RequiredAAL:       s.cfg.RequiredAAL,
		ExpiresAt:         s.now().Add(s.cfg.TransactionTTL),
	}
	transaction.BrowserState, err = s.startBrowserState(input.BrowserState)
	if err != nil {
		return RedirectResult{}, err
	}
	transaction.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return RedirectResult{}, err
	}
	handle, err := s.createTransaction(ctx, transaction)
	if err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.cfg.ExternalConsentRedirect(handle, transaction.CSRFToken, request.Client.Name, request.RequestedScopes)
	if err == nil && (request.Skip || client.SkipConsent) {
		redirect, err = addQueryValue(redirect, "skip_consent", "true")
	}
	return RedirectResult{URL: redirect, BrowserState: transaction.BrowserState}, err
}

// CompleteConsent consumes a consent transaction and submits a policy-checked result.
func (s *Service) CompleteConsent(ctx context.Context, input ConsentInput) (RedirectResult, error) {
	transaction, err := s.load(ctx, input.Transaction, domain.FlowConsent, input.CSRFToken, input.BrowserState)
	if err != nil {
		return RedirectResult{}, err
	}
	if input.Decision != "accept" && input.Decision != "deny" {
		return RedirectResult{}, domain.ErrInvalidDecision
	}
	if err := validateRemember(input.Remember, input.RememberFor); err != nil {
		return RedirectResult{}, err
	}
	if input.Decision == "deny" {
		if _, err := s.consume(ctx, input.Transaction); err != nil {
			return RedirectResult{}, err
		}
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
	if !domain.AALAtLeast(session.AAL, domain.HigherAAL(s.cfg.RequiredAAL, transaction.RequiredAAL)) {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInsufficientAssurance, domain.ErrInsufficientAssurance)
	}
	client, ok := s.cfg.Client(transaction.ClientID)
	if !ok {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidClient, domain.ErrInvalidClient)
	}
	if err := validateScopes(client, transaction.RequestedScopes); err != nil {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidScope, err)
	}
	if err := validateAudiences(client, transaction.RequestedAudience); err != nil {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidAudience, err)
	}
	if _, err := s.consume(ctx, input.Transaction); err != nil {
		return RedirectResult{}, err
	}
	return s.acceptConsentDecision(ctx, domain.ConsentRequest{
		Challenge:         transaction.Challenge,
		Subject:           transaction.Subject,
		RequestedScopes:   transaction.RequestedScopes,
		RequestedAudience: transaction.RequestedAudience,
	}, client, session, input.GrantScopes, input.Remember, input.RememberFor)
}

// StartLogout validates a Hydra logout challenge and starts a browser-bound
// logout handoff.
func (s *Service) StartLogout(ctx context.Context, challenge string, input ports.LogoutStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge); err != nil {
		return RedirectResult{}, err
	}
	request, err := s.logout.GetLogoutRequest(ctx, challenge)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.Challenge != challenge {
		return RedirectResult{}, domain.ErrInvalidChallenge
	}
	client, err := s.validateClient(request.Client)
	if err != nil {
		return RedirectResult{}, err
	}
	if request.PostLogoutRedirectURI != "" && !contains(client.AllowedPostLogoutRedirects, request.PostLogoutRedirectURI) {
		return RedirectResult{}, domain.ErrInvalidRedirect
	}
	transaction := domain.Transaction{
		Flow:         domain.FlowLogout,
		Challenge:    challenge,
		ClientID:     client.ID,
		BrowserState: input.BrowserState,
		ExpiresAt:    s.now().Add(s.cfg.TransactionTTL),
	}
	if transaction.BrowserState, err = s.startBrowserState(transaction.BrowserState); err != nil {
		return RedirectResult{}, err
	}
	transaction.CSRFToken, err = newOpaqueToken()
	if err != nil {
		return RedirectResult{}, err
	}
	handle, err := s.createTransaction(ctx, transaction)
	if err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.cfg.ExternalRedirect(domain.FlowLogout, handle, transaction.CSRFToken)
	return RedirectResult{URL: redirect, BrowserState: transaction.BrowserState}, err
}

// CompleteLogout consumes a validated logout handoff and accepts the Hydra
// logout challenge.
func (s *Service) CompleteLogout(ctx context.Context, input ports.LogoutInput) (RedirectResult, error) {
	transaction, err := s.load(ctx, input.Transaction, domain.FlowLogout, input.CSRFToken, input.BrowserState)
	if err != nil {
		return RedirectResult{}, err
	}
	if _, err := s.consume(ctx, input.Transaction); err != nil {
		return RedirectResult{}, err
	}
	redirect, err := s.logout.AcceptLogout(ctx, transaction.Challenge)
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

func (s *Service) createTransaction(ctx context.Context, transaction domain.Transaction) (string, error) {
	if !s.admission.reserve(transaction.ExpiresAt) {
		return "", domain.ErrUpstream
	}
	committed := false
	defer func() {
		if !committed {
			s.admission.cancel()
		}
	}()
	handle, err := s.state.Create(ctx, transaction)
	if err != nil {
		return "", err
	}
	s.admission.commit(handle, transaction.ExpiresAt)
	committed = true
	return handle, nil
}

func (s *Service) load(ctx context.Context, handle string, expectedFlow domain.Flow, csrfToken, browserState string) (domain.Transaction, error) {
	if handle == "" || len(handle) > 256 {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	transaction, err := s.state.Get(ctx, handle)
	if err != nil {
		if errors.Is(err, domain.ErrExpiredTransaction) || errors.Is(err, domain.ErrReplay) {
			s.admission.release(handle)
		}
		return domain.Transaction{}, err
	}
	if transaction.Flow != expectedFlow || transaction.Challenge == "" || transaction.ClientID == "" || transaction.CSRFToken == "" || transaction.BrowserState == "" {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	if !transaction.ExpiresAt.After(s.now()) {
		s.admission.release(handle)
		return domain.Transaction{}, domain.ErrExpiredTransaction
	}
	if err := validateCSRF(csrfToken, transaction.CSRFToken); err != nil {
		return domain.Transaction{}, err
	}
	if err := validateBrowserState(browserState, transaction.BrowserState); err != nil {
		return domain.Transaction{}, err
	}
	return transaction, nil
}

func (s *Service) consume(ctx context.Context, handle string) (domain.Transaction, error) {
	transaction, err := s.state.Consume(ctx, handle)
	if err == nil || errors.Is(err, domain.ErrReplay) || errors.Is(err, domain.ErrExpiredTransaction) {
		s.admission.release(handle)
	}
	return transaction, err
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

func (s *Service) acceptConsentDecision(ctx context.Context, request domain.ConsentRequest, client config.Client, session domain.Session, scopes []string, remember bool, rememberFor int64) (RedirectResult, error) {
	if err := validateRemember(remember, rememberFor); err != nil {
		return RedirectResult{}, err
	}
	if err := validateScopes(client, request.RequestedScopes); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrInvalidScope, err)
	}
	if err := validateAudiences(client, request.RequestedAudience); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrInvalidAudience, err)
	}
	if err := validateRequestedSubset(request.RequestedScopes, scopes); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrInvalidScope, err)
	}
	decision, err := s.policy.AuthorizeConsent(ctx, ports.PolicyInput{
		Subject:            request.Subject,
		ClientID:           client.ID,
		RequestedScopes:    append([]string(nil), request.RequestedScopes...),
		GrantedScopes:      append([]string(nil), scopes...),
		RequestedAudiences: append([]string(nil), request.RequestedAudience...),
		AAL:                session.AAL,
		AMR:                append([]string(nil), session.AMR...),
	})
	if err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrUpstream, err)
	}
	if !decision.Allowed {
		return s.rejectConsent(ctx, request.Challenge, "access_denied", "The consent policy denied access.")
	}
	if err := validateRequestedSubset(scopes, decision.GrantedScopes); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrUpstream, err)
	}
	if err := validateAudienceSubset(request.RequestedAudience, decision.GrantedAudiences); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrUpstream, err)
	}
	claims := s.filterClaims(client, decision.Claims, decision.GrantedScopes)
	redirect, err := s.consent.AcceptConsent(ctx, request.Challenge, ports.ConsentAcceptance{
		GrantScopes:   append([]string(nil), decision.GrantedScopes...),
		GrantAudience: append([]string(nil), decision.GrantedAudiences...),
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

func addQueryValue(target, name, value string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", domain.ErrInvalidRedirect
	}
	query := parsed.Query()
	query.Set(name, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
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

func validateAudiences(client config.Client, audiences []string) error {
	if hasDuplicates(audiences) {
		return domain.ErrInvalidAudience
	}
	for _, audience := range audiences {
		if audience == "" || !contains(client.AllowedAudiences, audience) {
			return domain.ErrInvalidAudience
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

func validateAudienceSubset(requested, granted []string) error {
	if hasDuplicates(granted) {
		return domain.ErrInvalidAudience
	}
	for _, audience := range granted {
		if !contains(requested, audience) {
			return domain.ErrInvalidAudience
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

func (s *Service) startBrowserState(value string) (string, error) {
	if value == "" {
		return newOpaqueToken()
	}
	if err := validateOpaqueToken(value); err != nil {
		return "", err
	}
	return value, nil
}

func validateCSRF(actual, expected string) error {
	if actual == "" || expected == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return domain.ErrInvalidCSRF
	}
	return nil
}

func validateBrowserState(actual, expected string) error {
	if err := validateOpaqueToken(actual); err != nil {
		return err
	}
	if err := validateOpaqueToken(expected); err != nil || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return domain.ErrInvalidBrowserState
	}
	return nil
}

func validateOpaqueToken(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return domain.ErrInvalidBrowserState
	}
	return nil
}

func validateRemember(remember bool, rememberFor int64) error {
	if rememberFor < 0 || rememberFor > int64((24*time.Hour)/time.Second) || (!remember && rememberFor != 0) {
		return domain.ErrInvalidRemember
	}
	return nil
}

type transactionAdmission struct {
	mu       sync.Mutex
	now      func() time.Time
	max      int
	reserved int
	active   map[string]time.Time
}

func newTransactionAdmission(maxPending int, now func() time.Time) *transactionAdmission {
	if maxPending <= 0 {
		maxPending = config.DefaultMaxPendingTransactions
	}
	if now == nil {
		now = time.Now
	}
	return &transactionAdmission{max: maxPending, now: now, active: make(map[string]time.Time)}
}

func (a *transactionAdmission) reserve(expiresAt time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeExpiredLocked()
	if !expiresAt.After(a.now()) || len(a.active)+a.reserved >= a.max {
		return false
	}
	a.reserved++
	return true
}

func (a *transactionAdmission) commit(handle string, expiresAt time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reserved > 0 {
		a.reserved--
	}
	a.active[handle] = expiresAt
}

func (a *transactionAdmission) cancel() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reserved > 0 {
		a.reserved--
	}
}

func (a *transactionAdmission) release(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.active, handle)
}

func (a *transactionAdmission) removeExpiredLocked() {
	now := a.now()
	for handle, expiresAt := range a.active {
		if !expiresAt.After(now) {
			delete(a.active, handle)
		}
	}
}
