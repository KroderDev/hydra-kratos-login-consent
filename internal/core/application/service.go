package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/identity"
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

type promptSet struct {
	login         bool
	none          bool
	consent       bool
	selectAccount bool
}

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
// OIDC prompt, max_age, and ACR requirements determine whether Hydra's existing
// session can be accepted or a browser-bound transaction is required.
func (s *Service) StartLogin(ctx context.Context, challenge string, input ports.LoginStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge, s.cfg.EffectiveMaxChallengeLength()); err != nil {
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

	acrValues := request.RequestedACRValues
	if len(acrValues) == 0 && request.RequestedAAL != "" {
		acrValues = []string{request.RequestedAAL}
	}
	requestedAAL, requestedACR, err := s.cfg.ResolveACR(acrValues)
	if err != nil {
		return RedirectResult{}, err
	}
	prompts, err := parsePrompt(request.Prompt)
	if err != nil {
		return RedirectResult{}, domain.ErrInvalidPrompt
	}
	if request.MaxAge != nil && *request.MaxAge < 0 {
		return RedirectResult{}, domain.ErrInvalidAssurance
	}
	requiredAAL := domain.HigherAAL(s.cfg.RequiredAAL, requestedAAL)
	requiresInteraction := !request.Skip || requiredAAL != ""
	if prompts.none && requiresInteraction {
		return s.rejectLogin(ctx, challenge, "login_required", "The login requires user interaction.")
	}
	forceLogin := prompts.login || prompts.selectAccount
	if request.Skip && !forceLogin && requiredAAL == "" {
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
		redirect, err := s.login.AcceptLogin(ctx, challenge, ports.LoginAcceptance{
			Subject: request.Subject,
			ACR:     requestedACR,
		})
		return s.hydraRedirect(redirect, err)
	}

	startedAt := s.now()
	transaction := domain.Transaction{
		Flow:         domain.FlowLogin,
		Challenge:    challenge,
		ClientID:     client.ID,
		Subject:      request.Subject,
		RequestedAAL: requestedAAL,
		RequestedACR: requestedACR,
		Prompt:       request.Prompt,
		MaxAge:       cloneInt64(request.MaxAge),
		StartedAt:    startedAt,
		RequiredAAL:  requiredAAL,
		ExpiresAt:    startedAt.Add(s.cfg.TransactionTTL),
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
	if err == nil && (forceLogin || (request.MaxAge != nil && *request.MaxAge == 0)) {
		redirect, err = addQueryValue(redirect, "force_reauth", "true")
	}
	if err == nil && request.MaxAge != nil {
		redirect, err = addQueryValue(redirect, "max_age", strconv.FormatInt(*request.MaxAge, 10))
	}
	if err == nil && requiredAAL != "" {
		redirect, err = addQueryValue(redirect, "aal", requiredAAL)
	}
	return RedirectResult{URL: redirect, BrowserState: transaction.BrowserState}, err
}

// CompleteLogin consumes a login transaction and accepts it only when the
// Kratos session satisfies the bound subject, freshness, assurance, and policy.
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
	if err := validateLoginFreshness(transaction, session, s.now()); err != nil {
		return s.rejectLogin(ctx, transaction.Challenge, "login_required", "The login session is not fresh enough.")
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
		ACR:         loginAcceptanceACR(transaction, session),
		AMR:         append([]string(nil), session.AMR...),
		Remember:    input.Remember,
		RememberFor: input.RememberFor,
	})
	return s.hydraRedirect(redirect, err)
}

// StartConsent validates a Hydra consent challenge and starts or completes
// consent according to the OIDC prompt and configured skip-consent policy.
func (s *Service) StartConsent(ctx context.Context, challenge string, input ports.ConsentStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge, s.cfg.EffectiveMaxChallengeLength()); err != nil {
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
	prompts, err := parsePrompt(request.Prompt)
	if err != nil {
		return RedirectResult{}, domain.ErrInvalidPrompt
	}
	if prompts.none && !request.Skip && !client.SkipConsent {
		return s.rejectConsent(ctx, challenge, "consent_required", "The consent requires user interaction.")
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
	redirect, err := s.cfg.ExternalConsentRedirectWithAudience(handle, transaction.CSRFToken, request.Client.Name, request.RequestedScopes, request.RequestedAudience)
	if err == nil && !prompts.consent && (request.Skip || client.SkipConsent) {
		redirect, err = addQueryValue(redirect, "skip_consent", "true")
	}
	return RedirectResult{URL: redirect, BrowserState: transaction.BrowserState}, err
}

// CompleteConsent consumes a consent transaction and submits a policy-checked
// result. For acceptance, an omitted audience grant selects every audience in
// the transaction.
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
	grantAudiences := input.GrantAudience
	if len(grantAudiences) == 0 {
		grantAudiences = transaction.RequestedAudience
	}
	if err := validateRequestedSubset(transaction.RequestedAudience, grantAudiences); err != nil {
		return s.rejectConsentFailure(ctx, transaction.Challenge, domain.ErrInvalidAudience, err)
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
	}, client, session, input.GrantScopes, grantAudiences, input.Remember, input.RememberFor)
}

// StartLogout validates a Hydra logout challenge and starts a browser-bound
// logout handoff.
func (s *Service) StartLogout(ctx context.Context, challenge string, input ports.LogoutStartInput) (RedirectResult, error) {
	if err := validateChallenge(challenge, s.cfg.EffectiveMaxChallengeLength()); err != nil {
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

func (s *Service) acceptConsentDecision(ctx context.Context, request domain.ConsentRequest, client config.Client, session domain.Session, scopes, audiences []string, remember bool, rememberFor int64) (RedirectResult, error) {
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
	if len(audiences) == 0 {
		audiences = request.RequestedAudience
	}
	if err := validateRequestedSubset(request.RequestedAudience, audiences); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrInvalidAudience, err)
	}
	decision, err := s.policy.AuthorizeConsent(ctx, ports.PolicyInput{
		Subject:            request.Subject,
		ClientID:           client.ID,
		RequestedScopes:    append([]string(nil), request.RequestedScopes...),
		GrantedScopes:      append([]string(nil), scopes...),
		RequestedAudiences: append([]string(nil), request.RequestedAudience...),
		GrantedAudiences:   append([]string(nil), audiences...),
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
	if err := validateAudienceSubset(audiences, decision.GrantedAudiences); err != nil {
		return s.rejectConsentFailure(ctx, request.Challenge, domain.ErrUpstream, err)
	}
	claims := s.filterClaims(client, decision.Claims, session, decision.GrantedScopes)
	redirect, err := s.consent.AcceptConsent(ctx, request.Challenge, ports.ConsentAcceptance{
		GrantScopes:   append([]string(nil), decision.GrantedScopes...),
		GrantAudience: append([]string(nil), decision.GrantedAudiences...),
		Session:       claims,
		Remember:      remember,
		RememberFor:   rememberFor,
	})
	return s.hydraRedirect(redirect, err)
}

func (s *Service) filterClaims(client config.Client, claims domain.Claims, session domain.Session, scopes []string) domain.Claims {
	result := domain.Claims{
		IDToken: filterClaimMap(
			claims.IDToken,
			client.AllowedIDTokenClaims,
			scopes,
			s.cfg.OIDCIdentityClaimMappings,
		),
		AccessToken: filterClaimMap(
			claims.AccessToken,
			client.AllowedAccessTokenClaims,
			scopes,
			s.cfg.OIDCIdentityClaimMappings,
		),
		UserInfo: filterClaimMap(
			claims.UserInfo,
			client.AllowedUserInfoClaims,
			scopes,
			s.cfg.OIDCIdentityClaimMappings,
		),
	}
	if len(s.cfg.OIDCIdentityClaimMappings) > 0 &&
		(len(client.AllowedIDTokenClaims) > 0 || len(client.AllowedAccessTokenClaims) > 0 || len(client.AllowedUserInfoClaims) > 0) {
		identityClaims := s.cfg.OIDCIdentityClaimMappings.Derive(session, s.cfg.IsSecureEnvironment())
		if len(identityClaims) > 0 {
			result.IDToken = mergeClaims(result.IDToken, filterIdentityClaimMap(
				identityClaims,
				client.AllowedIDTokenClaims,
				scopes,
			))
			result.AccessToken = mergeClaims(result.AccessToken, filterIdentityClaimMap(
				identityClaims,
				client.AllowedAccessTokenClaims,
				scopes,
			))
			result.UserInfo = mergeClaims(result.UserInfo, filterIdentityClaimMap(
				identityClaims,
				client.AllowedUserInfoClaims,
				scopes,
			))
		}
	}
	return result
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

// addQueryValue adds or replaces a query parameter in a URL.
// It returns the updated URL or domain.ErrInvalidRedirect if the target cannot be parsed.
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

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// parsePrompt validates supported OIDC prompt values. Duplicate values,
// unsupported values, and combinations containing none return ErrInvalidPrompt.
func parsePrompt(value string) (promptSet, error) {
	var prompts promptSet
	seen := make(map[string]struct{})
	for _, prompt := range strings.Fields(value) {
		if _, ok := seen[prompt]; ok {
			return promptSet{}, domain.ErrInvalidPrompt
		}
		seen[prompt] = struct{}{}
		switch prompt {
		case "login":
			prompts.login = true
		case "none":
			prompts.none = true
		case "consent":
			prompts.consent = true
		case "select_account":
			prompts.selectAccount = true
		default:
			return promptSet{}, domain.ErrInvalidPrompt
		}
	}
	if prompts.none && len(seen) != 1 {
		return promptSet{}, domain.ErrInvalidPrompt
	}
	return prompts, nil
}

func promptIncludes(prompt, value string) bool {
	for _, item := range strings.Fields(prompt) {
		if item == value {
			return true
		}
	}
	return false
}

// validateLoginFreshness enforces prompt=login and max_age against the session's
// authentication time. Missing, future, or insufficiently fresh timestamps
// return ErrInvalidAssurance.
func validateLoginFreshness(transaction domain.Transaction, session domain.Session, now time.Time) error {
	if !promptIncludes(transaction.Prompt, "login") && transaction.MaxAge == nil {
		return nil
	}
	if session.AuthenticatedAt.IsZero() {
		return domain.ErrInvalidAssurance
	}
	age := now.Sub(session.AuthenticatedAt)
	if age < 0 {
		return domain.ErrInvalidAssurance
	}
	if promptIncludes(transaction.Prompt, "login") && !session.AuthenticatedAt.After(transaction.StartedAt) {
		return domain.ErrInvalidAssurance
	}
	if transaction.MaxAge == nil {
		return nil
	}
	if *transaction.MaxAge < 0 {
		return domain.ErrInvalidAssurance
	}
	if *transaction.MaxAge == 0 {
		if !session.AuthenticatedAt.After(transaction.StartedAt) {
			return domain.ErrInvalidAssurance
		}
		return nil
	}
	ageSeconds := int64(age / time.Second)
	if age%time.Second != 0 {
		ageSeconds++
	}
	if ageSeconds > *transaction.MaxAge {
		return domain.ErrInvalidAssurance
	}
	return nil
}

func loginAcceptanceACR(transaction domain.Transaction, session domain.Session) string {
	if transaction.RequestedACR != "" {
		return transaction.RequestedACR
	}
	return session.AAL
}

// validateChallenge verifies that a challenge is non-empty, within the maximum allowed length, and contains no control characters.
func validateChallenge(value string, maxLength int) error {
	if value == "" || maxLength <= 0 || len(value) > maxLength || strings.IndexFunc(value, unicode.IsControl) >= 0 {
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

// validateAudienceSubset validates that each granted audience was requested and that no audience is granted more than once.
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

// filterClaimMap selects allowed claims whose required scopes are granted, excluding reserved and identity-mapped claims.
// It returns nil when no claims qualify.
func filterClaimMap(source map[string]any, allowed map[string][]string, scopes []string, identityMappings identity.ClaimMappings) map[string]any {
	if len(source) == 0 || len(allowed) == 0 {
		return nil
	}
	result := make(map[string]any)
	for name, value := range source {
		if identity.IsReservedClaim(name) {
			continue
		}
		if _, identityMappingExists := identityMappings[name]; identityMappingExists {
			continue
		}
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

// filterIdentityClaimMap filters identity claims to those allowed for the client and supported by the granted scopes.
func filterIdentityClaimMap(source map[string]any, allowed map[string][]string, scopes []string) map[string]any {
	if len(source) == 0 || len(allowed) == 0 {
		return nil
	}
	result := make(map[string]any)
	for name, value := range source {
		requiredScopes, ok := allowed[name]
		if !ok || !subset(requiredScopes, scopes) || !subset(identity.RequiredScopes(name), scopes) {
			continue
		}
		result[name] = value
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// mergeClaims combines overlay claims into base, replacing values for duplicate claim names.
func mergeClaims(base, overlay map[string]any) map[string]any {
	if len(overlay) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string]any, len(overlay))
	}
	for name, value := range overlay {
		base[name] = value
	}
	return base
}

// subset reports whether every value in required is present in values.
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
	if len(value) != 43 {
		return domain.ErrInvalidBrowserState
	}
	var buf [32]byte
	if _, err := base64.RawURLEncoding.Decode(buf[:], []byte(value)); err != nil {
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
	now := a.now()
	if !expiresAt.After(now) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.active)+a.reserved >= a.max {
		a.removeExpiredLocked(now)
		if len(a.active)+a.reserved >= a.max {
			return false
		}
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

func (a *transactionAdmission) removeExpiredLocked(now time.Time) {
	for handle, expiresAt := range a.active {
		if !expiresAt.After(now) {
			delete(a.active, handle)
		}
	}
}
