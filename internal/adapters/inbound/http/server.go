// Package http adapts the provider application flows to HTTP requests.
package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

const maxFormBytes = 32 << 10
const maxInFlightRequests = 128
const requestBudget = 12 * time.Second
const requestRatePerSecond = 64

const (
	loginBrowserStateCookie   = "provider_login_state"
	consentBrowserStateCookie = "provider_consent_state"
	logoutBrowserStateCookie  = "provider_logout_state"
)

type Server struct {
	service  ports.Provider
	cfg      config.Config
	logger   *slog.Logger
	inFlight chan struct{}
	rate     *requestLimiter
}

type requestIDContextKey struct{}

// New validates the HTTP adapter configuration and returns a handler facade.
func New(service ports.Provider, cfg config.Config, logger *slog.Logger) (*Server, error) {
	if service == nil {
		return nil, fmt.Errorf("http service is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate http configuration: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		service:  service,
		cfg:      cfg,
		logger:   logger,
		inFlight: make(chan struct{}, maxInFlightRequests),
		rate:     newRequestLimiter(requestRatePerSecond, maxInFlightRequests),
	}, nil
}

// Handler builds the public HTTP router. No Hydra or Kratos admin endpoint is
// exposed by this router.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(s.securityHeaders)
	router.Use(s.requestID)
	router.Use(s.accessLog)
	router.Use(s.requestAdmission)
	router.Use(s.requestTimeout)

	router.Get("/login", s.handleLogin)
	router.Get("/login/callback", s.handleLoginCallback)
	router.Get("/consent", s.handleConsent)
	router.Post("/consent", s.handleConsentSubmit)
	router.Get("/logout", s.handleLogout)
	router.Post("/logout", s.handleLogoutSubmit)
	router.Get("/healthz", s.handleHealth)
	router.Get("/readyz", s.handleReady)

	return router
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "login_challenge", s.cfg.EffectiveMaxChallengeLength())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.StartLogin(r.Context(), challenge, ports.LoginStartInput{
		BrowserState: s.browserStateCookie(r, loginBrowserStateCookie),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setBrowserStateCookie(w, loginBrowserStateCookie, result.BrowserState)
	s.redirect(w, r, result.URL)
}

func (s *Server) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	transaction, err := requiredQuery(r, "transaction", 256)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	csrfToken, err := requiredQuery(r, "csrf", 256)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	remember, rememberFor, err := rememberOptions(r.URL.Query().Get("remember"), r.URL.Query().Get("remember_for"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.CompleteLogin(r.Context(), transaction, ports.LoginInput{
		CSRFToken:    csrfToken,
		BrowserState: s.browserStateCookie(r, loginBrowserStateCookie),
		Credentials:  s.sessionCredentials(r),
		Remember:     remember,
		RememberFor:  rememberFor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "consent_challenge", s.cfg.EffectiveMaxChallengeLength())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.StartConsent(r.Context(), challenge, ports.ConsentStartInput{
		BrowserState: s.browserStateCookie(r, consentBrowserStateCookie),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setBrowserStateCookie(w, consentBrowserStateCookie, result.BrowserState)
	s.redirect(w, r, result.URL)
}

func (s *Server) handleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OriginAllowed(r.Header.Get("Origin")) {
		s.writeError(w, r, domain.ErrInvalidOrigin)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, fmt.Errorf("parse consent form: %w", domain.ErrInvalidForm))
		return
	}
	transaction := strings.TrimSpace(r.Form.Get("transaction"))
	csrfToken := strings.TrimSpace(r.Form.Get("csrf"))
	decision := strings.ToLower(strings.TrimSpace(r.Form.Get("decision")))
	grantScopes := formScopes(r.Form["grant_scope"])
	remember, rememberFor, err := rememberOptions(r.Form.Get("remember"), r.Form.Get("remember_for"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.CompleteConsent(r.Context(), ports.ConsentInput{
		Transaction:  transaction,
		CSRFToken:    csrfToken,
		BrowserState: s.browserStateCookie(r, consentBrowserStateCookie),
		Decision:     decision,
		GrantScopes:  grantScopes,
		Credentials:  s.sessionCredentials(r),
		Remember:     remember,
		RememberFor:  rememberFor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "logout_challenge", s.cfg.EffectiveMaxChallengeLength())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.StartLogout(r.Context(), challenge, ports.LogoutStartInput{
		BrowserState: s.browserStateCookie(r, logoutBrowserStateCookie),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setBrowserStateCookie(w, logoutBrowserStateCookie, result.BrowserState)
	s.redirect(w, r, result.URL)
}

func (s *Server) handleLogoutSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OriginAllowed(r.Header.Get("Origin")) {
		s.writeError(w, r, domain.ErrInvalidOrigin)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, fmt.Errorf("parse logout form: %w", domain.ErrInvalidForm))
		return
	}
	result, err := s.service.CompleteLogout(r.Context(), ports.LogoutInput{
		Transaction:  strings.TrimSpace(r.Form.Get("transaction")),
		CSRFToken:    strings.TrimSpace(r.Form.Get("csrf")),
		BrowserState: s.browserStateCookie(r, logoutBrowserStateCookie),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.service.Ready(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) sessionCredentials(r *http.Request) ports.SessionCredentials {
	cookie, err := r.Cookie(s.cfg.KratosSessionCookie)
	if err != nil {
		return ports.SessionCredentials{CookieName: s.cfg.KratosSessionCookie}
	}
	return ports.SessionCredentials{
		CookieName:  cookie.Name,
		CookieValue: cookie.Value,
	}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if err := validateRedirectTarget(target); err != nil {
		s.writeError(w, r, err)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status := statusForError(err)
	s.logger.ErrorContext(r.Context(), "request failed", "request_id", requestID(r.Context()), "status", status, "error_type", fmt.Sprintf("%T", err))
	s.writeJSON(w, status, map[string]string{"error": publicError(status)})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.logger.Error("write json response", "error", err)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if s.cfg.ProviderURL != nil && s.cfg.ProviderURL.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if !validRequestID(requestID) {
			var err error
			requestID, err = newRequestID()
			if err != nil {
				s.writeError(w, r, fmt.Errorf("create request id: %w", err))
				return
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		started := time.Now()
		next.ServeHTTP(recorder, r)
		route := "unknown"
		if pattern := chi.RouteContext(r.Context()).RoutePattern(); pattern != "" {
			route = pattern
		}
		s.logger.InfoContext(r.Context(), "http request",
			"request_id", requestID(r.Context()),
			"method", r.Method,
			"route", route,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func (s *Server) requestAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.rate.allow() {
			s.writeError(w, r, domain.ErrRateLimited)
			return
		}
		select {
		case s.inFlight <- struct{}{}:
			defer func() { <-s.inFlight }()
			next.ServeHTTP(w, r)
		default:
			s.writeError(w, r, domain.ErrRateLimited)
		}
	})
}

type requestLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRequestLimiter(rate, burst int) *requestLimiter {
	now := time.Now()
	return &requestLimiter{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

func (l *requestLimiter) allow() bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func (s *Server) requestTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestBudget)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(body)
}

func requiredQuery(r *http.Request, name string, maxLength int) (string, error) {
	values, ok := r.URL.Query()[name]
	if !ok || len(values) != 1 {
		return "", domain.ErrInvalidChallenge
	}
	value := strings.TrimSpace(values[0])
	if value == "" || len(value) > maxLength || strings.ContainsAny(value, "\r\n") {
		return "", domain.ErrInvalidChallenge
	}
	return value, nil
}

func formScopes(values []string) []string {
	scopes := make([]string, 0, len(values))
	for _, value := range values {
		scopes = append(scopes, strings.Fields(value)...)
	}
	return scopes
}

func validateRedirectTarget(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(target, "\r\n") {
		return domain.ErrInvalidRedirect
	}
	return nil
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func rememberOptions(rememberValue, rememberForValue string) (bool, int64, error) {
	remember := false
	if rememberValue != "" {
		switch strings.ToLower(strings.TrimSpace(rememberValue)) {
		case "1", "on", "true":
			remember = true
		case "0", "off", "false":
		default:
			return false, 0, domain.ErrInvalidRemember
		}
	}
	if rememberForValue == "" {
		return remember, 0, nil
	}
	rememberFor, err := strconv.ParseInt(rememberForValue, 10, 64)
	if err != nil || rememberFor < 0 || rememberFor > int64((24*time.Hour)/time.Second) || (!remember && rememberFor != 0) {
		return false, 0, domain.ErrInvalidRemember
	}
	return remember, rememberFor, nil
}

func browserStateCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil || len(cookie.Value) > 128 {
		return ""
	}
	return cookie.Value
}

func (s *Server) browserStateCookie(r *http.Request, name string) string {
	return browserStateCookie(r, s.browserStateCookieName(name))
}

func (s *Server) setBrowserStateCookie(w http.ResponseWriter, name, value string) {
	if value == "" {
		return
	}
	name = s.browserStateCookieName(name)
	sameSite := http.SameSiteLaxMode
	secure := s.cfg.ProviderURL != nil && s.cfg.ProviderURL.Scheme == "https"
	if secure {
		sameSite = http.SameSiteNoneMode
	}
	//nolint:gosec // development permits HTTP; non-development Config requires HTTPS.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func (s *Server) browserStateCookieName(name string) string {
	if s.cfg.ProviderURL != nil && s.cfg.ProviderURL.Scheme == "https" {
		return "__Host-" + name
	}
	return name
}

func newRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, domain.ErrInvalidForm):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrInvalidOrigin), errors.Is(err, domain.ErrPolicyDenied):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, domain.ErrUnauthenticated), errors.Is(err, domain.ErrInsufficientAssurance):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrUpstream):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrInvalidChallenge),
		errors.Is(err, domain.ErrInvalidClient),
		errors.Is(err, domain.ErrInvalidRedirect),
		errors.Is(err, domain.ErrInvalidScope),
		errors.Is(err, domain.ErrInvalidAudience),
		errors.Is(err, domain.ErrInvalidAssurance),
		errors.Is(err, domain.ErrInvalidTransaction),
		errors.Is(err, domain.ErrExpiredTransaction),
		errors.Is(err, domain.ErrReplay),
		errors.Is(err, domain.ErrInvalidDecision),
		errors.Is(err, domain.ErrInvalidCSRF),
		errors.Is(err, domain.ErrInvalidBrowserState),
		errors.Is(err, domain.ErrInvalidRemember):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func publicError(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusForbidden:
		return "access_denied"
	case http.StatusUnauthorized:
		return "login_required"
	case http.StatusBadGateway:
		return "temporarily_unavailable"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		return "server_error"
	}
}
