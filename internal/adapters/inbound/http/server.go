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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

const maxFormBytes = 32 << 10

type Server struct {
	service ports.Provider
	cfg     config.Config
	logger  *slog.Logger
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
	return &Server{service: service, cfg: cfg, logger: logger}, nil
}

// Handler builds the public HTTP router. No Hydra or Kratos admin endpoint is
// exposed by this router.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(s.securityHeaders)
	router.Use(s.requestID)
	router.Use(s.accessLog)

	router.Get("/login", s.handleLogin)
	router.Get("/login/callback", s.handleLoginCallback)
	router.Get("/consent", s.handleConsent)
	router.Post("/consent", s.handleConsentSubmit)
	router.Get("/logout", s.handleLogout)
	router.Get("/healthz", s.handleHealth)
	router.Get("/readyz", s.handleReady)

	return router
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "login_challenge", 512)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.StartLogin(r.Context(), challenge)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
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
		CSRFToken:   csrfToken,
		Credentials: s.sessionCredentials(r),
		Remember:    remember,
		RememberFor: rememberFor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "consent_challenge", 512)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.StartConsent(r.Context(), challenge)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OriginAllowed(r.Header.Get("Origin")) {
		s.writeError(w, r, domain.ErrInvalidOrigin)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, fmt.Errorf("parse consent form: %w", err))
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
		Transaction: transaction,
		CSRFToken:   csrfToken,
		Decision:    decision,
		GrantScopes: grantScopes,
		Credentials: s.sessionCredentials(r),
		Remember:    remember,
		RememberFor: rememberFor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.redirect(w, r, result.URL)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	challenge, err := requiredQuery(r, "logout_challenge", 512)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.Logout(r.Context(), challenge)
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
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(target, "\r\n") {
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
	if err != nil || rememberFor < 0 {
		return false, 0, domain.ErrInvalidRemember
	}
	return remember, rememberFor, nil
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
	case errors.Is(err, domain.ErrInvalidOrigin), errors.Is(err, domain.ErrPolicyDenied):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrUnauthenticated), errors.Is(err, domain.ErrInsufficientAssurance):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrUpstream):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrInvalidChallenge),
		errors.Is(err, domain.ErrInvalidClient),
		errors.Is(err, domain.ErrInvalidRedirect),
		errors.Is(err, domain.ErrInvalidScope),
		errors.Is(err, domain.ErrInvalidTransaction),
		errors.Is(err, domain.ErrExpiredTransaction),
		errors.Is(err, domain.ErrReplay),
		errors.Is(err, domain.ErrInvalidDecision),
		errors.Is(err, domain.ErrInvalidCSRF),
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
	default:
		return "server_error"
	}
}
