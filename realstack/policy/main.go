package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	contractVersion  = "v1"
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 1 << 20
)

type policyServer struct {
	clientID     string
	operatorMail string
	deniedMail   string
	token        []byte
	identities   map[string]string
	client       *http.Client
}

type policyRequest struct {
	Version            string   `json:"version"`
	Operation          string   `json:"operation"`
	Subject            string   `json:"subject"`
	ClientID           string   `json:"client_id"`
	RequestedScopes    []string `json:"requested_scopes"`
	GrantedScopes      []string `json:"granted_scopes"`
	RequestedAudiences []string `json:"requested_audiences"`
	GrantedAudiences   []string `json:"granted_audiences"`
	AAL                string   `json:"aal"`
	AMR                []string `json:"amr"`
}

type kratosIdentity struct {
	ID     string         `json:"id"`
	Traits map[string]any `json:"traits"`
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	server, err := newPolicyServer()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc("/v1/authorize", server.authorize)
	listener := &http.Server{
		Addr:              ":8090",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		if err := listener.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := listener.Shutdown(shutdownContext); err != nil {
			return err
		}
	}
	return nil
}

func newPolicyServer() (*policyServer, error) {
	token := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_TOKEN"))
	if token == "" {
		return nil, errors.New("REALSTACK_POLICY_TOKEN is required")
	}
	clientID := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_CLIENT_ID"))
	if clientID == "" {
		return nil, errors.New("REALSTACK_POLICY_CLIENT_ID is required")
	}
	operatorMail := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_OPERATOR_EMAIL"))
	if operatorMail == "" {
		return nil, errors.New("REALSTACK_POLICY_OPERATOR_EMAIL is required")
	}
	deniedMail := strings.TrimSpace(os.Getenv("REALSTACK_POLICY_DENY_EMAIL"))
	if deniedMail == "" {
		return nil, errors.New("REALSTACK_POLICY_DENY_EMAIL is required")
	}
	adminURL, err := requiredURL("REALSTACK_KRATOS_ADMIN_URL")
	if err != nil {
		return nil, err
	}
	identities, err := loadIdentities(adminURL)
	if err != nil {
		return nil, err
	}
	return &policyServer{
		clientID:     clientID,
		operatorMail: operatorMail,
		deniedMail:   deniedMail,
		token:        []byte(token),
		identities:   identities,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func loadIdentities(adminURL *url.URL) (map[string]string, error) {
	endpoint := *adminURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/identities"
	query := endpoint.Query()
	query.Set("per_page", "500")
	query.Set("page", "0")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create Kratos identity request: %w", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("list Kratos identities: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list Kratos identities returned status %d", response.StatusCode)
	}
	var values []kratosIdentity
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("decode Kratos identities: %w", err)
	}
	identities := make(map[string]string, len(values))
	for _, value := range values {
		if value.ID == "" {
			continue
		}
		email, _ := value.Traits["email"].(string)
		identities[value.ID] = email
	}
	return identities, nil
}

func requiredURL(name string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP URL without query or fragment", name)
	}
	return parsed, nil
}

func (s *policyServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *policyServer) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !s.authorized(r.Header.Get("Authorization")) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	defer r.Body.Close()
	var input policyRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	decision := s.evaluate(input)
	writeDecision(w, decision)
}

func (s *policyServer) authorized(value string) bool {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(value, bearerPrefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(value, bearerPrefix)), s.token) == 1
}

func (s *policyServer) evaluate(input policyRequest) decision {
	if input.Version != contractVersion || input.ClientID != s.clientID || input.Subject == "" || (input.Operation != "login" && input.Operation != "consent") {
		return decision{}
	}
	identityEmail, known := s.identities[input.Subject]
	if !known || identityEmail != s.operatorMail || identityEmail == s.deniedMail || !assuranceAllowed(input) {
		return decision{}
	}
	if input.Operation == "login" {
		return decision{Allowed: true}
	}
	if !subset(input.GrantedScopes, input.RequestedScopes) || !uniqueNonEmpty(input.GrantedScopes) ||
		!subset(input.GrantedAudiences, input.RequestedAudiences) || !uniqueNonEmpty(input.GrantedAudiences) {
		return decision{}
	}
	grantedAudiences := append([]string(nil), input.GrantedAudiences...)
	return decision{
		Allowed:          true,
		GrantedScopes:    append([]string(nil), input.GrantedScopes...),
		GrantedAudiences: grantedAudiences,
		Claims: map[string]any{
			"id_token": map[string]any{
				"email":     s.operatorMail,
				"role":      "operator",
				"sensitive": "not-allowlisted",
			},
			"access_token": map[string]any{
				"tenant": "tenant-realstack",
			},
		},
	}
}

type decision struct {
	Allowed          bool
	GrantedScopes    []string
	GrantedAudiences []string
	Claims           map[string]any
}

func assuranceAllowed(input policyRequest) bool {
	if !contains(input.AMR, "password") {
		return false
	}
	if input.AAL == "aal1" {
		return true
	}
	return input.AAL == "aal2" && contains(input.AMR, "totp")
}

func writeDecision(w http.ResponseWriter, value decision) {
	if value.GrantedScopes == nil {
		value.GrantedScopes = []string{}
	}
	if value.GrantedAudiences == nil {
		value.GrantedAudiences = []string{}
	}
	if value.Claims == nil {
		value.Claims = map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"version":           contractVersion,
		"allowed":           value.Allowed,
		"granted_scopes":    value.GrantedScopes,
		"granted_audiences": value.GrantedAudiences,
		"claims":            value.Claims,
	}); err != nil {
		return
	}
}

func subset(values, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func uniqueNonEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
