package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type config struct {
	publicURL      *url.URL
	adminURL       *url.URL
	operatorEmail  string
	deniedEmail    string
	operatorPass   string
	deniedPassword string
}

type seeder struct {
	cfg    config
	client *http.Client
}

type identity struct {
	ID     string         `json:"id"`
	Traits map[string]any `json:"traits"`
}

type registrationFlow struct {
	ID string `json:"id"`
}

type registrationResponse struct {
	Identity identity `json:"identity"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	seed := &seeder{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if _, err := seed.ensureIdentity(ctx, cfg.operatorEmail, "Real-stack operator", cfg.operatorPass); err != nil {
		fatal(err)
	}
	if _, err := seed.ensureIdentity(ctx, cfg.deniedEmail, "Real-stack denied", cfg.deniedPassword); err != nil {
		fatal(err)
	}
}

func loadConfig() (config, error) {
	publicURL, err := requiredURL("KRATOS_PUBLIC_URL", "http://kratos:4433")
	if err != nil {
		return config{}, err
	}
	adminURL, err := requiredURL("KRATOS_ADMIN_URL", "http://kratos:4434")
	if err != nil {
		return config{}, err
	}
	operatorEmail, err := requiredEnv("REALSTACK_OPERATOR_EMAIL")
	if err != nil {
		return config{}, err
	}
	deniedEmail, err := requiredEnv("REALSTACK_DENIED_EMAIL")
	if err != nil {
		return config{}, err
	}
	operatorPass, err := requiredEnv("REALSTACK_PASSWORD")
	if err != nil {
		return config{}, err
	}
	deniedPassword, err := requiredEnv("REALSTACK_BASIC_PASSWORD")
	if err != nil {
		return config{}, err
	}
	return config{
		publicURL:      publicURL,
		adminURL:       adminURL,
		operatorEmail:  operatorEmail,
		deniedEmail:    deniedEmail,
		operatorPass:   operatorPass,
		deniedPassword: deniedPassword,
	}, nil
}

func (s *seeder) ensureIdentity(ctx context.Context, email, name, password string) (string, error) {
	identities, err := s.listIdentities(ctx)
	if err != nil {
		return "", err
	}
	for _, value := range identities {
		if identityEmail(value) == email && value.ID != "" {
			return value.ID, nil
		}
	}

	flow, err := s.initializeRegistration(ctx)
	if err != nil {
		return "", err
	}
	requestBody, err := json.Marshal(map[string]any{
		"method":   "password",
		"password": password,
		"traits": map[string]string{
			"email": email,
			"name":  name,
		},
	})
	if err != nil {
		return "", fmt.Errorf("encode registration request: %w", err)
	}
	endpoint := endpointURL(s.cfg.publicURL, "/self-service/registration")
	query := endpoint.Query()
	query.Set("flow", flow.ID)
	endpoint.RawQuery = query.Encode()
	response, err := s.doJSON(ctx, http.MethodPost, endpoint, requestBody, "application/json")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", statusError("complete registration", response.StatusCode)
	}

	var result registrationResponse
	if err := decodeBody(response.Body, &result); err != nil {
		return "", fmt.Errorf("decode registration response: %w", err)
	}
	if result.Identity.ID == "" {
		return "", errors.New("registration response did not contain an identity")
	}
	return result.Identity.ID, nil
}

func (s *seeder) listIdentities(ctx context.Context) ([]identity, error) {
	endpoint := endpointURL(s.cfg.adminURL, "/identities")
	query := endpoint.Query()
	query.Set("per_page", "500")
	query.Set("page", "0")
	endpoint.RawQuery = query.Encode()
	response, err := s.doJSON(ctx, http.MethodGet, endpoint, nil, "application/json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, statusError("list identities", response.StatusCode)
	}
	var identities []identity
	if err := decodeBody(response.Body, &identities); err != nil {
		return nil, fmt.Errorf("decode identities response: %w", err)
	}
	return identities, nil
}

func (s *seeder) initializeRegistration(ctx context.Context) (registrationFlow, error) {
	endpoint := endpointURL(s.cfg.publicURL, "/self-service/registration/api")
	response, err := s.doJSON(ctx, http.MethodGet, endpoint, nil, "application/json")
	if err != nil {
		return registrationFlow{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return registrationFlow{}, statusError("initialize registration", response.StatusCode)
	}
	var flow registrationFlow
	if err := decodeBody(response.Body, &flow); err != nil {
		return registrationFlow{}, fmt.Errorf("decode registration flow: %w", err)
	}
	if flow.ID == "" {
		return registrationFlow{}, errors.New("registration flow did not contain an id")
	}
	return flow, nil
}

func (s *seeder) doJSON(ctx context.Context, method string, endpoint *url.URL, body []byte, accept string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create kratos request: %w", err)
	}
	request.Header.Set("Accept", accept)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("kratos request failed: %w", err)
	}
	return response, nil
}

func decodeBody(body io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(body, maxResponseBytes))
	return decoder.Decode(target)
}

func identityEmail(value identity) string {
	email, _ := value.Traits["email"].(string)
	return email
}

func endpointURL(base *url.URL, path string) *url.URL {
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return &endpoint
}

func requiredURL(name, fallback string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP URL", name)
	}
	return parsed, nil
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func statusError(operation string, status int) error {
	return fmt.Errorf("%s returned status %d", operation, status)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
