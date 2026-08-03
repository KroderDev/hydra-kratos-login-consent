//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	inboundhttp "github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/inbound/http"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/hydra"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/kratos"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/state"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/application"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestE2E_LoginConsentLogout(t *testing.T) {
	fixture := newFixture(t)

	loginResponse := fixture.get(t, "/login?login_challenge=login-challenge")
	loginLocation := requireRedirect(t, loginResponse)
	if strings.Contains(loginLocation.String(), "login-challenge") {
		t.Fatal("login challenge leaked to external UI")
	}
	loginTransaction := loginLocation.Query().Get("transaction")
	loginCSRF := loginLocation.Query().Get("csrf")
	if loginTransaction == "" || loginCSRF == "" {
		t.Fatalf("login handoff = %s, want transaction and csrf", loginLocation)
	}

	callback := fixture.request(t, http.MethodGet, "/login/callback?transaction="+url.QueryEscape(loginTransaction)+"&csrf="+url.QueryEscape(loginCSRF)+"&remember=true&remember_for=3600", nil)
	callback.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	callbackResponse := fixture.do(t, callback)
	if got := requireRedirect(t, callbackResponse).String(); got != fixture.hydra.redirect("oauth2/auth/callback") {
		t.Fatalf("login callback redirect = %q, want Hydra redirect", got)
	}
	if fixture.hydra.loginAcceptance.Subject != "operator-1" || !fixture.hydra.loginAcceptance.Remember || fixture.hydra.loginAcceptance.RememberFor != 3600 {
		t.Fatalf("login acceptance = %#v, want authenticated remembered subject", fixture.hydra.loginAcceptance)
	}

	consentResponse := fixture.get(t, "/consent?consent_challenge=consent-challenge")
	consentLocation := requireRedirect(t, consentResponse)
	consentTransaction := consentLocation.Query().Get("transaction")
	consentCSRF := consentLocation.Query().Get("csrf")
	if consentTransaction == "" || consentCSRF == "" {
		t.Fatalf("consent handoff = %s, want transaction and csrf", consentLocation)
	}
	consentForm := url.Values{
		"transaction":  {consentTransaction},
		"csrf":         {consentCSRF},
		"decision":     {"accept"},
		"grant_scope":  {"openid"},
		"remember":     {"true"},
		"remember_for": {"7200"},
	}
	consentRequest := fixture.request(t, http.MethodPost, "/consent", strings.NewReader(consentForm.Encode()))
	consentRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentRequest.Header.Set("Origin", "https://ui.example")
	consentRequest.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	consentResult := fixture.do(t, consentRequest)
	if got := requireRedirect(t, consentResult).String(); got != fixture.hydra.redirect("oauth2/consent/callback") {
		t.Fatalf("consent redirect = %q, want Hydra redirect", got)
	}
	if fixture.hydra.consentAcceptance.GrantScopes[0] != "openid" || !fixture.hydra.consentAcceptance.Remember || fixture.hydra.consentAcceptance.RememberFor != 7200 {
		t.Fatalf("consent acceptance = %#v, want reduced remembered consent", fixture.hydra.consentAcceptance)
	}
	if _, ok := fixture.hydra.consentAcceptance.Session.IDToken["role"]; ok {
		t.Fatal("scope-gated role claim was not filtered")
	}

	logoutResponse := fixture.get(t, "/logout?logout_challenge=logout-challenge")
	if got := requireRedirect(t, logoutResponse).String(); got != fixture.hydra.redirect("oauth2/logout/callback") {
		t.Fatalf("logout redirect = %q, want Hydra redirect", got)
	}
	if !fixture.hydra.logoutAccepted {
		t.Fatal("logout challenge was not accepted")
	}
}

func TestE2E_HealthAndReadiness(t *testing.T) {
	fixture := newFixture(t)

	healthResponse := fixture.get(t, "/healthz")
	if healthResponse.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", healthResponse.StatusCode, http.StatusOK)
	}

	readinessResponse := fixture.get(t, "/readyz")
	if readinessResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(readinessResponse.Body)
		t.Fatalf("readiness status = %d, want %d; body = %s", readinessResponse.StatusCode, http.StatusOK, body)
	}
}

func TestE2E_ConsentOriginAndReplayProtection(t *testing.T) {
	fixture := newFixture(t)
	start := fixture.get(t, "/consent?consent_challenge=consent-challenge")
	location := requireRedirect(t, start)
	transaction := location.Query().Get("transaction")
	csrfToken := location.Query().Get("csrf")
	form := url.Values{
		"transaction": {transaction},
		"csrf":        {csrfToken},
		"decision":    {"accept"},
		"grant_scope": {"openid"},
	}

	for _, origin := range []string{"https://attacker.example", ""} {
		request := fixture.request(t, http.MethodPost, "/consent", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		request.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
		response := fixture.do(t, request)
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q status = %d, want %d", origin, response.StatusCode, http.StatusForbidden)
		}
	}

	validRequest := fixture.request(t, http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	validRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validRequest.Header.Set("Origin", "https://ui.example")
	validRequest.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	validResponse := fixture.do(t, validRequest)
	if validResponse.StatusCode != http.StatusFound {
		t.Fatalf("valid consent status = %d, want %d", validResponse.StatusCode, http.StatusFound)
	}

	replayRequest := fixture.request(t, http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRequest.Header.Set("Origin", "https://ui.example")
	replayRequest.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	replayResponse := fixture.do(t, replayRequest)
	if replayResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want %d", replayResponse.StatusCode, http.StatusBadRequest)
	}
}

func TestE2E_ConsentRejectsUnrequestedScope(t *testing.T) {
	fixture := newFixture(t)
	start := fixture.get(t, "/consent?consent_challenge=consent-challenge")
	location := requireRedirect(t, start)
	form := url.Values{
		"transaction": {location.Query().Get("transaction")},
		"csrf":        {location.Query().Get("csrf")},
		"decision":    {"accept"},
		"grant_scope": {"admin"},
	}
	request := fixture.request(t, http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://ui.example")
	request.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	response := fixture.do(t, request)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("invalid scope status = %d, want %d Hydra rejection redirect", response.StatusCode, http.StatusFound)
	}
	if fixture.hydra.consentRejection.Error != "access_denied" {
		t.Fatalf("rejection = %#v, want access_denied", fixture.hydra.consentRejection)
	}
}

func TestE2E_LoginRequiresTransactionCSRF(t *testing.T) {
	fixture := newFixture(t)
	start := fixture.get(t, "/login?login_challenge=login-challenge")
	location := requireRedirect(t, start)
	request := fixture.request(t, http.MethodGet, "/login/callback?transaction="+url.QueryEscape(location.Query().Get("transaction"))+"&csrf=wrong-token", nil)
	request.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session-value"})
	response := fixture.do(t, request)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid login csrf status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	if fixture.hydra.loginAcceptance.Subject != "" {
		t.Fatal("login was accepted with an invalid csrf token")
	}
}

type fixture struct {
	provider *httptest.Server
	hydra    *hydraFixture
	client   *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	hydraServer := httptest.NewUnstartedServer(nil)
	hydraURL := "http://" + hydraServer.Listener.Addr().String()
	hydraState := &hydraFixture{baseURL: hydraURL}
	hydraServer.Config.Handler = http.HandlerFunc(hydraState.serveHTTP)
	hydraServer.Start()
	t.Cleanup(hydraServer.Close)

	kratosServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health/ready" {
			writeStatus(w, http.StatusOK)
			return
		}
		if r.URL.Path != "/sessions/whoami" {
			http.NotFound(w, r)
			return
		}
		cookie, err := r.Cookie("ory_kratos_session")
		if err != nil || cookie.Value != "session-value" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(t, w, map[string]any{
			"active":                        true,
			"authenticator_assurance_level": "aal2",
			"authentication_methods":        []map[string]string{{"method": "oidc"}, {"method": "totp"}},
			"identity":                      map[string]string{"id": "operator-1"},
		})
	}))
	t.Cleanup(kratosServer.Close)

	providerServer := httptest.NewUnstartedServer(nil)
	providerURL := "http://" + providerServer.Listener.Addr().String()

	redisURL := os.Getenv("E2E_REDIS_URL")
	var redisServer *miniredis.Miniredis
	var err error
	if redisURL == "" {
		redisServer, err = miniredis.Run()
		if err != nil {
			t.Fatalf("start redis fixture: %v", err)
		}
		redisURL = "redis://" + redisServer.Addr() + "/0"
		t.Cleanup(redisServer.Close)
	}
	transactionStore, err := state.NewRedisStore(redisURL, "e2e:transaction:")
	if err != nil {
		t.Fatalf("create redis fixture: %v", err)
	}
	t.Cleanup(func() { _ = transactionStore.Close() })

	providerURLValue := parseURL(t, providerURL)
	uiURL := parseURL(t, "https://ui.example/login")
	hydraURLValue := parseURL(t, hydraURL)
	kratosURLValue := parseURL(t, kratosServer.URL)
	cfg := config.Config{
		ListenAddress:       providerURLValue.Host,
		ProviderURL:         providerURLValue,
		ExternalUIURL:       uiURL,
		HydraAdminURL:       hydraURLValue,
		HydraPublicURL:      hydraURLValue,
		KratosPublicURL:     kratosURLValue,
		KratosSessionCookie: "ory_kratos_session",
		RequiredAAL:         "aal2",
		TransactionTTL:      5 * time.Minute,
		Clients: map[string]config.Client{
			"example-client": {
				ID:                         "example-client",
				AllowedRedirectURIs:        []string{"https://client.example/callback"},
				AllowedPostLogoutRedirects: []string{"https://client.example/logout"},
				AllowedScopes:              []string{"openid", "profile"},
				AllowedIDTokenClaims: map[string][]string{
					"email": nil,
					"role":  {"profile"},
				},
			},
		},
	}
	hydraClient, err := hydra.New(hydraURLValue, &http.Client{Timeout: 2 * time.Second}, "")
	if err != nil {
		t.Fatalf("create Hydra adapter: %v", err)
	}
	kratosClient, err := kratos.New(kratosURLValue, &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("create Kratos adapter: %v", err)
	}
	providerPolicy := e2ePolicy{}
	service, err := application.NewService(cfg, application.Dependencies{
		Login:     hydraClient,
		Consent:   hydraClient,
		Logout:    hydraClient,
		Kratos:    kratosClient,
		State:     transactionStore,
		Policy:    providerPolicy,
		Readiness: []ports.Readiness{hydraClient, kratosClient, transactionStore},
	})
	if err != nil {
		t.Fatalf("create provider service: %v", err)
	}
	api, err := inboundhttp.New(service, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("create provider HTTP adapter: %v", err)
	}
	providerServer.Config.Handler = api.Handler()
	providerServer.Start()
	t.Cleanup(providerServer.Close)

	return &fixture{
		provider: providerServer,
		hydra:    hydraState,
		client:   &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (f *fixture) get(t *testing.T, path string) *http.Response {
	t.Helper()
	return f.do(t, f.request(t, http.MethodGet, path, nil))
}

func (f *fixture) request(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, f.provider.URL+path, body)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	return request
}

func (f *fixture) do(t *testing.T, request *http.Request) *http.Response {
	t.Helper()
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", request.Method, request.URL, err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func requireRedirect(t *testing.T, response *http.Response) *url.URL {
	t.Helper()
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want %d; body = %s", response.StatusCode, http.StatusFound, body)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || location.Scheme == "" || location.Host == "" {
		t.Fatalf("invalid redirect location %q: %v", response.Header.Get("Location"), err)
	}
	return location
}

func parseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse URL %q: %v", value, err)
	}
	return parsed
}

type hydraFixture struct {
	mu                sync.Mutex
	baseURL           string
	loginAcceptance   ports.LoginAcceptance
	consentAcceptance ports.ConsentAcceptance
	consentRejection  ports.Rejection
	logoutAccepted    bool
}

func (f *hydraFixture) redirect(path string) string {
	return f.baseURL + "/" + path
}

func (f *hydraFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health/ready":
		writeStatus(w, http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Path == "/admin/oauth2/auth/requests/login":
		writeJSONNoTest(w, map[string]any{
			"challenge": r.URL.Query().Get("login_challenge"),
			"client": map[string]any{
				"client_id":     "example-client",
				"client_name":   "Example Client",
				"redirect_uris": []string{"https://client.example/callback"},
			},
			"skip":         false,
			"oidc_context": map[string]any{"acr_values": []string{"aal2"}},
		})
	case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/login/accept":
		var body struct {
			Subject     string `json:"subject"`
			Remember    bool   `json:"remember"`
			RememberFor int64  `json:"remember_for"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.loginAcceptance = ports.LoginAcceptance{Subject: body.Subject, Remember: body.Remember, RememberFor: body.RememberFor}
		f.mu.Unlock()
		writeJSONNoTest(w, map[string]string{"redirect_to": f.redirect("oauth2/auth/callback")})
	case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/login/reject":
		writeJSONNoTest(w, map[string]string{"redirect_to": f.redirect("oauth2/auth/rejected")})
	case r.Method == http.MethodGet && r.URL.Path == "/admin/oauth2/auth/requests/consent":
		writeJSONNoTest(w, map[string]any{
			"challenge":                       r.URL.Query().Get("consent_challenge"),
			"subject":                         "operator-1",
			"requested_scope":                 []string{"openid", "profile"},
			"requested_access_token_audience": []string{"example-api"},
			"client": map[string]any{
				"client_id":     "example-client",
				"client_name":   "Example Client",
				"redirect_uris": []string{"https://client.example/callback"},
			},
			"skip": false,
		})
	case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/consent/accept":
		var body struct {
			GrantScope  []string `json:"grant_scope"`
			Remember    bool     `json:"remember"`
			RememberFor int64    `json:"remember_for"`
			Session     struct {
				IDToken map[string]any `json:"id_token"`
			} `json:"session"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.consentAcceptance = ports.ConsentAcceptance{
			GrantScopes: body.GrantScope,
			Remember:    body.Remember,
			RememberFor: body.RememberFor,
			Session:     domain.Claims{IDToken: body.Session.IDToken},
		}
		f.mu.Unlock()
		writeJSONNoTest(w, map[string]string{"redirect_to": f.redirect("oauth2/consent/callback")})
	case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/consent/reject":
		var body ports.Rejection
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.consentRejection = body
		f.mu.Unlock()
		writeJSONNoTest(w, map[string]string{"redirect_to": f.redirect("oauth2/consent/rejected")})
	case r.Method == http.MethodGet && r.URL.Path == "/admin/oauth2/auth/requests/logout":
		requestURL := f.baseURL + "/oauth2/sessions/logout?post_logout_redirect_uri=" + url.QueryEscape("https://client.example/logout")
		writeJSONNoTest(w, map[string]any{
			"challenge":   r.URL.Query().Get("logout_challenge"),
			"request_url": requestURL,
			"client": map[string]any{
				"client_id":     "example-client",
				"redirect_uris": []string{"https://client.example/callback"},
			},
		})
	case r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/logout/accept":
		f.mu.Lock()
		f.logoutAccepted = true
		f.mu.Unlock()
		writeJSONNoTest(w, map[string]string{"redirect_to": f.redirect("oauth2/logout/callback")})
	default:
		writeStatus(w, http.StatusNotFound)
	}
}

type e2ePolicy struct{}

func (e2ePolicy) AuthorizeLogin(context.Context, string, string) (bool, error) {
	return true, nil
}

func (e2ePolicy) AuthorizeConsent(context.Context, string, string, []string) (ports.ConsentDecision, error) {
	return ports.ConsentDecision{
		Allowed: true,
		Claims: domain.Claims{IDToken: map[string]any{
			"email": "operator@example.com",
			"role":  "operator",
		}},
	}, nil
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	writeJSONNoTest(w, value)
}

func writeJSONNoTest(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}
