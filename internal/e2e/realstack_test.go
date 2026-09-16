//go:build integration && realstack

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	realstackIssuer      = "http://localhost:4444/"
	realstackClientID    = "realstack-client"
	realstackCallbackURL = "http://127.0.0.1:5555/callback"
	realstackLogoutURL   = "http://127.0.0.1:5555/logout-callback"
)

func TestRealstack_OIDCCodePKCEClaimsRememberedConsentAndLogout(t *testing.T) {
	password := realstackRequiredEnv(t, "REALSTACK_PASSWORD")
	basicPassword := realstackRequiredEnv(t, "REALSTACK_BASIC_PASSWORD")
	clientSecret := realstackRequiredEnv(t, "REALSTACK_CLIENT_SECRET")
	callbacks := newRealstackCallbackServer(t)
	browser := newRealstackBrowser(t, callbacks)

	provider := realstackOIDCProvider(t)
	oauthConfig := oauth2.Config{
		ClientID:     realstackClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  realstackCallbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := realstackToken(t)
	nonce := realstackToken(t)
	verifier := oauth2.GenerateVerifier()
	authURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("audience", "https://api.example.test"),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("acr_values", "aal1"),
	)
	first := browser.authorize(t, authURL, "operator@example.com", password, true)
	if first.callback.Values.Get("state") != state {
		t.Fatalf("authorization state did not round-trip")
	}
	code := first.callback.Values.Get("code")
	if code == "" {
		t.Fatalf("authorization callback did not contain a code")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}
	if !token.Valid() {
		t.Fatal("exchanged OAuth token is not valid")
	}
	scope, ok := token.Extra("scope").(string)
	if !ok || !containsAllRealstackStrings(strings.Fields(scope), []string{"openid", "profile", "email"}) {
		t.Fatalf("granted scopes = %q, want openid, profile, and email", scope)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatal("token response did not contain an ID token")
	}
	verifierForIDToken := provider.Verifier(&oidc.Config{ClientID: realstackClientID})
	idToken, err := verifierForIDToken.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	if idToken.Issuer != realstackIssuer {
		t.Fatalf("ID token issuer = %q, want %q", idToken.Issuer, realstackIssuer)
	}
	if !containsRealstackString(idToken.Audience, realstackClientID) {
		t.Fatalf("ID token audience does not contain the registered client")
	}
	if !idToken.Expiry.After(time.Now()) {
		t.Fatal("ID token is already expired")
	}
	if idToken.Nonce != nonce {
		t.Fatal("ID token nonce did not round-trip")
	}
	var claims struct {
		Email     string   `json:"email"`
		Role      string   `json:"role"`
		Sensitive string   `json:"sensitive"`
		ACR       string   `json:"acr"`
		AMR       []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("decode ID token claims: %v", err)
	}
	if claims.Email != "operator@example.com" || claims.Role != "operator" {
		t.Fatalf("ID token identity claims were not mapped as expected")
	}
	if claims.Sensitive != "" {
		t.Fatal("unauthorized policy claim was present in the ID token")
	}
	if claims.ACR != "aal1" || !containsRealstackString(claims.AMR, "password") {
		t.Fatalf("ID token assurance claims did not reflect the Kratos session")
	}

	if first.consentForm == nil {
		t.Fatal("first authorization did not render a consent form")
	}
	replayResponse := browser.submit(t, first.consentForm, first.consentForm.values, "http://localhost:3000")
	closeRealstackResponse(replayResponse)
	if replayResponse.StatusCode < http.StatusBadRequest {
		t.Fatalf("replayed consent status = %d, want a client error", replayResponse.StatusCode)
	}

	secondState := realstackToken(t)
	secondNonce := realstackToken(t)
	secondVerifier := oauth2.GenerateVerifier()
	secondURL := oauthConfig.AuthCodeURL(
		secondState,
		oauth2.S256ChallengeOption(secondVerifier),
		oidc.Nonce(secondNonce),
		oauth2.SetAuthURLParam("audience", "https://api.example.test"),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("acr_values", "aal1"),
	)
	second := browser.authorize(t, secondURL, "operator@example.com", password, false)
	if !second.skippedConsent {
		t.Fatal("remembered consent was not marked as skipped")
	}
	if second.callback.Values.Get("state") != secondState || second.callback.Values.Get("code") == "" {
		t.Fatal("remembered-consent authorization callback was incomplete")
	}

	deniedState := realstackToken(t)
	deniedURL := oauthConfig.AuthCodeURL(
		deniedState,
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier()),
		oidc.Nonce(realstackToken(t)),
		oauth2.SetAuthURLParam("audience", "https://api.example.test"),
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	denied := newRealstackBrowser(t, callbacks).authorizeWithConsentDecision(t, deniedURL, "operator@example.com", password, "deny")
	if denied.Values.Get("state") != deniedState || denied.Values.Get("error") != "access_denied" {
		t.Fatal("rejected consent did not return access_denied")
	}

	rejectedVerifier := oauth2.GenerateVerifier()
	rejectedState := realstackToken(t)
	rejectedURL := oauthConfig.AuthCodeURL(
		rejectedState,
		oauth2.S256ChallengeOption(rejectedVerifier),
		oidc.Nonce(realstackToken(t)),
		oauth2.SetAuthURLParam("audience", "https://api.example.test"),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("acr_values", "aal2"),
	)
	rejected := newRealstackBrowser(t, callbacks).authorizeLoginOnly(t, rejectedURL, "basic@example.com", basicPassword)
	if rejected.Values.Get("state") != rejectedState || rejected.Values.Get("error") != "access_denied" {
		t.Fatal("policy-rejected login did not return access_denied")
	}

	metadata := struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}{}
	if err := provider.Claims(&metadata); err != nil {
		t.Fatalf("read OIDC logout metadata: %v", err)
	}
	if metadata.EndSessionEndpoint == "" {
		t.Fatal("OIDC discovery did not advertise an end-session endpoint")
	}
	logoutState := realstackToken(t)
	logoutEndpoint, err := url.Parse(metadata.EndSessionEndpoint)
	if err != nil {
		t.Fatalf("parse OIDC logout endpoint: %v", err)
	}
	logoutQuery := logoutEndpoint.Query()
	logoutQuery.Set("id_token_hint", rawIDToken)
	logoutQuery.Set("post_logout_redirect_uri", realstackLogoutURL)
	logoutQuery.Set("state", logoutState)
	logoutEndpoint.RawQuery = logoutQuery.Encode()
	logout := browser.follow(t, browser.get(t, logoutEndpoint.String()))
	if logout.callback == nil || logout.callback.Path != "/logout-callback" {
		t.Fatal("logout did not complete through the registered post-logout redirect")
	}
	if logout.callback.Values.Get("state") != logoutState {
		t.Fatal("logout state did not round-trip")
	}
}

func TestRealstack_RejectsUnknownClientRedirectAndChallenge(t *testing.T) {
	client := realstackHTTPClient(t)
	base := "http://localhost:4444/oauth2/auth"
	common := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {realstackCallbackURL},
		"scope":                 {"openid"},
		"state":                 {"realstack-edge-state"},
		"code_challenge":        {"realstack-edge-challenge"},
		"code_challenge_method": {"S256"},
	}

	unknownClient := cloneRealstackValues(common)
	unknownClient.Set("client_id", "unknown-client")
	assertRealstackAuthorizationError(t, "unknown client", realstackGet(t, client, base, unknownClient))

	badRedirect := cloneRealstackValues(common)
	badRedirect.Set("client_id", realstackClientID)
	badRedirect.Set("redirect_uri", "http://127.0.0.1:5555/not-registered")
	assertRealstackAuthorizationError(t, "manipulated redirect", realstackGet(t, client, base, badRedirect))

	challengeURL := "http://localhost:8080/login?login_challenge=unknown-realstack-challenge"
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, challengeURL, nil)
	if err != nil {
		t.Fatal("create unknown challenge request")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request unknown login challenge: %v", err)
	}
	closeRealstackResponse(response)
	if response.StatusCode < http.StatusBadRequest {
		t.Fatalf("unknown challenge status = %d, want a client error", response.StatusCode)
	}
}

type realstackAuthorization struct {
	callback       *realstackCallbackEvent
	consentForm    *realstackForm
	skippedConsent bool
}

type realstackBrowser struct {
	client    *http.Client
	callbacks *realstackCallbackServer
}

func newRealstackBrowser(t *testing.T, callbacks *realstackCallbackServer) *realstackBrowser {
	t.Helper()
	return &realstackBrowser{client: realstackHTTPClient(t), callbacks: callbacks}
}

func (b *realstackBrowser) authorize(t *testing.T, authorizationURL, identifier, password string, remember bool) realstackAuthorization {
	t.Helper()
	page := b.follow(t, b.get(t, authorizationURL))
	if page.form == nil {
		t.Fatalf("authorization did not reach a form: status=%d path=%q", page.status, page.path)
	}
	consent := page.form
	if realstackFormPath(consent) != "/consent" {
		login := page.form
		login.values.Set("identifier", identifier)
		login.values.Set("password", password)
		login.values.Set("method", "password")
		page = b.follow(t, b.submit(t, login, login.values, ""))
		if page.callback != nil {
			return realstackAuthorization{callback: page.callback}
		}
		if page.form == nil {
			t.Fatalf("login did not reach the consent form: status=%d path=%q form_action_path=%q", page.status, page.path, realstackFormPath(page.form))
		}
		consent = page.form
	}
	if realstackFormPath(consent) != "/consent" {
		t.Fatalf("authorization form action path = %q, want /consent", realstackFormPath(consent))
	}
	skipped := consent.values.Get("skip_consent") == "true"
	replay := &realstackForm{action: consent.action, method: consent.method, values: cloneRealstackValues(consent.values)}
	consent.values.Set("decision", "accept")
	if len(consent.values["grant_scope"]) == 0 {
		consent.values.Add("grant_scope", "openid")
	}
	if remember {
		consent.values.Set("remember", "true")
		consent.values.Set("remember_for", "3600")
	}
	page = b.follow(t, b.submit(t, consent, consent.values, "http://localhost:3000"))
	if page.callback == nil {
		t.Fatalf("consent did not reach the registered redirect: status=%d path=%q form_action_path=%q", page.status, page.path, realstackFormPath(page.form))
	}
	return realstackAuthorization{callback: page.callback, consentForm: replay, skippedConsent: skipped}
}

func (b *realstackBrowser) authorizeLoginOnly(t *testing.T, authorizationURL, identifier, password string) *realstackCallbackEvent {
	t.Helper()
	page := b.follow(t, b.get(t, authorizationURL))
	if page.form == nil {
		t.Fatal("rejected authorization did not reach the login form")
	}
	page.form.values.Set("identifier", identifier)
	page.form.values.Set("password", password)
	page.form.values.Set("method", "password")
	page = b.follow(t, b.submit(t, page.form, page.form.values, ""))
	if page.callback == nil {
		t.Fatalf("rejected login did not reach the registered redirect: status=%d path=%q form_action_path=%q", page.status, page.path, realstackFormPath(page.form))
	}
	return page.callback
}

func (b *realstackBrowser) authorizeWithConsentDecision(t *testing.T, authorizationURL, identifier, password, decision string) *realstackCallbackEvent {
	t.Helper()
	page := b.follow(t, b.get(t, authorizationURL))
	if page.form == nil {
		t.Fatal("consent rejection did not reach the login form")
	}
	page.form.values.Set("identifier", identifier)
	page.form.values.Set("password", password)
	page.form.values.Set("method", "password")
	page = b.follow(t, b.submit(t, page.form, page.form.values, ""))
	if page.form == nil {
		t.Fatal("consent rejection did not reach the consent form")
	}
	page.form.values.Set("decision", decision)
	page = b.follow(t, b.submit(t, page.form, page.form.values, "http://localhost:3000"))
	if page.callback == nil {
		t.Fatal("consent rejection did not reach the registered redirect")
	}
	return page.callback
}

func (b *realstackBrowser) get(t *testing.T, target string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("create browser request: %v", err)
	}
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatalf("browser GET: %v", err)
	}
	return response
}

func (b *realstackBrowser) submit(t *testing.T, form *realstackForm, values url.Values, origin string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, form.action, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("create browser form request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatalf("browser form POST: %v", err)
	}
	return response
}

type realstackPage struct {
	form     *realstackForm
	callback *realstackCallbackEvent
	status   int
	path     string
}

func (b *realstackBrowser) follow(t *testing.T, response *http.Response) realstackPage {
	t.Helper()
	for redirects := 0; redirects < 20; redirects++ {
		if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < 400 {
			location, err := response.Location()
			closeRealstackResponse(response)
			if err != nil {
				t.Fatalf("read browser redirect: %v", err)
			}
			if b.callbacks.matches(location) {
				callbackResponse, err := b.client.Get(location.String())
				if err != nil {
					t.Fatalf("request registered callback: %v", err)
				}
				closeRealstackResponse(callbackResponse)
				select {
				case callback := <-b.callbacks.events:
					return realstackPage{callback: callback}
				case <-time.After(2 * time.Second):
					t.Fatal("registered callback was not observed")
				}
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location.String(), nil)
			if err != nil {
				t.Fatalf("create redirect request: %v", err)
			}
			response, err = b.client.Do(request)
			if err != nil {
				t.Fatalf("follow browser redirect: %v", err)
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeRealstackResponse(response)
		if err != nil {
			t.Fatalf("read browser page: %v", err)
		}
		form, err := parseRealstackForm(string(body))
		if err != nil {
			path := ""
			if response.Request != nil && response.Request.URL != nil {
				path = response.Request.URL.Path
			}
			t.Fatalf("parse browser page: status=%d path=%q: %v", response.StatusCode, path, err)
		}
		path := ""
		if response.Request != nil && response.Request.URL != nil {
			path = response.Request.URL.Path
		}
		return realstackPage{form: form, status: response.StatusCode, path: path}
	}
	t.Fatal("browser redirect chain exceeded limit")
	return realstackPage{}
}

func realstackFormPath(form *realstackForm) string {
	if form == nil {
		return ""
	}
	parsed, err := url.Parse(form.action)
	if err != nil {
		return ""
	}
	return parsed.Path
}

type realstackForm struct {
	action string
	method string
	values url.Values
}

var (
	realstackFormTagPattern   = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	realstackInputPattern     = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	realstackAttributePattern = regexp.MustCompile(`(?i)([a-zA-Z_:][a-zA-Z0-9_:.-]*)\s*=\s*"([^"]*)"`)
)

func parseRealstackForm(body string) (*realstackForm, error) {
	formTag := realstackFormTagPattern.FindString(body)
	if formTag == "" {
		return nil, fmt.Errorf("form not found")
	}
	attributes := realstackAttributes(formTag)
	action := html.UnescapeString(attributes["action"])
	if action == "" {
		return nil, fmt.Errorf("form action not found")
	}
	method := strings.ToUpper(attributes["method"])
	if method == "" {
		method = http.MethodPost
	}
	values := make(url.Values)
	for _, inputTag := range realstackInputPattern.FindAllString(body, -1) {
		input := realstackAttributes(inputTag)
		name := html.UnescapeString(input["name"])
		if name == "" {
			continue
		}
		values.Add(name, html.UnescapeString(input["value"]))
	}
	return &realstackForm{action: action, method: method, values: values}, nil
}

func realstackAttributes(tag string) map[string]string {
	attributes := make(map[string]string)
	for _, match := range realstackAttributePattern.FindAllStringSubmatch(tag, -1) {
		attributes[strings.ToLower(match[1])] = match[2]
	}
	return attributes
}

type realstackCallbackEvent struct {
	Path   string
	Values url.Values
}

type realstackCallbackServer struct {
	server *http.Server
	events chan *realstackCallbackEvent
}

func newRealstackCallbackServer(t *testing.T) *realstackCallbackServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:5555")
	if err != nil {
		t.Fatalf("listen on registered callback port: %v", err)
	}
	callbacks := &realstackCallbackServer{events: make(chan *realstackCallbackEvent, 4)}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", callbacks.handle)
	mux.HandleFunc("/logout-callback", callbacks.handle)
	callbacks.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		_ = callbacks.server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = callbacks.server.Shutdown(context.Background())
	})
	return callbacks
}

func (s *realstackCallbackServer) handle(w http.ResponseWriter, r *http.Request) {
	s.events <- &realstackCallbackEvent{Path: r.URL.Path, Values: r.URL.Query()}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "callback received")
}

func (s *realstackCallbackServer) matches(target *url.URL) bool {
	return target != nil && target.Host == "127.0.0.1:5555" && (target.Path == "/callback" || target.Path == "/logout-callback")
}

func realstackOIDCProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	client := realstackHTTPClient(t)
	ctx := oidc.ClientContext(t.Context(), client)
	provider, err := oidc.NewProvider(ctx, realstackIssuer)
	if err != nil {
		t.Fatalf("discover Hydra OIDC provider: %v", err)
	}
	return provider
}

func realstackHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create browser cookie jar: %v", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func realstackGet(t *testing.T, client *http.Client, endpoint string, values url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint+"?"+values.Encode(), nil)
	if err != nil {
		t.Fatalf("create edge-case request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request edge case: %v", err)
	}
	return response
}

func assertRealstackAuthorizationError(t *testing.T, name string, response *http.Response) {
	t.Helper()
	defer closeRealstackResponse(response)
	if response.StatusCode >= http.StatusBadRequest {
		return
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		location, err := response.Location()
		if err == nil && location.Host == "localhost:4444" && location.Path == "/oauth2/fallbacks/error" {
			return
		}
	}
	t.Fatalf("%s response status = %d, want a client error or Hydra fallback error", name, response.StatusCode)
}

func realstackRequiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s must be set for realstack tests", name)
	}
	return value
}

func realstackToken(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatalf("generate OIDC test value: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func cloneRealstackValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}

func containsRealstackString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsAllRealstackStrings(values, wanted []string) bool {
	for _, value := range wanted {
		if !containsRealstackString(values, value) {
			return false
		}
	}
	return true
}

func closeRealstackResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}
