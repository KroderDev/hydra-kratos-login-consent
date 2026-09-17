//go:build integration && realstack

package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	realstackClientID    = "realstack-client"
	realstackCallbackURL = "http://127.0.0.1:5555/callback"
	realstackLogoutURL   = "http://127.0.0.1:5555/logout-callback"
)

func TestRealstackOIDCCodePKCEClaimsRememberedConsentAndLogout(t *testing.T) {
	password := realstackRequiredEnv(t, "REALSTACK_PASSWORD")
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
	first := browser.authorize(t, authURL, "operator@example.com", password, authorizeOptions{
		remember: true,
	})
	if first.callback.Values.Get("state") != state {
		t.Fatal("authorization state did not round-trip")
	}
	code := first.callback.Values.Get("code")
	if code == "" {
		t.Fatal("authorization callback did not contain a code")
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
	idToken, err := provider.Verifier(&oidc.Config{ClientID: realstackClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	if idToken.Issuer != realstackIssuer(t) {
		t.Fatalf("ID token issuer = %q, want configured Hydra issuer", idToken.Issuer)
	}
	if !containsRealstackString(idToken.Audience, realstackClientID) {
		t.Fatal("ID token audience does not contain the registered client")
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
		t.Fatal("ID token identity claims were not mapped as expected")
	}
	if claims.Sensitive != "" {
		t.Fatal("unauthorized policy claim was present in the ID token")
	}
	if claims.ACR != "aal1" || !containsRealstackString(claims.AMR, "password") {
		t.Fatal("ID token assurance claims did not reflect the Kratos session")
	}

	if first.consentForm == nil {
		t.Fatal("first authorization did not render a consent form")
	}
	replayResponse := browser.submit(t, first.consentForm, first.consentForm.values, realstackUIOrigin(t))
	if replayResponse.StatusCode < http.StatusBadRequest {
		closeRealstackResponse(replayResponse)
		t.Fatalf("replayed consent status = %d, want a client error", replayResponse.StatusCode)
	}
	closeRealstackResponse(replayResponse)

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
	second := browser.authorize(t, secondURL, "operator@example.com", password, authorizeOptions{})
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
	)
	denied := newRealstackBrowser(t, callbacks).authorizeWithConsentDecision(t, deniedURL, "operator@example.com", password, "deny")
	if denied.Values.Get("state") != deniedState || denied.Values.Get("error") != "access_denied" {
		t.Fatal("rejected consent did not return access_denied")
	}

	totpSecret := enrollRealstackTOTP(t, password)
	aal2State := realstackToken(t)
	aal2Nonce := realstackToken(t)
	aal2Verifier := oauth2.GenerateVerifier()
	aal2URL := oauthConfig.AuthCodeURL(
		aal2State,
		oauth2.S256ChallengeOption(aal2Verifier),
		oidc.Nonce(aal2Nonce),
		oauth2.SetAuthURLParam("audience", "https://api.example.test"),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("acr_values", "aal2"),
	)
	aal2 := browser.authorize(t, aal2URL, "operator@example.com", password, authorizeOptions{
		totpSecret: totpSecret,
	})
	if aal2.callback == nil || aal2.callback.Values.Get("state") != aal2State {
		t.Fatal("AAL2 authorization callback was incomplete")
	}
	aal2Code := aal2.callback.Values.Get("code")
	aal2Ctx, aal2Cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer aal2Cancel()
	aal2Token, err := oauthConfig.Exchange(aal2Ctx, aal2Code, oauth2.VerifierOption(aal2Verifier))
	if err != nil {
		t.Fatalf("exchange AAL2 authorization code: %v", err)
	}
	aal2RawIDToken, ok := aal2Token.Extra("id_token").(string)
	if !ok || aal2RawIDToken == "" {
		t.Fatal("AAL2 token response did not contain an ID token")
	}
	aal2IDToken, err := provider.Verifier(&oidc.Config{ClientID: realstackClientID}).Verify(aal2Ctx, aal2RawIDToken)
	if err != nil {
		t.Fatalf("verify AAL2 ID token: %v", err)
	}
	if aal2IDToken.Nonce != aal2Nonce {
		t.Fatal("AAL2 ID token nonce did not round-trip")
	}
	var aal2Claims struct {
		ACR string   `json:"acr"`
		AMR []string `json:"amr"`
	}
	if err := aal2IDToken.Claims(&aal2Claims); err != nil {
		t.Fatalf("decode AAL2 ID token claims: %v", err)
	}
	if aal2Claims.ACR != "aal2" || !containsAllRealstackStrings(aal2Claims.AMR, []string{"password", "totp"}) {
		t.Fatal("AAL2 ID token assurance claims did not reflect password and TOTP authentication")
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
	logoutEndpoint, err := url.Parse(metadata.EndSessionEndpoint)
	if err != nil {
		t.Fatalf("parse OIDC logout endpoint: %v", err)
	}
	logoutState := realstackToken(t)
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

func TestRealstackRejectsPromptNoneUnknownClientRedirectAndChallenge(t *testing.T) {
	callbacks := newRealstackCallbackServer(t)
	browser := newRealstackBrowser(t, callbacks)
	provider := realstackOIDCProvider(t)
	oauthConfig := oauth2.Config{
		ClientID:    realstackClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: realstackCallbackURL,
		Scopes:      []string{oidc.ScopeOpenID},
	}

	silentState := realstackToken(t)
	silentURL := oauthConfig.AuthCodeURL(
		silentState,
		oauth2.SetAuthURLParam("prompt", "none"),
		oauth2.SetAuthURLParam("nonce", realstackToken(t)),
		oauth2.SetAuthURLParam("code_challenge", realstackToken(t)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	silent := browser.follow(t, browser.get(t, silentURL))
	if silent.callback == nil || silent.callback.Values.Get("state") != silentState || silent.callback.Values.Get("error") != "login_required" {
		t.Fatal("prompt=none did not return login_required")
	}

	client := realstackHTTPClient(t)
	common := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {realstackCallbackURL},
		"scope":                 {"openid"},
		"state":                 {realstackToken(t)},
		"code_challenge":        {realstackToken(t)},
		"code_challenge_method": {"S256"},
	}
	unknownClient := cloneRealstackValues(common)
	unknownClient.Set("client_id", "unknown-client")
	assertRealstackAuthorizationError(t, "unknown client", realstackGet(t, client, realstackAuthorizationEndpoint(t), unknownClient))

	badRedirect := cloneRealstackValues(common)
	badRedirect.Set("client_id", realstackClientID)
	badRedirect.Set("redirect_uri", "http://127.0.0.1:5555/not-registered")
	assertRealstackAuthorizationError(t, "manipulated redirect", realstackGet(t, client, realstackAuthorizationEndpoint(t), badRedirect))

	challengeEndpoint := realstackProviderURL(t) + "/login?login_challenge=unknown-realstack-challenge"
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, challengeEndpoint, nil)
	if err != nil {
		t.Fatal("create unknown challenge request")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request unknown challenge: %v", err)
	}
	if response.StatusCode < http.StatusBadRequest {
		closeRealstackResponse(response)
		t.Fatalf("unknown challenge status = %d, want a client error", response.StatusCode)
	}
	closeRealstackResponse(response)
}

type authorizeOptions struct {
	remember      bool
	grantScopes   []string
	grantAudience []string
	totpSecret    string
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

func (b *realstackBrowser) authorize(t *testing.T, authorizationURL, identifier, password string, options authorizeOptions) realstackAuthorization {
	t.Helper()
	page := b.follow(t, b.get(t, authorizationURL))
	if page.callback != nil {
		return realstackAuthorization{callback: page.callback}
	}
	if page.form == nil {
		t.Fatalf("authorization did not reach a form: status=%d path=%q", page.status, page.path)
	}
	if realstackFormPath(page.form) != "/consent" {
		login := page.form
		login.values.Set("identifier", identifier)
		login.values.Set("password", password)
		login.values.Set("method", "password")
		page = b.follow(t, b.submit(t, login, login.values, ""))
		if page.callback != nil {
			return realstackAuthorization{callback: page.callback}
		}
		if page.form == nil {
			t.Fatalf("login did not reach consent: status=%d path=%q", page.status, page.path)
		}
		if realstackFormPath(page.form) != "/consent" {
			_, hasTOTPCode := page.form.values["totp_code"]
			if options.totpSecret == "" || !hasTOTPCode {
				t.Fatalf("login did not reach consent or TOTP verification: status=%d path=%q fields=%s", page.status, page.path, realstackFormFields(page.form))
			}
			page.form.values.Set("totp_code", realstackTOTPCode(t, options.totpSecret, time.Now()))
			page.form.values.Set("method", "totp")
			page = b.follow(t, b.submit(t, page.form, page.form.values, ""))
			if page.callback != nil {
				return realstackAuthorization{callback: page.callback}
			}
			if page.form == nil {
				t.Fatalf("TOTP login did not reach consent: status=%d path=%q", page.status, page.path)
			}
		}
	}
	if realstackFormPath(page.form) != "/consent" {
		t.Fatalf("authorization form action path = %q, want /consent; fields=%s", realstackFormPath(page.form), realstackFormFields(page.form))
	}
	consent := page.form
	skipped := consent.values.Get("skip_consent") == "true"
	replay := &realstackForm{action: consent.action, method: consent.method, values: cloneRealstackValues(consent.values)}
	consent.values.Del("grant_scope")
	for _, scope := range options.grantScopes {
		consent.values.Add("grant_scope", scope)
	}
	if len(options.grantScopes) == 0 {
		for _, scope := range replay.values["grant_scope"] {
			consent.values.Add("grant_scope", scope)
		}
	}
	consent.values.Del("grant_audience")
	for _, audience := range options.grantAudience {
		consent.values.Add("grant_audience", audience)
	}
	if len(options.grantAudience) == 0 {
		for _, audience := range replay.values["grant_audience"] {
			consent.values.Add("grant_audience", audience)
		}
	}
	consent.values.Set("decision", "accept")
	if options.remember {
		consent.values.Set("remember", "true")
		consent.values.Set("remember_for", "3600")
	}
	page = b.follow(t, b.submit(t, consent, consent.values, realstackUIOrigin(t)))
	if page.callback == nil {
		t.Fatalf("consent did not reach the registered redirect: status=%d path=%q", page.status, page.path)
	}
	return realstackAuthorization{callback: page.callback, consentForm: replay, skippedConsent: skipped}
}

type realstackKratosFlow struct {
	ID string `json:"id"`
	UI struct {
		Nodes []realstackKratosNode `json:"nodes"`
	} `json:"ui"`
}

type realstackKratosNode struct {
	Attributes struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Text  *struct {
			Context struct {
				Secret string `json:"secret"`
			} `json:"context"`
		} `json:"text"`
	} `json:"attributes"`
}

type realstackKratosLoginResponse struct {
	SessionToken string `json:"session_token"`
}

func enrollRealstackTOTP(t *testing.T, password string) string {
	t.Helper()
	client := realstackHTTPClient(t)
	loginFlow := realstackKratosFlowRequest(t, client, http.MethodGet, "http://127.0.0.1:4433/self-service/login/api", "", nil)
	loginPayload := map[string]string{
		"method":     "password",
		"identifier": "operator@example.com",
		"password":   password,
	}
	loginResponse := realstackKratosJSONRequest(t, client, http.MethodPost, "http://127.0.0.1:4433/self-service/login?flow="+url.QueryEscape(loginFlow.ID), "", loginPayload)
	var loginResult realstackKratosLoginResponse
	decodeRealstackKratosResponse(t, loginResponse, &loginResult)
	if loginResult.SessionToken == "" {
		t.Fatal("Kratos API login did not return a session token")
	}

	settingsEndpoint := "http://127.0.0.1:4433/self-service/settings/api"
	settingsFlow := realstackKratosFlowRequest(t, client, http.MethodGet, settingsEndpoint, loginResult.SessionToken, nil)
	var secret string
	for _, node := range settingsFlow.UI.Nodes {
		if node.Attributes.Text != nil && node.Attributes.Text.Context.Secret != "" {
			secret = node.Attributes.Text.Context.Secret
			break
		}
	}
	if secret == "" {
		t.Fatal("Kratos settings flow did not return a TOTP enrollment secret")
	}
	settingsPayload := map[string]string{
		"method":    "totp",
		"totp_code": realstackTOTPCode(t, secret, time.Now()),
	}
	settingsResponse := realstackKratosJSONRequest(t, client, http.MethodPost, "http://127.0.0.1:4433/self-service/settings?flow="+url.QueryEscape(settingsFlow.ID), loginResult.SessionToken, settingsPayload)
	if settingsResponse.StatusCode != http.StatusOK {
		closeRealstackResponse(settingsResponse)
		t.Fatalf("Kratos TOTP enrollment status = %d, want %d", settingsResponse.StatusCode, http.StatusOK)
	}
	closeRealstackResponse(settingsResponse)
	return secret
}

func realstackKratosFlowRequest(t *testing.T, client *http.Client, method, endpoint, token string, payload any) realstackKratosFlow {
	t.Helper()
	response := realstackKratosJSONRequest(t, client, method, endpoint, token, payload)
	var flow realstackKratosFlow
	decodeRealstackKratosResponse(t, response, &flow)
	if flow.ID == "" {
		t.Fatal("Kratos flow did not return an ID")
	}
	return flow
}

func realstackKratosJSONRequest(t *testing.T, client *http.Client, method, endpoint, token string, payload any) *http.Response {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal("encode Kratos API request")
		}
		body = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, body)
	if err != nil {
		t.Fatal("create Kratos API request")
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("Kratos API request failed")
	}
	return response
}

func decodeRealstackKratosResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer closeRealstackResponse(response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Kratos API response status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
		t.Fatal("decode Kratos API response")
	}
}

func realstackTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	encoded := strings.TrimRight(strings.ToUpper(strings.TrimSpace(secret)), "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatal("decode TOTP enrollment secret")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	digest := hmac.New(sha1.New, key)
	_, _ = digest.Write(counter[:])
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", value)
}

func (b *realstackBrowser) authorizeWithConsentDecision(t *testing.T, authorizationURL, identifier, password, decision string) *realstackCallbackEvent {
	t.Helper()
	page := b.follow(t, b.get(t, authorizationURL))
	if page.form == nil {
		t.Fatal("consent decision did not reach a form")
	}
	if realstackFormPath(page.form) != "/consent" {
		page.form.values.Set("identifier", identifier)
		page.form.values.Set("password", password)
		page.form.values.Set("method", "password")
		page = b.follow(t, b.submit(t, page.form, page.form.values, ""))
		if page.form == nil {
			t.Fatal("consent decision did not reach the consent form")
		}
	}
	page.form.values.Set("decision", decision)
	page = b.follow(t, b.submit(t, page.form, page.form.values, realstackUIOrigin(t)))
	if page.callback == nil {
		t.Fatal("consent decision did not reach the registered redirect")
	}
	return page.callback
}

func (b *realstackBrowser) get(t *testing.T, target string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal("create browser request")
	}
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatalf("browser GET: %v", err)
	}
	return response
}

func (b *realstackBrowser) submit(t *testing.T, form *realstackForm, values url.Values, origin string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, form.action, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal("create browser form request")
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
	for redirects := 0; redirects < 30; redirects++ {
		if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
			location, err := response.Location()
			closeRealstackResponse(response)
			if err != nil {
				t.Fatal("read browser redirect")
			}
			if b.callbacks.matches(location) {
				callbackResponse, err := b.client.Get(location.String())
				if err != nil {
					t.Fatal("request registered callback")
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
				t.Fatal("create redirect request")
			}
			response, err = b.client.Do(request)
			if err != nil {
				t.Fatalf("follow browser redirect: %v", err)
			}
			continue
		}
		status := response.StatusCode
		path := ""
		if response.Request != nil && response.Request.URL != nil {
			path = response.Request.URL.Path
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeRealstackResponse(response)
		if err != nil {
			t.Fatal("read browser page")
		}
		form, err := parseRealstackForm(string(body))
		if err != nil {
			reason := realstackPageError(body)
			if reason == "" {
				reason = err.Error()
			}
			t.Fatalf("parse browser page: status=%d path=%q: %s", status, path, reason)
		}
		return realstackPage{form: form, status: status, path: path}
	}
	t.Fatal("browser redirect chain exceeded limit")
	return realstackPage{}
}

func realstackPageError(body []byte) string {
	text := string(body)
	for _, reason := range []string{
		"unable to load flow",
		"invalid flow action",
		"flow has no usable fields",
		"invalid flow",
	} {
		if strings.Contains(text, reason) {
			return reason
		}
	}
	return ""
}

type realstackForm struct {
	action string
	method string
	values url.Values
}

var (
	realstackFormTagPattern   = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	realstackInputPattern     = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	realstackAttributePattern = regexp.MustCompile(`(?i)([a-zA-Z_:][a-zA-Z0-9_:.-]*)\s*=\s*"([^"]*)"`)
)

func parseRealstackForm(body string) (*realstackForm, error) {
	formBlock := realstackFormTagPattern.FindString(body)
	if formBlock == "" {
		return nil, fmt.Errorf("form not found")
	}
	formTagEnd := strings.Index(formBlock, ">")
	if formTagEnd < 0 {
		return nil, fmt.Errorf("form tag not found")
	}
	attributes := realstackAttributes(formBlock[:formTagEnd+1])
	action := html.UnescapeString(attributes["action"])
	if action == "" {
		return nil, fmt.Errorf("form action not found")
	}
	method := strings.ToUpper(attributes["method"])
	if method == "" {
		method = http.MethodPost
	}
	values := make(url.Values)
	for _, inputTag := range realstackInputPattern.FindAllString(formBlock, -1) {
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

func realstackFormFields(form *realstackForm) string {
	if form == nil {
		return ""
	}
	fields := make([]string, 0, len(form.values))
	for name, values := range form.values {
		if name == "method" {
			fields = append(fields, name+"="+strings.Join(values, ","))
			continue
		}
		fields = append(fields, name)
	}
	return strings.Join(fields, ",")
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
	callbacks := &realstackCallbackServer{events: make(chan *realstackCallbackEvent, 8)}
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
}

func (s *realstackCallbackServer) matches(target *url.URL) bool {
	return target != nil && target.Host == "127.0.0.1:5555" && (target.Path == "/callback" || target.Path == "/logout-callback")
}

func realstackOIDCProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	client := realstackHTTPClient(t)
	provider, err := oidc.NewProvider(oidc.ClientContext(t.Context(), client), realstackIssuer(t))
	if err != nil {
		t.Fatalf("discover Hydra OIDC provider: %v", err)
	}
	return provider
}

func realstackHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("create browser cookie jar")
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
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("parse edge-case endpoint")
	}
	parsed.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, parsed.String(), nil)
	if err != nil {
		t.Fatal("create edge-case request")
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
		if err == nil {
			if location.Path == "/oauth2/fallbacks/error" {
				return
			}
			if location.Host == "127.0.0.1:5555" &&
				location.Query().Get("error") != "" &&
				location.Query().Get("code") == "" {
				return
			}
		}
	}
	t.Fatalf("%s response status = %d, want a client error", name, response.StatusCode)
}

func realstackRequiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s must be set for realstack tests", name)
	}
	return value
}

func realstackIssuer(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("REALSTACK_HYDRA_PUBLIC_URL"))
	if value == "" {
		value = "http://127.0.0.1:4444/"
	}
	if !strings.HasSuffix(value, "/") {
		value += "/"
	}
	return value
}

func realstackProviderURL(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("REALSTACK_PROVIDER_URL"))
	if value != "" {
		return strings.TrimRight(value, "/")
	}
	port := strings.TrimSpace(os.Getenv("REALSTACK_PROVIDER_PORT"))
	if port == "" {
		port = "8080"
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("REALSTACK_PROVIDER_PORT is invalid")
	}
	return "http://127.0.0.1:" + port
}

func realstackAuthorizationEndpoint(t *testing.T) string {
	t.Helper()
	return strings.TrimRight(realstackIssuer(t), "/") + "/oauth2/auth"
}

func realstackUIOrigin(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("REALSTACK_UI_ORIGIN"))
	if value == "" {
		value = "http://127.0.0.1:3000"
	}
	return value
}

func realstackToken(t *testing.T) string {
	t.Helper()
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("generate OIDC test value")
	}
	return base64.RawURLEncoding.EncodeToString(value)
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
