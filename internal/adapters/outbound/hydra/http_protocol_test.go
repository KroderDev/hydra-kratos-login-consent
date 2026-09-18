package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	hydraapi "github.com/ory/hydra-client-go/v26"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

func TestParseOIDCRequestURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		requestURL string
		wantPrompt string
		wantMaxAge *int64
		wantErr    bool
	}{
		{name: "empty"},
		{name: "prompt login", requestURL: "https://hydra.example/auth?prompt=login", wantPrompt: "login"},
		{name: "prompt none and max age", requestURL: "https://hydra.example/auth?prompt=none&max_age=60", wantPrompt: "none", wantMaxAge: int64Value(60)},
		{name: "trimmed values", requestURL: "https://hydra.example/auth?prompt=%20login%20&max_age=%2060%20", wantPrompt: "login", wantMaxAge: int64Value(60)},
		{name: "unsupported prompt is preserved", requestURL: "https://hydra.example/auth?prompt=consent", wantPrompt: "consent"},
		{name: "duplicate prompt", requestURL: "https://hydra.example/auth?prompt=login&prompt=none", wantErr: true},
		{name: "blank prompt", requestURL: "https://hydra.example/auth?prompt=%20", wantErr: true},
		{name: "duplicate max age", requestURL: "https://hydra.example/auth?max_age=1&max_age=2", wantErr: true},
		{name: "invalid max age", requestURL: "https://hydra.example/auth?max_age=not-a-number", wantErr: true},
		{name: "negative max age", requestURL: "https://hydra.example/auth?max_age=-1", wantErr: true},
		{name: "malformed query escape", requestURL: "https://hydra.example/auth?prompt=%zz", wantErr: true},
		{name: "malformed url", requestURL: "https://[", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prompt, maxAge, err := parseOIDCRequestURL(tt.requestURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOIDCRequestURL error = %v, want error: %t", err, tt.wantErr)
			}
			if tt.wantErr {
				if !errors.Is(err, domain.ErrUpstream) {
					t.Fatalf("error = %v, want ErrUpstream", err)
				}
				return
			}
			if prompt != tt.wantPrompt || !reflect.DeepEqual(maxAge, tt.wantMaxAge) {
				t.Fatalf("parseOIDCRequestURL = %q, %v; want %q, %v", prompt, maxAge, tt.wantPrompt, tt.wantMaxAge)
			}
		})
	}
}

func TestClient_GetLoginRequestMapsAllOIDCContext(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oauth2/auth/requests/login" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{
			"challenge": "login-challenge",
			"client": map[string]any{
				"client_id": "example-client",
			},
			"request_url":  "https://hydra.example/oauth2/auth?prompt=login&max_age=60",
			"oidc_context": map[string]any{"acr_values": []string{"urn:example:aal3", "aal2"}},
			"skip":         false,
			"subject":      "",
		})
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}

	request, err := client.GetLoginRequest(context.Background(), "login-challenge")
	if err != nil {
		t.Fatalf("GetLoginRequest: %v", err)
	}
	if request.RequestedAAL != "urn:example:aal3" ||
		!reflect.DeepEqual(request.RequestedACRValues, []string{"urn:example:aal3", "aal2"}) ||
		request.Prompt != "login" || request.MaxAge == nil || *request.MaxAge != 60 {
		t.Fatalf("login request = %#v, want complete OIDC context", request)
	}
}

func TestClient_GetConsentRequestMapsPrompt(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oauth2/auth/requests/consent" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{
			"challenge":       "consent-challenge",
			"request_url":     "https://hydra.example/oauth2/auth?prompt=none",
			"requested_scope": []string{"openid"},
			"subject":         "operator-1",
		})
	}))
	defer server.Close()
	baseURL, _ := url.Parse(server.URL)
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}

	request, err := client.GetConsentRequest(context.Background(), "consent-challenge")
	if err != nil {
		t.Fatalf("GetConsentRequest: %v", err)
	}
	if request.Prompt != "none" || request.Subject != "operator-1" || !reflect.DeepEqual(request.RequestedScopes, []string{"openid"}) {
		t.Fatalf("consent request = %#v, want prompt and scope", request)
	}
}

func TestClient_GetRequestsRejectMalformedOIDCRequestURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		request func(context.Context, *Client) error
	}{
		{
			name: "login",
			path: "/admin/oauth2/auth/requests/login",
			request: func(ctx context.Context, client *Client) error {
				_, err := client.GetLoginRequest(ctx, "login-challenge")
				return err
			},
		},
		{
			name: "consent",
			path: "/admin/oauth2/auth/requests/consent",
			request: func(ctx context.Context, client *Client) error {
				_, err := client.GetConsentRequest(ctx, "consent-challenge")
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					http.NotFound(w, r)
					return
				}
				writeJSON(t, w, map[string]any{
					"challenge":   "challenge",
					"client":      map[string]any{"client_id": "example-client"},
					"request_url": "https://hydra.example/oauth2/auth?prompt=login&prompt=none",
					"skip":        false,
					"subject":     "operator-1",
				})
			}))
			defer server.Close()
			baseURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(baseURL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}

			if err := tt.request(context.Background(), client); !errors.Is(err, domain.ErrUpstream) {
				t.Fatalf("request error = %v, want ErrUpstream", err)
			}
		})
	}
}

func TestClient_AcceptRequestsMapOptionalValues(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		switch r.URL.Path {
		case "/admin/oauth2/auth/requests/login/accept":
			if body["subject"] != "operator-1" || body["acr"] != "urn:example:aal2" || body["remember"] != true || body["remember_for"] != float64(3600) {
				t.Errorf("login acceptance body = %#v", body)
			}
			amr, ok := body["amr"].([]any)
			if !ok || !reflect.DeepEqual(amr, []any{"password", "totp"}) {
				t.Errorf("login amr = %#v", body["amr"])
			}
		case "/admin/oauth2/auth/requests/consent/accept":
			if body["remember"] != true || body["remember_for"] != float64(3600) {
				t.Errorf("consent acceptance options = %#v", body)
			}
			if !reflect.DeepEqual(body["grant_scope"], []any{"openid"}) || !reflect.DeepEqual(body["grant_access_token_audience"], []any{"api"}) {
				t.Errorf("consent grants = %#v", body)
			}
			session, ok := body["session"].(map[string]any)
			idToken, idTokenOK := session["id_token"].(map[string]any)
			accessToken, accessTokenOK := session["access_token"].(map[string]any)
			if !ok || !idTokenOK || !accessTokenOK || idToken["email"] != "operator@example.com" || accessToken["tenant"] != "tenant-1" {
				t.Errorf("consent session = %#v", body["session"])
			}
		default:
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/next"})
	}))
	defer server.Close()
	baseURL, _ := url.Parse(server.URL)
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcceptLogin(context.Background(), "login", ports.LoginAcceptance{
		Subject: "operator-1", ACR: "urn:example:aal2", AMR: []string{"password", "totp"}, Remember: true, RememberFor: 3600,
	}); err != nil {
		t.Fatalf("AcceptLogin: %v", err)
	}
	if _, err := client.AcceptConsent(context.Background(), "consent", ports.ConsentAcceptance{
		GrantScopes: []string{"openid"}, GrantAudience: []string{"api"}, Remember: true, RememberFor: 3600,
		Session: domain.Claims{
			IDToken:     map[string]any{"email": "operator@example.com"},
			AccessToken: map[string]any{"tenant": "tenant-1"},
		},
	}); err != nil {
		t.Fatalf("AcceptConsent: %v", err)
	}
}

func TestClient_AcceptConsentRejectsUnsupportedUserInfoSessionClaims(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(baseURL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcceptConsent(context.Background(), "consent", ports.ConsentAcceptance{
		GrantScopes: []string{"openid"},
		Session: domain.Claims{
			IDToken:  map[string]any{"email": "operator@example.com"},
			UserInfo: map[string]any{"phone_number": "+15550100"},
		},
	})
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("AcceptConsent error = %v, want ErrUpstream", err)
	}
	if !errors.Is(err, errUnsupportedUserInfoClaims) {
		t.Fatalf("AcceptConsent error = %v, want unsupported UserInfo error", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("Hydra requests = %d, want 0", got)
	}
}

func TestClient_AcceptConsentOmitsEmptyUserInfoSessionClaims(t *testing.T) {
	t.Parallel()

	t.Run("absent userinfo is omitted", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			session, ok := body["session"].(map[string]any)
			if !ok {
				t.Fatalf("consent session = %#v", body["session"])
			}
			if _, exists := session["userinfo"]; exists {
				t.Errorf("userinfo field was serialized without claims: %#v", session)
			}
			writeJSON(t, w, map[string]string{"redirect_to": "https://hydra.example/next"})
		}))
		defer server.Close()
		baseURL, _ := url.Parse(server.URL)
		client, err := New(baseURL, server.Client(), "")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := client.AcceptConsent(context.Background(), "consent", ports.ConsentAcceptance{
			GrantScopes: []string{"openid"},
			Session: domain.Claims{
				IDToken:     map[string]any{"email": "operator@example.com"},
				AccessToken: map[string]any{"tenant": "tenant-1"},
			},
		}); err != nil {
			t.Fatalf("AcceptConsent: %v", err)
		}
	})
}

func TestClient_DirectHelpersFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := redirectResponse(nil, nil); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("nil redirect response error = %v, want ErrUpstream", err)
	}
	if _, err := redirectResponse(&hydraapi.OAuth2RedirectTo{}, nil); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("empty redirect response error = %v, want ErrUpstream", err)
	}
	if _, err := redirectResponse(nil, errors.New("sdk failure")); !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("sdk redirect error = %v, want ErrUpstream", err)
	}
	if got := firstValue(nil); got != "" {
		t.Fatalf("firstValue(nil) = %q, want empty", got)
	}
	if got := requestedACRValues(nil); got != nil {
		t.Fatalf("requestedACRValues(nil) = %#v, want nil", got)
	}
	if got := clientDomain(hydraapi.OAuth2Client{}); got.ID != "" || got.Name != "" {
		t.Fatalf("empty client = %#v, want zero client", got)
	}
	if got := upstreamError(nil); got != nil {
		t.Fatalf("upstreamError(nil) = %v, want nil", got)
	}
}

func TestNewRejectsUnsafeURLs(t *testing.T) {
	t.Parallel()

	tests := []url.URL{
		{Path: "/admin"},
		{Scheme: "http"},
		{Host: "hydra.example"},
		{Scheme: "http", Host: "hydra.example", User: url.User("admin")},
		{Scheme: "http", Host: "hydra.example", Fragment: "secret"},
	}
	for _, value := range tests {
		if _, err := New(&value, nil, ""); err == nil {
			t.Fatalf("New accepted unsafe URL %#v", value)
		}
	}
}

func int64Value(value int64) *int64 {
	return &value
}
