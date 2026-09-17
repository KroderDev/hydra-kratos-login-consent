package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSafeFlowFields(t *testing.T) {
	t.Parallel()

	nodes := []any{
		map[string]any{"attributes": map[string]any{"name": "csrf_token", "type": "hidden", "value": "csrf"}},
		map[string]any{"attributes": map[string]any{"name": "identifier", "type": "email"}},
		map[string]any{"attributes": map[string]any{"name": "password", "type": "password"}},
		map[string]any{"attributes": map[string]any{"name": "totp_code", "type": "text"}},
		map[string]any{"attributes": map[string]any{"name": "traits.email", "type": "email"}},
		map[string]any{"attributes": map[string]any{"name": "traits.name", "type": "text"}},
		map[string]any{"attributes": map[string]any{"name": "method", "type": "submit", "value": "password"}},
		map[string]any{"attributes": map[string]any{"name": "totp_url", "type": "hidden", "value": "otpauth://secret"}},
		map[string]any{"attributes": map[string]any{"name": "recovery_code", "type": "text"}},
	}

	fields := safeFlowFields(nodes)
	if len(fields) != 7 {
		t.Fatalf("safe field count = %d, want 7", len(fields))
	}
	for _, field := range fields {
		if strings.Contains(field.Name, "totp_url") || strings.Contains(field.Name, "recovery_code") {
			t.Fatalf("sensitive field rendered: %q", field.Name)
		}
	}
}

func TestFlowAction(t *testing.T) {
	t.Parallel()

	internal, _ := url.Parse("http://kratos:4433")
	browser, _ := url.Parse("http://127.0.0.1:4433")
	server := &uiServer{kratosInternal: internal, kratosBrowser: browser}

	tests := []struct {
		name string
		raw  any
		want bool
	}{
		{
			name: "browser action",
			raw:  "http://127.0.0.1:4433/self-service/login?flow=flow-1",
			want: true,
		},
		{
			name: "internal action",
			raw:  "http://kratos:4433/self-service/login?flow=flow-1",
			want: true,
		},
		{
			name: "external origin",
			raw:  "https://attacker.example/self-service/login?flow=flow-1",
			want: false,
		},
		{
			name: "different flow",
			raw:  "http://kratos:4433/self-service/login?flow=flow-2",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := server.flowAction(tt.raw, "login", "flow-1")
			if ok != tt.want {
				t.Fatalf("flowAction ok = %t, want %t", ok, tt.want)
			}
		})
	}
}

func TestKratosCookieHeader(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://ui.example/login", nil)
	request.Header.Add("Cookie", "ory_kratos_session=session-value")
	request.Header.Add("Cookie", "csrf_token=csrf-value")
	request.Header.Add("Cookie", "provider_state=must-not-forward")

	if got := kratosCookieHeader(request); got != "ory_kratos_session=session-value; csrf_token=csrf-value" {
		t.Fatalf("Kratos cookie header = %q", got)
	}
}

func TestStartLoginAddsFreshnessParameters(t *testing.T) {
	t.Parallel()

	provider, _ := url.Parse("http://127.0.0.1:8080")
	kratos, _ := url.Parse("http://127.0.0.1:4433")
	server := &uiServer{
		kratosBrowser: kratos,
		provider:      provider,
		loginAAL:      "aal1",
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login?flow=login&transaction=transaction&csrf=csrf&force_reauth=true&max_age=60", nil)
	recorder := httptest.NewRecorder()

	server.startLogin(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("refresh") != "true" || location.Query().Get("aal") != "aal1" {
		t.Fatalf("Kratos handoff query = %q", location.RawQuery)
	}
	if location.Query().Get("return_to") != "http://127.0.0.1:8080/login/callback?csrf=csrf&transaction=transaction" {
		t.Fatalf("return_to = %q", location.Query().Get("return_to"))
	}
}

func TestStartLoginUsesHandoffAAL(t *testing.T) {
	t.Parallel()

	provider, _ := url.Parse("http://127.0.0.1:8080")
	kratos, _ := url.Parse("http://127.0.0.1:4433")
	server := &uiServer{kratosBrowser: kratos, provider: provider, loginAAL: "aal1"}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login?flow=login&transaction=transaction&csrf=csrf&aal=aal2", nil)
	recorder := httptest.NewRecorder()

	server.startLogin(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("aal") != "aal2" {
		t.Fatalf("Kratos AAL = %q, want aal2", location.Query().Get("aal"))
	}
}

func TestMaxAgeQueryAcceptsValuesOverOneDay(t *testing.T) {
	t.Parallel()

	maxAge, ok, err := maxAgeQuery(url.Values{"max_age": {"172800"}})
	if err != nil || !ok || maxAge != 172800 {
		t.Fatalf("maxAgeQuery = %d, %t, %v; want 172800, true, nil", maxAge, ok, err)
	}
}

func TestSecurityHeadersUseConfiguredOrigins(t *testing.T) {
	t.Parallel()

	kratos, _ := url.Parse("http://127.0.0.1:15433")
	provider, _ := url.Parse("http://127.0.0.1:18080")
	server := &uiServer{kratosBrowser: kratos, provider: provider}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	server.securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(recorder, request)

	want := "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' http://127.0.0.1:15433 http://127.0.0.1:18080"
	if got := recorder.Header().Get("Content-Security-Policy"); got != want {
		t.Fatalf("CSP = %q, want %q", got, want)
	}
}

func TestRenderConsentIncludesAudiences(t *testing.T) {
	t.Parallel()

	provider, _ := url.Parse("http://127.0.0.1:8080")
	server := &uiServer{provider: provider}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login?flow=consent&transaction=transaction&csrf=csrf&scope=openid%20profile&audience=https%3A%2F%2Fapi.example.test", nil)
	recorder := httptest.NewRecorder()

	server.renderConsent(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), `name="grant_audience" value="https://api.example.test"`) {
		t.Fatal("consent page did not include the requested audience")
	}
}
