package main

import (
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/adapters/outbound/policy"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
)

func TestServerHelpers(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		environment string
		secure      bool
	}{
		{name: "production", environment: "production", secure: true},
		{name: "trimmed development", environment: " development ", secure: false},
		{name: "case insensitive test", environment: "TEST", secure: false},
		{name: "empty environment", environment: "", secure: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := secureEnvironment(tt.environment); got != tt.secure {
				t.Fatalf("secureEnvironment(%q) = %t, want %t", tt.environment, got, tt.secure)
			}
		})
	}

	rules, err := subjectScopeRules(`{"subject-1":{"client-1":["openid"]}}`)
	if err != nil {
		t.Fatalf("subject scope rules: %v", err)
	}
	if got := rules["subject-1"]["client-1"]; !reflect.DeepEqual(got, []string{"openid"}) {
		t.Fatalf("subject scope rules = %#v, want [openid]", got)
	}
	if got, err := subjectScopeRules(" "); err != nil || got != nil {
		t.Fatalf("empty subject scope rules = %#v, error = %v, want nil, nil", got, err)
	}
	if _, err := subjectScopeRules("{"); err == nil {
		t.Fatal("malformed subject scope rules were accepted")
	}
}

func TestNewLogger(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		value string
		level slog.Level
	}{
		{name: "default", level: slog.LevelInfo},
		{name: "debug", value: " DEBUG ", level: slog.LevelDebug},
		{name: "warning", value: "warning", level: slog.LevelWarn},
		{name: "error", value: "error", level: slog.LevelError},
		{name: "unknown defaults to info", value: "verbose", level: slog.LevelInfo},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger := newLogger(tt.value)
			if !logger.Enabled(t.Context(), tt.level) {
				t.Fatalf("logger does not enable configured level %s", tt.level)
			}
			if tt.level > slog.LevelDebug && logger.Enabled(t.Context(), tt.level-1) {
				t.Fatalf("logger unexpectedly enables level %s", tt.level-1)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestValidateStateConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name        string
		store       string
		redisURL    string
		keyPrefix   string
		environment string
		wantErr     bool
	}{
		{name: "defaults to development memory", environment: "development"},
		{name: "allows development memory", store: "memory", environment: "development"},
		{name: "rejects memory in production", store: "memory", environment: "production", wantErr: true},
		{name: "rejects unknown store", store: "filesystem", environment: "development", wantErr: true},
		{name: "requires Redis URL", store: "redis", environment: "development", wantErr: true},
		{name: "rejects plaintext Redis in production", store: "redis", redisURL: "redis://redis.example/0", keyPrefix: "production:", environment: "production", wantErr: true},
		{name: "requires production key prefix", store: "redis", redisURL: "rediss://redis.example/0", environment: "production", wantErr: true},
		{name: "accepts secure production Redis", store: "redis", redisURL: "rediss://redis.example/0", keyPrefix: "production:", environment: "production"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STATE_STORE", tt.store)
			t.Setenv("REDIS_URL", tt.redisURL)
			t.Setenv("REDIS_KEY_PREFIX", tt.keyPrefix)
			err := validateStateConfiguration(config.Config{Environment: tt.environment})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateStateConfiguration() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestNewTransactionStoreDefaultsToMemory(t *testing.T) {
	t.Setenv("STATE_STORE", "")
	store, closeStore, err := newTransactionStore(config.Config{Environment: "development"})
	if err != nil {
		t.Fatalf("new memory transaction store: %v", err)
	}
	if store == nil || closeStore == nil {
		t.Fatal("newTransactionStore returned nil store or close function")
	}
	if err := closeStore(); err != nil {
		t.Fatalf("close memory store: %v", err)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestNewTransactionStoreSelectsRedis(t *testing.T) {
	t.Setenv("STATE_STORE", " REDIS ")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
	t.Setenv("REDIS_KEY_PREFIX", "test:transaction:")
	store, closeStore, err := newTransactionStore(config.Config{Environment: "development"})
	if err != nil {
		t.Fatalf("new redis transaction store: %v", err)
	}
	if store == nil || closeStore == nil {
		t.Fatal("newTransactionStore returned nil store or close function")
	}
	if closeErr := closeStore(); closeErr != nil {
		// The connection is lazy, so closing a newly-created client should succeed.
		t.Fatalf("close redis store: %v", closeErr)
	}
}

func TestCSVValues(t *testing.T) {
	t.Parallel()

	if got := csvValues(" , "); len(got) != 0 {
		t.Fatalf("empty csv values = %#v, want empty", got)
	}
	if got := csvValues("one, two,, three"); !reflect.DeepEqual(got, []string{"one", "two", "three"}) {
		t.Fatalf("csv values = %#v, want trimmed non-empty values", got)
	}
}

func TestClientIDs(t *testing.T) {
	t.Parallel()

	cfg := config.Config{Clients: map[string]config.Client{
		"client-a": {},
		"client-b": {},
	}}
	got := clientIDs(cfg)
	if len(got) != 2 || !contains(got, "client-a") || !contains(got, "client-b") {
		t.Fatalf("client IDs = %#v, want both configured IDs", got)
	}
}

//nolint:paralleltest // Runs in the same package as tests that use process-wide t.Setenv.
func TestNewPolicySelectsHTTPBackend(t *testing.T) {
	policyURL, err := url.Parse("https://policy.example/v1/authorize")
	if err != nil {
		t.Fatalf("parse policy URL: %v", err)
	}
	provider, err := newPolicy(config.Config{
		Environment:   "production",
		PolicyBackend: config.PolicyBackendHTTP,
		PolicyURL:     policyURL,
	}, &http.Client{}, "secret")
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	if _, ok := provider.(*policy.HTTP); !ok {
		t.Fatalf("policy type = %T, want HTTP", provider)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestNewPolicySelectsStaticBackend(t *testing.T) {
	t.Setenv("ALLOWED_SUBJECTS", "operator-1")
	t.Setenv("ALLOWED_SUBJECT_SCOPES", `{"operator-1":{"client-1":["openid"]}}`)

	provider, err := newPolicy(config.Config{
		Environment:   "production",
		PolicyBackend: config.PolicyBackendStatic,
	}, &http.Client{}, "")
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	if _, ok := provider.(*policy.Static); !ok {
		t.Fatalf("policy type = %T, want Static", provider)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestNewPolicyRejectsMalformedStaticRules(t *testing.T) {
	t.Setenv("ALLOWED_SUBJECT_SCOPES", "{")

	if _, err := newPolicy(config.Config{Environment: "development"}, &http.Client{}, ""); err == nil {
		t.Fatal("newPolicy accepted malformed static scope rules")
	}
}

//nolint:paralleltest // Runs in the same package as tests that use process-wide t.Setenv.
func TestNewPolicyRejectsUnsafeHTTPEndpoint(t *testing.T) {
	policyURL, err := url.Parse("https://user:password@policy.example/v1/authorize")
	if err != nil {
		t.Fatalf("parse policy URL: %v", err)
	}
	if _, err := newPolicy(config.Config{
		Environment:   "development",
		PolicyBackend: config.PolicyBackendHTTP,
		PolicyURL:     policyURL,
	}, &http.Client{}, ""); err == nil {
		t.Fatal("newPolicy accepted an unsafe HTTP policy endpoint")
	}
}

//nolint:paralleltest // Runs in the same package as tests that use process-wide t.Setenv.
func TestNewPolicyRejectsUnknownBackend(t *testing.T) {
	if _, err := newPolicy(config.Config{PolicyBackend: "database"}, &http.Client{}, ""); err == nil {
		t.Fatal("newPolicy accepted an unknown policy backend")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestNewPolicyRequiresStaticRulesOnlyForStaticBackend(t *testing.T) {
	t.Setenv("ALLOWED_SUBJECTS", "")
	t.Setenv("ALLOWED_SUBJECT_SCOPES", "")
	if _, err := newPolicy(config.Config{Environment: "production"}, &http.Client{}, ""); err == nil {
		t.Fatal("static policy was accepted without production scope rules")
	}

	policyURL, err := url.Parse("https://policy.example/v1/authorize")
	if err != nil {
		t.Fatalf("parse policy URL: %v", err)
	}
	if _, err := newPolicy(config.Config{
		Environment:   "production",
		PolicyBackend: config.PolicyBackendHTTP,
		PolicyURL:     policyURL,
	}, &http.Client{}, ""); err == nil {
		t.Fatal("HTTP policy was accepted without a production bearer token")
	}
	if _, err := newPolicy(config.Config{
		Environment:   "production",
		PolicyBackend: config.PolicyBackendHTTP,
		PolicyURL:     policyURL,
	}, &http.Client{}, "secret"); err != nil {
		t.Fatalf("HTTP policy unexpectedly required static scope rules: %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestNewHTTPClient(t *testing.T) {
	t.Parallel()

	client := newHTTPClient()
	if client == nil || client.Transport == nil {
		t.Fatal("newHTTPClient returned nil client or transport")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
	if transport.MaxIdleConns != 256 || transport.MaxIdleConnsPerHost != 64 || transport.MaxConnsPerHost != 128 {
		t.Errorf("unexpected pool limits: MaxIdleConns=%d, MaxIdleConnsPerHost=%d, MaxConnsPerHost=%d",
			transport.MaxIdleConns, transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost)
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestRun_InvalidListenAddress(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://provider.example")
	t.Setenv("EXTERNAL_UI_URL", "https://ui.example")
	t.Setenv("HYDRA_ADMIN_URL", "https://hydra.example")
	t.Setenv("HYDRA_PUBLIC_URL", "https://hydra.example")
	t.Setenv("KRATOS_PUBLIC_URL", "https://kratos.example")
	t.Setenv("ALLOWED_CLIENTS", `{"test-client":{"id":"test-client","allowed_redirect_uris":["https://example.com/cb"],"allowed_scopes":["openid"]}}`)
	t.Setenv("LISTEN_ADDR", "127.0.0.1:-1")

	err := run()
	if err == nil {
		t.Fatal("run() with invalid listen address should return error")
	}
}
