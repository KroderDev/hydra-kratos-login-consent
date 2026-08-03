package main

import (
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/config"
)

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestValidateStateConfigurationRejectsMemoryOutsideDevelopment(t *testing.T) {
	t.Setenv("STATE_STORE", "memory")

	if err := validateStateConfiguration(config.Config{Environment: "production"}); err == nil {
		t.Fatal("memory state store was accepted outside development and test")
	}
}

//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
func TestValidateStateConfigurationRequiresSecureRedisOutsideDevelopment(t *testing.T) {
	t.Setenv("STATE_STORE", "redis")
	t.Setenv("REDIS_URL", "redis://redis.example/0")
	t.Setenv("REDIS_KEY_PREFIX", "production:transaction:")

	if err := validateStateConfiguration(config.Config{Environment: "production"}); err == nil {
		t.Fatal("plaintext Redis was accepted outside development and test")
	}
}

func TestServerHelpers(t *testing.T) {
	t.Parallel()

	if !secureEnvironment("production") || secureEnvironment(" development ") || secureEnvironment("TEST") {
		t.Fatal("secureEnvironment returned an unexpected result")
	}
	if got := csvValues(" one, ,two,one "); len(got) != 3 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("csv values = %#v, want trimmed non-empty values", got)
	}
	if got := csvValues(" , "); len(got) != 0 {
		t.Fatalf("empty csv values = %#v, want empty", got)
	}
	rules, err := subjectScopeRules(`{"subject-1":{"client-1":["openid"]}}`)
	if err != nil || len(rules["subject-1"]["client-1"]) != 1 {
		t.Fatalf("subject scope rules = %#v, error = %v", rules, err)
	}
	if _, err := subjectScopeRules("{"); err == nil {
		t.Fatal("malformed subject scope rules were accepted")
	}
}

func TestValidateStateConfigurationRejectsUnknownStore(t *testing.T) {
	//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
	t.Setenv("STATE_STORE", "filesystem")
	if err := validateStateConfiguration(config.Config{Environment: "development"}); err == nil {
		t.Fatal("unknown state store was accepted")
	}
}

func TestValidateStateConfigurationAllowsDevelopmentMemory(t *testing.T) {
	//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
	t.Setenv("STATE_STORE", "memory")
	if err := validateStateConfiguration(config.Config{Environment: "development"}); err != nil {
		t.Fatalf("development memory store rejected: %v", err)
	}
}

func TestNewTransactionStoreSelectsRedis(t *testing.T) {
	//nolint:paralleltest // t.Setenv intentionally serializes process-wide environment changes.
	t.Setenv("STATE_STORE", "redis")
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
