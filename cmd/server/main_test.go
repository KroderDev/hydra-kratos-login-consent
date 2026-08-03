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
