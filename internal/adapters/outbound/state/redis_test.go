package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func TestRedisStore_ConsumeIsSingleUse(t *testing.T) {
	t.Parallel()

	store, cleanup := newRedisStore(t)
	defer cleanup()
	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow:              domain.FlowConsent,
		Challenge:         "challenge",
		ClientID:          "client",
		RequestedScopes:   []string{"openid"},
		RequestedAudience: []string{"api"},
		ExpiresAt:         time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	transaction, err := store.Consume(context.Background(), handle)
	if err != nil {
		t.Fatalf("consume transaction: %v", err)
	}
	if transaction.Challenge != "challenge" || transaction.RequestedScopes[0] != "openid" {
		t.Fatalf("transaction = %#v, want stored transaction", transaction)
	}
	if _, err := store.Consume(context.Background(), handle); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("second consume error = %v, want replay", err)
	}
}

func TestRedisStore_ExpiredTransactionCannotBeCreated(t *testing.T) {
	t.Parallel()

	store, cleanup := newRedisStore(t)
	defer cleanup()
	if _, err := store.Create(context.Background(), domain.Transaction{ExpiresAt: time.Now()}); !errors.Is(err, domain.ErrExpiredTransaction) {
		t.Fatalf("create error = %v, want expired transaction", err)
	}
}

func TestRedisStore_Ready(t *testing.T) {
	t.Parallel()

	store, cleanup := newRedisStore(t)
	defer cleanup()
	if err := store.Ready(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestValidateRedisURLRejectsUnsafeTLSOptions(t *testing.T) {
	t.Parallel()

	if err := ValidateRedisURL("rediss://redis.example/0?skip_verify=true", true); err == nil {
		t.Fatal("ValidateRedisURL accepted skip_verify=true")
	}
	if err := ValidateRedisURL("redis://redis.example/0", true); err == nil {
		t.Fatal("ValidateRedisURL accepted plaintext Redis outside development")
	}
}

func TestNewRedisStoreRedactsMalformedURLCredentials(t *testing.T) {
	t.Parallel()

	_, err := NewRedisStore("redis://:super-secret%zz@redis.example/0", "test:")
	if err == nil {
		t.Fatal("NewRedisStore accepted malformed Redis URL")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("Redis credential leaked in error: %v", err)
	}
}

func newRedisStore(t *testing.T) (*RedisStore, func()) {
	t.Helper()
	server := miniredis.RunT(t)
	store, err := NewRedisStore("redis://"+server.Addr(), "test:transaction:")
	if err != nil {
		t.Fatalf("create redis store: %v", err)
	}
	return store, func() {
		if err := store.Close(); err != nil {
			t.Errorf("close redis store: %v", err)
		}
		server.Close()
	}
}
