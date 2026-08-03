package state

import (
	"context"
	"errors"
	"strings"
	"sync"
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

func TestRedisStore_ConcurrentConsumeHasOneWinner(t *testing.T) {
	t.Parallel()

	store, cleanup := newRedisStore(t)
	defer cleanup()
	handle, err := store.Create(context.Background(), domain.Transaction{ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	const attempts = 16
	var group sync.WaitGroup
	results := make(chan error, attempts)
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			_, consumeErr := store.Consume(context.Background(), handle)
			results <- consumeErr
		}()
	}
	group.Wait()
	close(results)

	winners := 0
	for consumeErr := range results {
		if consumeErr == nil {
			winners++
		} else if !errors.Is(consumeErr, domain.ErrReplay) {
			t.Fatalf("consume error = %v, want replay or success", consumeErr)
		}
	}
	if winners != 1 {
		t.Fatalf("successful consumes = %d, want 1", winners)
	}
}

func TestRedisStore_GetReturnsStoredTransactionAndRejectsMalformedPayload(t *testing.T) {
	t.Parallel()

	store, cleanup := newRedisStore(t)
	defer cleanup()
	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow: domain.FlowLogin, Challenge: "challenge", ClientID: "client", ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	transaction, err := store.Get(context.Background(), handle)
	if err != nil || transaction.Challenge != "challenge" {
		t.Fatalf("get transaction = %#v, error = %v", transaction, err)
	}
	if _, err := store.Get(context.Background(), "missing"); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("missing transaction error = %v, want replay", err)
	}
	if err := store.client.Set(context.Background(), store.key("malformed"), "not-json", time.Minute).Err(); err != nil {
		t.Fatalf("set malformed transaction: %v", err)
	}
	if _, err := store.Get(context.Background(), "malformed"); err == nil {
		t.Fatal("malformed transaction was accepted")
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
