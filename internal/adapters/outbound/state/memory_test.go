package state

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func TestMemoryStore_ConsumeIsSingleUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "challenge",
		ClientID:  "client",
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	transaction, err := store.Consume(context.Background(), handle)
	if err != nil {
		t.Fatalf("consume transaction: %v", err)
	}
	if transaction.Challenge != "challenge" {
		t.Fatalf("challenge = %q, want challenge", transaction.Challenge)
	}
	if _, err := store.Consume(context.Background(), handle); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("second consume error = %v, want replay", err)
	}
}

func TestMemoryStore_GetDoesNotConsume(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow:         domain.FlowLogin,
		Challenge:    "challenge",
		CSRFToken:    "csrf",
		BrowserState: "browser-state",
		ClientID:     "client",
		ExpiresAt:    now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if _, err := store.Get(context.Background(), handle); err != nil {
		t.Fatalf("get transaction: %v", err)
	}
	if _, err := store.Consume(context.Background(), handle); err != nil {
		t.Fatalf("consume after get: %v", err)
	}
}

func TestMemoryStore_ExpiredTransactionCannotBeCreatedOrConsumed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	expired := domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "challenge",
		ClientID:  "client",
		ExpiresAt: now,
	}
	if _, err := store.Create(context.Background(), expired); !errors.Is(err, domain.ErrExpiredTransaction) {
		t.Fatalf("create error = %v, want expired transaction", err)
	}

	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "challenge",
		ClientID:  "client",
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create live transaction: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := store.Consume(context.Background(), handle); !errors.Is(err, domain.ErrExpiredTransaction) {
		t.Fatalf("consume error = %v, want expired transaction", err)
	}
}

func TestMemoryStore_ConsumeReturnsIndependentSlices(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	scopes := []string{"openid"}
	audience := []string{"api"}
	handle, err := store.Create(context.Background(), domain.Transaction{
		Flow:              domain.FlowConsent,
		Challenge:         "challenge",
		ClientID:          "client",
		RequestedScopes:   scopes,
		RequestedAudience: audience,
		ExpiresAt:         now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	scopes[0] = "changed"
	audience[0] = "changed"
	transaction, err := store.Consume(context.Background(), handle)
	if err != nil {
		t.Fatalf("consume transaction: %v", err)
	}
	if transaction.RequestedScopes[0] != "openid" || transaction.RequestedAudience[0] != "api" {
		t.Fatalf("stored slices were aliased: %#v %#v", transaction.RequestedScopes, transaction.RequestedAudience)
	}
}

func TestMemoryStore_ConcurrentConsumeHasOneWinner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	handle, err := store.Create(context.Background(), domain.Transaction{ExpiresAt: now.Add(time.Minute)})
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

func TestMemoryStore_EvictsExpiredWhenCapacityReached(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	store.maxEntries = 2

	// Fill store with 2 entries, 1 will expire
	h1, err := store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "c1",
		ClientID:  "client",
		ExpiresAt: now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("create c1: %v", err)
	}
	_, err = store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "c2",
		ClientID:  "client",
		ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create c2: %v", err)
	}

	// Advance clock so c1 expires
	now = now.Add(20 * time.Second)

	// Creating a 3rd entry triggers removal of expired c1 and succeeds
	h3, err := store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "c3",
		ClientID:  "client",
		ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create c3: %v", err)
	}
	if h3 == "" {
		t.Fatal("expected non-empty handle for c3")
	}

	// Verify c1 was removed
	if _, err := store.Get(context.Background(), h1); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("c1 error = %v, want replay (deleted)", err)
	}
}

func TestMemoryStore_RejectsWhenFullAndNoExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	store.maxEntries = 2

	for i := range 2 {
		_, err := store.Create(context.Background(), domain.Transaction{
			Flow:      domain.FlowLogin,
			Challenge: "c",
			ClientID:  "client",
			ExpiresAt: now.Add(10 * time.Minute),
		})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	// 3rd entry when none are expired should fail with ErrUpstream
	_, err := store.Create(context.Background(), domain.Transaction{
		Flow:      domain.FlowLogin,
		Challenge: "c3",
		ClientID:  "client",
		ExpiresAt: now.Add(10 * time.Minute),
	})
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("create full error = %v, want upstream", err)
	}
}

func TestMemoryStore_InvalidHandles(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(nil)
	if _, err := store.Get(context.Background(), ""); !errors.Is(err, domain.ErrInvalidTransaction) {
		t.Fatalf("Get empty handle error = %v, want ErrInvalidTransaction", err)
	}
	if _, err := store.Consume(context.Background(), ""); !errors.Is(err, domain.ErrInvalidTransaction) {
		t.Fatalf("Consume empty handle error = %v, want ErrInvalidTransaction", err)
	}
	if _, err := store.Get(context.Background(), "non-existent"); !errors.Is(err, domain.ErrReplay) {
		t.Fatalf("Get non-existent error = %v, want ErrReplay", err)
	}
}
