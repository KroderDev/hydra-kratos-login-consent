package state

import (
	"context"
	"errors"
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
