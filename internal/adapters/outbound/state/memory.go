// Package state contains transaction-store adapters.
package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
)

const defaultMaxEntries = 10_000

// MemoryStore provides bounded, single-use transaction state for local use.
type MemoryStore struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	data       map[string]domain.Transaction
}

var _ ports.TransactionStore = (*MemoryStore)(nil)

// NewMemoryStore creates a bounded in-memory transaction store.
func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		now:        now,
		maxEntries: defaultMaxEntries,
		data:       make(map[string]domain.Transaction),
	}
}

// Create stores transaction with a cryptographically random opaque handle.
func (s *MemoryStore) Create(_ context.Context, transaction domain.Transaction) (string, error) {
	if transaction.ExpiresAt.IsZero() || !transaction.ExpiresAt.After(s.now()) {
		return "", domain.ErrExpiredTransaction
	}
	for range 3 {
		handle, err := randomHandle()
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		s.removeExpiredLocked()
		if s.maxEntries <= 0 {
			s.maxEntries = defaultMaxEntries
		}
		if len(s.data) >= s.maxEntries {
			s.mu.Unlock()
			return "", domain.ErrUpstream
		}
		if _, exists := s.data[handle]; !exists {
			s.data[handle] = cloneTransaction(transaction)
			s.mu.Unlock()
			return handle, nil
		}
		s.mu.Unlock()
	}
	return "", domain.ErrUpstream
}

func (s *MemoryStore) removeExpiredLocked() {
	now := s.now()
	for handle, transaction := range s.data {
		if !transaction.ExpiresAt.After(now) {
			delete(s.data, handle)
		}
	}
}

// Consume atomically removes and returns an unexpired transaction.
func (s *MemoryStore) Consume(_ context.Context, handle string) (domain.Transaction, error) {
	if handle == "" {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	s.mu.Lock()
	transaction, exists := s.data[handle]
	if exists {
		delete(s.data, handle)
	}
	s.mu.Unlock()
	if !exists {
		return domain.Transaction{}, domain.ErrReplay
	}
	if !transaction.ExpiresAt.After(s.now()) {
		return domain.Transaction{}, domain.ErrExpiredTransaction
	}
	return cloneTransaction(transaction), nil
}

func randomHandle() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func cloneTransaction(transaction domain.Transaction) domain.Transaction {
	transaction.RequestedScopes = append([]string(nil), transaction.RequestedScopes...)
	transaction.RequestedAudience = append([]string(nil), transaction.RequestedAudience...)
	return transaction
}
