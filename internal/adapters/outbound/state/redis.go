package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/ports"
	redisclient "github.com/redis/go-redis/v9"
)

const defaultKeyPrefix = "transaction:"

var consumeScript = redisclient.NewScript(`
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
end
return value
`)

// RedisStore provides shared, expiry-bound, single-use transaction state.
type RedisStore struct {
	client    *redisclient.Client
	keyPrefix string
	now       func() time.Time
}

var (
	_ ports.TransactionStore = (*RedisStore)(nil)
	_ ports.Readiness        = (*RedisStore)(nil)
)

// NewRedisStore creates a transaction store from a redis:// or rediss:// URL.
func NewRedisStore(redisURL, keyPrefix string) (*RedisStore, error) {
	options, err := redisclient.ParseURL(strings.TrimSpace(redisURL))
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}
	return &RedisStore{
		client:    redisclient.NewClient(options),
		keyPrefix: keyPrefix,
		now:       time.Now,
	}, nil
}

// Create stores a transaction with an opaque handle and Redis expiry.
func (s *RedisStore) Create(ctx context.Context, transaction domain.Transaction) (string, error) {
	if transaction.ExpiresAt.IsZero() || !transaction.ExpiresAt.After(s.now()) {
		return "", domain.ErrExpiredTransaction
	}
	payload, err := json.Marshal(cloneTransaction(transaction))
	if err != nil {
		return "", fmt.Errorf("marshal transaction: %w", err)
	}
	ttl := transaction.ExpiresAt.Sub(s.now())
	if ttl <= 0 {
		return "", domain.ErrExpiredTransaction
	}
	for range 3 {
		handle, err := randomHandle()
		if err != nil {
			return "", fmt.Errorf("create transaction handle: %w", err)
		}
		created, err := s.client.SetNX(ctx, s.key(handle), payload, ttl).Result()
		if err != nil {
			return "", fmt.Errorf("store transaction in redis: %w", err)
		}
		if created {
			return handle, nil
		}
	}
	return "", domain.ErrUpstream
}

// Consume atomically removes and returns an unexpired transaction.
func (s *RedisStore) Consume(ctx context.Context, handle string) (domain.Transaction, error) {
	if handle == "" {
		return domain.Transaction{}, domain.ErrInvalidTransaction
	}
	payload, err := consumeScript.Run(ctx, s.client, []string{s.key(handle)}).Result()
	if err != nil {
		if errors.Is(err, redisclient.Nil) {
			return domain.Transaction{}, domain.ErrReplay
		}
		return domain.Transaction{}, fmt.Errorf("consume transaction from redis: %w", err)
	}
	if payload == nil {
		return domain.Transaction{}, domain.ErrReplay
	}
	value, ok := payload.(string)
	if !ok {
		return domain.Transaction{}, fmt.Errorf("consume transaction from redis: unexpected value type %T", payload)
	}
	var transaction domain.Transaction
	if err := json.Unmarshal([]byte(value), &transaction); err != nil {
		return domain.Transaction{}, fmt.Errorf("unmarshal transaction: %w", err)
	}
	if !transaction.ExpiresAt.After(s.now()) {
		return domain.Transaction{}, domain.ErrExpiredTransaction
	}
	return cloneTransaction(transaction), nil
}

// Ready checks that Redis accepts commands.
func (s *RedisStore) Ready(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis readiness: %w", err)
	}
	return nil
}

// Close releases Redis client resources.
func (s *RedisStore) Close() error {
	if err := s.client.Close(); err != nil && !errors.Is(err, redisclient.ErrClosed) {
		return fmt.Errorf("close redis client: %w", err)
	}
	return nil
}

func (s *RedisStore) key(handle string) string {
	return s.keyPrefix + handle
}
