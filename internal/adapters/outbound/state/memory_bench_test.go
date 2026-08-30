package state

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func BenchmarkMemoryStoreCreate(b *testing.B) {
	store := NewMemoryStore(time.Now)
	ctx := context.Background()
	expiresAt := time.Now().Add(10 * time.Minute)

	// Pre-fill with 5000 entries
	for i := range 5000 {
		_, err := store.Create(ctx, domain.Transaction{
			Flow:      domain.FlowLogin,
			Challenge: fmt.Sprintf("challenge-%d", i),
			ClientID:  "client-id",
			ExpiresAt: expiresAt,
		})
		if err != nil {
			b.Fatalf("failed to seed: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			handle, err := store.Create(ctx, domain.Transaction{
				Flow:      domain.FlowLogin,
				Challenge: "benchmark-challenge",
				ClientID:  "client-id",
				ExpiresAt: expiresAt,
			})
			if err == nil {
				_, _ = store.Consume(ctx, handle)
			}
		}
	})
}
