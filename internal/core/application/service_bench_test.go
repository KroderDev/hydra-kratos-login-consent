package application

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkTransactionAdmission(b *testing.B) {
	admission := newTransactionAdmission(10000, time.Now)
	expiresAt := time.Now().Add(10 * time.Minute)

	// Pre-fill with active transactions
	for i := range 5000 {
		handle := fmt.Sprintf("handle-%d", i)
		admission.commit(handle, expiresAt)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if admission.reserve(expiresAt) {
				admission.cancel()
			}
		}
	})
}
