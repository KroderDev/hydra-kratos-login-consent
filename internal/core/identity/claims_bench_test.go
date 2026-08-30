package identity

import (
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func BenchmarkClaimDerive(b *testing.B) {
	mappings, err := ParseJSON(`{
		"email":{"source":"/traits/email","type":"string","format":"email"},
		"name":{"sources":["/traits/name/given","/traits/name/family"],"type":"string","transform":"join_space"},
		"slash":{"source":"/traits/labels/a~1b","type":"string"},
		"tilde":{"source":"/traits/labels/a~0b","type":"string"},
		"role":{"source":"/metadata_public/role","type":"string"},
		"address":{"source":"/traits/address","type":"object"}
	}`, false)
	if err != nil {
		b.Fatalf("ParseJSON: %v", err)
	}

	session := domain.Session{
		IdentityTraits: map[string]any{
			"email": "operator@example.com",
			"name": map[string]any{
				"given":  "Operator",
				"family": "Example",
			},
			"labels": map[string]any{
				"a/b": "slash-value",
				"a~b": "tilde-value",
			},
			"address": map[string]any{
				"street_address": "123 Main St",
				"locality":       "Anytown",
				"country":        "US",
			},
		},
		IdentityMetadataPublic: map[string]any{
			"role": "reader",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		claims := mappings.Derive(session, false)
		if len(claims) == 0 {
			b.Fatal("unexpected empty claims")
		}
	}
}
