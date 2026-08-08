package identity

import (
	"reflect"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func TestParseJSONAndDeriveUsesRFC6901Pointers(t *testing.T) {
	t.Parallel()

	mappings, err := ParseJSON(`{
		"email":{"source":"/traits/email","type":"string","format":"email"},
		"name":{"sources":["/traits/name/given","/traits/name/family"],"type":"string","transform":"join_space"},
		"slash":{"source":"/traits/labels/a~1b","type":"string"},
		"tilde":{"source":"/traits/labels/a~0b","type":"string"},
		"role":{"source":"/metadata_public/role","type":"string"}
	}`, false)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	claims := mappings.Derive(domain.Session{
		IdentityTraits: map[string]any{
			"email":  "operator@example.com",
			"name":   map[string]any{"given": "Operator", "family": "Example"},
			"labels": map[string]any{"a/b": "slash-value", "a~b": "tilde-value"},
		},
		IdentityMetadataPublic: map[string]any{"role": "reader"},
	}, false)
	want := map[string]any{
		"email": "operator@example.com",
		"name":  "Operator Example",
		"slash": "slash-value",
		"tilde": "tilde-value",
		"role":  "reader",
	}
	if !reflect.DeepEqual(claims, want) {
		t.Fatalf("derived claims = %#v, want %#v", claims, want)
	}
}

func TestClaimMappingsValidateRejectsUnsafeMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "not a pointer", raw: `{"role":{"source":"traits/role","type":"string"}}`},
		{name: "invalid pointer escape", raw: `{"role":{"source":"/traits/role~2value","type":"string"}}`},
		{name: "wildcard", raw: `{"role":{"source":"/traits/*","type":"string"}}`},
		{name: "json path", raw: `{"role":{"source":"/traits/roles[*]","type":"string"}}`},
		{name: "unsupported transform", raw: `{"name":{"source":"/traits/name","type":"string","transform":"lowercase"}}`},
		{name: "ambiguous sources", raw: `{"name":{"sources":["/traits/given","/traits/family"],"type":"string"}}`},
		{name: "reserved claim", raw: `{"sub":{"source":"/traits/id","type":"string"}}`},
		{name: "reserved authorized party", raw: `{"azp":{"source":"/traits/id","type":"string"}}`},
		{name: "standard type", raw: `{"email":{"source":"/traits/email","type":"boolean","format":"email"}}`},
		{name: "picture format", raw: `{"picture":{"source":"/traits/picture","type":"string","format":"email"}}`},
		{name: "unknown field", raw: `{"role":{"source":"/traits/role","type":"string","template":"x"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseJSON(tt.raw, false); err == nil {
				t.Fatal("ParseJSON accepted an invalid mapping")
			}
		})
	}
}

func TestDeriveOmitsMissingWrongAndInvalidValues(t *testing.T) {
	t.Parallel()

	mappings := ClaimMappings{
		"email": {
			Source: "/traits/email",
			Type:   "string",
			Format: "email",
		},
		"email_verified": {
			Source: "/traits/email_verified",
			Type:   "boolean",
		},
		"picture": {
			Source: "/metadata_public/picture",
			Type:   "string",
			Format: "uri",
		},
		"missing": {
			Source: "/traits/missing",
			Type:   "string",
		},
	}
	if err := mappings.Validate(true); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	claims := mappings.Derive(domain.Session{
		IdentityTraits: map[string]any{
			"email":          "not-an-email",
			"email_verified": false,
		},
		IdentityMetadataPublic: map[string]any{
			"picture": "http://images.example/avatar.png",
		},
	}, true)
	if !reflect.DeepEqual(claims, map[string]any{"email_verified": false}) {
		t.Fatalf("derived claims = %#v, want only explicit false email_verified", claims)
	}
}

func TestDeriveAcceptsHTTPSPictureAndDoesNotExposeSessionFields(t *testing.T) {
	t.Parallel()

	mappings := ClaimMappings{
		"picture": {Source: "/metadata_public/picture", Type: "string", Format: "uri"},
	}
	claims := mappings.Derive(domain.Session{
		Subject: "operator-1",
		IdentityMetadataPublic: map[string]any{
			"picture": "https://images.example/avatar.png",
		},
	}, true)
	if got := claims["picture"]; got != "https://images.example/avatar.png" {
		t.Fatalf("picture claim = %#v, want HTTPS URL", got)
	}

	if _, err := ParseJSON(`{"subject":{"source":"/subject","type":"string"}}`, false); err == nil {
		t.Fatal("mapping selected a non-identity session field")
	}
}

func TestRequiredScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		claim string
		want  string
	}{
		{name: "email", claim: "email", want: "email"},
		{name: "verified email", claim: "email_verified", want: "email"},
		{name: "profile", claim: "name", want: "profile"},
		{name: "picture", claim: "picture", want: "profile"},
		{name: "custom", claim: "tenant", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RequiredScopes(tt.claim)
			if len(got) == 0 && tt.want == "" {
				return
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("RequiredScopes(%q) = %#v, want [%q]", tt.claim, got, tt.want)
			}
		})
	}
}
