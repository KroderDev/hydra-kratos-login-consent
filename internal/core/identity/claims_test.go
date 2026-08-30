package identity

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

func TestParseJSONEmptyAndBoundaryCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "empty string", raw: "", wantErr: false},
		{name: "whitespace only", raw: "   ", wantErr: false},
		{name: "null literal", raw: "null", wantErr: true},
		{name: "trailing JSON", raw: `{"role":{"source":"/traits/role","type":"string"}}{}`, wantErr: true},
		{name: "trailing garbage", raw: `{"role":{"source":"/traits/role","type":"string"}}garbage`, wantErr: true},
		{name: "oversized", raw: `{"x":{"sources":["/` + strings.Repeat("a", maxMappingBytes) + `"],"type":"string"}}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mappings, err := ParseJSON(tt.raw, false)
			if tt.wantErr && err == nil {
				t.Fatal("ParseJSON returned nil error for invalid input")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ParseJSON: %v", err)
			}
			if tt.raw == "" || tt.raw == "   " {
				if mappings != nil {
					t.Fatal("expected nil mappings for empty input")
				}
			}
		})
	}
}

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

func TestClaimMappingsValidateRejectsAdditionalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "both source and sources", raw: `{"role":{"source":"/traits/role","sources":["/traits/role"],"type":"string"}}`},
		{name: "neither source nor sources", raw: `{"role":{"type":"string"}}`},
		{name: "empty sources entry", raw: `{"role":{"sources":[""],"type":"string"}}`},
		{name: "duplicate sources", raw: `{"role":{"sources":["/traits/x","/traits/x"],"type":"string"}}`},
		{name: "unsupported type", raw: `{"role":{"source":"/traits/role","type":"binary"}}`},
		{name: "format on non-string type", raw: `{"role":{"source":"/traits/role","type":"boolean","format":"email"}}`},
		{name: "unsupported format", raw: `{"role":{"source":"/traits/role","type":"string","format":"base64"}}`},
		{name: "join space with non-string type", raw: `{"name":{"sources":["/traits/a","/traits/b"],"type":"integer","transform":"join_space"}}`},
		{name: "pointer root is not traits or metadata", raw: `{"role":{"source":"/addresses/0","type":"string"}}`},
		{name: "single token pointer", raw: `{"role":{"source":"/traits","type":"string"}}`},
		{name: "claim name with leading whitespace", raw: `{" role":{"source":"/traits/role","type":"string"}}`},
		{name: "claim name with trailing whitespace", raw: `{"role " :{"source":"/traits/role","type":"string"}}`},
		{name: "email_verified requires boolean", raw: `{"email_verified":{"source":"/traits/verified","type":"string"}}`},
		{name: "email_verified rejects format", raw: `{"email_verified":{"source":"/traits/verified","type":"boolean","format":"email"}}`},
		{name: "phone_number requires string", raw: `{"phone_number":{"source":"/traits/phone","type":"integer"}}`},
		{name: "phone_number_verified requires boolean", raw: `{"phone_number_verified":{"source":"/traits/verified","type":"string"}}`},
		{name: "phone_number_verified rejects format", raw: `{"phone_number_verified":{"source":"/traits/verified","type":"boolean","format":"string"}}`},
		{name: "address requires object", raw: `{"address":{"source":"/traits/addr","type":"string"}}`},
		{name: "address rejects format", raw: `{"address":{"source":"/traits/addr","type":"object","format":"email"}}`},
		{name: "updated_at requires numeric", raw: `{"updated_at":{"source":"/traits/updated","type":"string"}}`},
		{name: "profile claim bad format", raw: `{"name":{"source":"/traits/name","type":"string","format":"uri"}}`},
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

func TestClaimMappingsValidateRejectsTooManySources(t *testing.T) {
	t.Parallel()

	sources := make([]string, maxSources+1)
	for i := range sources {
		sources[i] = "/traits/val" + string(rune('0'+i%10))
	}
	raw := `{"name":{"sources":["` + strings.Join(sources, `","`) + `"],"type":"string","transform":"join_space"}}`
	if _, err := ParseJSON(raw, false); err == nil {
		t.Fatal("ParseJSON accepted too many sources")
	}
}

func TestDeriveClaimValueMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mappings ClaimMappings
		session  domain.Session
		secure   bool
		want     map[string]any
	}{
		{
			name:     "nil claim for empty mappings",
			mappings: ClaimMappings{},
			secure:   false,
			want:     nil,
		},
		{
			name: "join space skips nil source",
			mappings: ClaimMappings{
				"name": {Sources: []string{"/traits/first", "/traits/missing"}, Transform: TransformJoinSpace, Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"first": "Only"}},
			secure:  false,
			want:    map[string]any{"name": "Only"},
		},
		{
			name: "join space with all missing returns nil",
			mappings: ClaimMappings{
				"name": {Sources: []string{"/traits/missing1", "/traits/missing2"}, Transform: TransformJoinSpace, Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{}},
			secure:  false,
			want:    nil,
		},
		{
			name: "join space with non-string source omits claim",
			mappings: ClaimMappings{
				"name": {Sources: []string{"/traits/str", "/traits/num"}, Transform: TransformJoinSpace, Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"str": "Hello", "num": 42}},
			secure:  false,
			want:    nil,
		},
		{
			name: "blank string value omitted",
			mappings: ClaimMappings{
				"role": {Source: "/traits/role", Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"role": "   "}},
			secure:  false,
			want:    nil,
		},
		{
			name: "nil source value omitted",
			mappings: ClaimMappings{
				"role": {Source: "/traits/role", Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"role": nil}},
			secure:  false,
			want:    nil,
		},
		{
			name: "integer value",
			mappings: ClaimMappings{
				"count": {Source: "/traits/count", Type: "integer"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"count": float64(7)}},
			secure:  false,
			want:    map[string]any{"count": float64(7)},
		},
		{
			name: "float value as number",
			mappings: ClaimMappings{
				"score": {Source: "/traits/score", Type: "number"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"score": float64(3.14)}},
			secure:  false,
			want:    map[string]any{"score": float64(3.14)},
		},
		{
			name: "array value cloned",
			mappings: ClaimMappings{
				"roles": {Source: "/traits/roles", Type: "array"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"roles": []any{"a", "b"}}},
			secure:  false,
			want:    map[string]any{"roles": []any{"a", "b"}},
		},
		{
			name: "object value cloned",
			mappings: ClaimMappings{
				"meta": {Source: "/traits/meta", Type: "object"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"meta": map[string]any{"key": "val"}}},
			secure:  false,
			want:    map[string]any{"meta": map[string]any{"key": "val"}},
		},
		{
			name: "boolean value",
			mappings: ClaimMappings{
				"enabled": {Source: "/traits/enabled", Type: "boolean"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"enabled": true}},
			secure:  false,
			want:    map[string]any{"enabled": true},
		},
		{
			name: "type mismatch omits claim",
			mappings: ClaimMappings{
				"count": {Source: "/traits/count", Type: "integer"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"count": "not-an-int"}},
			secure:  false,
			want:    nil,
		},
		{
			name: "invalid email omitted",
			mappings: ClaimMappings{
				"email": {Source: "/traits/email", Type: "string", Format: "email"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"email": "not-an-email"}},
			secure:  false,
			want:    nil,
		},
		{
			name: "valid email accepted",
			mappings: ClaimMappings{
				"email": {Source: "/traits/email", Type: "string", Format: "email"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"email": "user@example.com"}},
			secure:  false,
			want:    map[string]any{"email": "user@example.com"},
		},
		{
			name: "format uri with javascript rejected",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "javascript:alert(1)"}},
			secure:  false,
			want:    nil,
		},
		{
			name: "format uri with data rejected",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "data:text/html,<script>"}},
			secure:  false,
			want:    nil,
		},
		{
			name: "format uri with file rejected",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "file:///etc/passwd"}},
			secure:  false,
			want:    nil,
		},
		{
			name: "format uri with http accepted in dev",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "http://example.com"}},
			secure:  false,
			want:    map[string]any{"custom_uri": "http://example.com"},
		},
		{
			name: "format uri with https accepted in secure",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "https://example.com"}},
			secure:  true,
			want:    map[string]any{"custom_uri": "https://example.com"},
		},
		{
			name: "format uri with http rejected in secure",
			mappings: ClaimMappings{
				"custom_uri": {Source: "/traits/website", Type: "string", Format: "uri"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"website": "http://example.com"}},
			secure:  true,
			want:    nil,
		},
		{
			name: "format url with http accepted in dev",
			mappings: ClaimMappings{
				"homepage": {Source: "/traits/homepage", Type: "string", Format: "url"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"homepage": "http://example.com"}},
			secure:  false,
			want:    map[string]any{"homepage": "http://example.com"},
		},
		{
			name: "format url with http rejected in secure",
			mappings: ClaimMappings{
				"homepage": {Source: "/traits/homepage", Type: "string", Format: "url"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"homepage": "http://example.com"}},
			secure:  true,
			want:    nil,
		},
		{
			name: "all omitted returns nil not empty map",
			mappings: ClaimMappings{
				"missing": {Source: "/traits/missing", Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{}},
			secure:  false,
			want:    nil,
		},
		{
			name: "derive does not mutate session",
			mappings: ClaimMappings{
				"role": {Source: "/traits/roles/0", Type: "string"},
			},
			session: domain.Session{IdentityTraits: map[string]any{"roles": []any{"admin", "viewer"}}},
			secure:  false,
			want:    map[string]any{"role": "admin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.mappings.Validate(tt.secure); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			claims := tt.mappings.Derive(tt.session, tt.secure)
			if !reflect.DeepEqual(claims, tt.want) {
				t.Fatalf("derived claims = %#v, want %#v", claims, tt.want)
			}
		})
	}
}

func TestClaimTypeMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		typ   string
		value any
		want  bool
	}{
		{name: "string matches", typ: "string", value: "hello", want: true},
		{name: "string rejects bool", typ: "string", value: true, want: false},
		{name: "boolean matches", typ: "boolean", value: false, want: true},
		{name: "boolean rejects string", typ: "boolean", value: "true", want: false},
		{name: "number float64", typ: "number", value: float64(3.14), want: true},
		{name: "number float32", typ: "number", value: float32(1.5), want: true},
		{name: "number int", typ: "number", value: int(42), want: true},
		{name: "number int8", typ: "number", value: int8(8), want: true},
		{name: "number int16", typ: "number", value: int16(16), want: true},
		{name: "number int32", typ: "number", value: int32(32), want: true},
		{name: "number int64", typ: "number", value: int64(64), want: true},
		{name: "number uint", typ: "number", value: uint(10), want: true},
		{name: "number uint8", typ: "number", value: uint8(8), want: true},
		{name: "number uint16", typ: "number", value: uint16(16), want: true},
		{name: "number uint32", typ: "number", value: uint32(32), want: true},
		{name: "number uint64", typ: "number", value: uint64(64), want: true},
		{name: "number NaN rejected", typ: "number", value: float64NaN(), want: false},
		{name: "number Inf rejected", typ: "number", value: float64Inf(), want: false},
		{name: "number float32 NaN rejected", typ: "number", value: float32NaN(), want: false},
		{name: "number float32 Inf rejected", typ: "number", value: float32Inf(), want: false},
		{name: "number rejects non-numeric", typ: "number", value: "42", want: false},
		{name: "integer float64", typ: "integer", value: float64(7), want: true},
		{name: "integer float64 fractional", typ: "integer", value: float64(3.14), want: false},
		{name: "integer float64 NaN rejected", typ: "integer", value: float64NaN(), want: false},
		{name: "integer float64 Inf rejected", typ: "integer", value: float64Inf(), want: false},
		{name: "integer float32 NaN rejected", typ: "integer", value: float32NaN(), want: false},
		{name: "integer float32 Inf rejected", typ: "integer", value: float32Inf(), want: false},
		{name: "integer ints allowed", typ: "integer", value: int(42), want: true},
		{name: "integer uints allowed", typ: "integer", value: uint(42), want: true},
		{name: "array matches", typ: "array", value: []any{1, 2}, want: true},
		{name: "array rejects map", typ: "array", value: map[string]any{}, want: false},
		{name: "object matches", typ: "object", value: map[string]any{"a": 1}, want: true},
		{name: "object rejects slice", typ: "object", value: []any{}, want: false},
		{name: "unknown type", typ: "unknown", value: "x", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesType(tt.typ, tt.value); got != tt.want {
				t.Fatalf("matchesType(%q, %#v) = %t, want %t", tt.typ, tt.value, got, tt.want)
			}
		})
	}
}

func TestRFC6901PointerResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document any
		pointer  string
		want     any
		wantOK   bool
	}{
		{name: "array index 0", document: []any{"first", "second"}, pointer: "/0", want: "first", wantOK: true},
		{name: "array index 1", document: []any{"first", "second"}, pointer: "/1", want: "second", wantOK: true},
		{name: "array index out of bounds", document: []any{"first"}, pointer: "/1", want: nil, wantOK: false},
		{name: "array non-numeric index", document: []any{"first"}, pointer: "/abc", want: nil, wantOK: false},
		{name: "array leading zero", document: []any{"first"}, pointer: "/0", want: "first", wantOK: true},
		{name: "array double leading zero", document: []any{"first", "second"}, pointer: "/01", want: nil, wantOK: false},
		{name: "scalar traversal fails", document: "not-an-object", pointer: "/key", want: nil, wantOK: false},
		{name: "empty pointer to document", document: map[string]any{"key": "val"}, pointer: "", want: map[string]any{"key": "val"}, wantOK: true},
		{name: "nested map", document: map[string]any{"a": map[string]any{"b": "val"}}, pointer: "/a/b", want: "val", wantOK: true},
		{name: "map key not found", document: map[string]any{"a": 1}, pointer: "/b", want: nil, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := resolvePointer(tt.document, tt.pointer)
			if ok != tt.wantOK || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("resolvePointer(%#v, %q) = (%#v, %t), want (%#v, %t)", tt.document, tt.pointer, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestParsePointerEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pointer string
		want    []string
		wantErr bool
	}{
		{name: "empty string", pointer: "", want: []string{}, wantErr: false},
		{name: "root only", pointer: "/", want: []string{""}, wantErr: false},
		{name: "no leading slash", pointer: "traits/email", want: nil, wantErr: true},
		{name: "trailing escape", pointer: "/traits/key~", want: nil, wantErr: true},
		{name: "invalid escape char", pointer: "/traits/key~2value", want: nil, wantErr: true},
		{name: "tilde-0 escape", pointer: "/a~0b", want: []string{"a~b"}, wantErr: false},
		{name: "tilde-1 escape", pointer: "/a~1b", want: []string{"a/b"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePointer(tt.pointer)
			if tt.wantErr && err == nil {
				t.Fatal("parsePointer returned nil error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("parsePointer: %v", err)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parsePointer(%q) = %#v, want %#v", tt.pointer, got, tt.want)
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

func TestURLValidationMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		value            string
		secure           bool
		wantValidHTTPURL bool
	}{
		{name: "empty", value: "", secure: false, wantValidHTTPURL: false},
		{name: "crlf", value: "http://example.com\r\n", secure: false, wantValidHTTPURL: false},
		{name: "https dev", value: "https://example.com", secure: false, wantValidHTTPURL: true},
		{name: "https secure", value: "https://example.com", secure: true, wantValidHTTPURL: true},
		{name: "http dev", value: "http://example.com", secure: false, wantValidHTTPURL: true},
		{name: "http secure rejected", value: "http://example.com", secure: true, wantValidHTTPURL: false},
		{name: "ftp rejected", value: "ftp://example.com", secure: false, wantValidHTTPURL: false},
		{name: "user info rejected", value: "https://user@example.com", secure: false, wantValidHTTPURL: false},
		{name: "fragment rejected", value: "https://example.com#section", secure: false, wantValidHTTPURL: false},
		{name: "no host", value: "https:///path", secure: false, wantValidHTTPURL: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validHTTPURL(tt.value, tt.secure); got != tt.wantValidHTTPURL {
				t.Fatalf("validHTTPURL(%q, %t) = %t, want %t", tt.value, tt.secure, got, tt.wantValidHTTPURL)
			}
		})
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
		{name: "phone number", claim: "phone_number", want: "phone"},
		{name: "phone number verified", claim: "phone_number_verified", want: "phone"},
		{name: "address", claim: "address", want: "address"},
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

func float64NaN() float64 {
	return math.NaN()
}

func float64Inf() float64 {
	return math.Inf(1)
}

func float32NaN() float32 {
	return float32(math.NaN())
}

func float32Inf() float32 {
	return float32(math.Inf(1))
}

func TestMappingValue_UnparsedFallbackAndEdgeCases(t *testing.T) {
	t.Parallel()

	doc := map[string]any{
		"traits": map[string]any{
			"first": "John",
			"last":  "Doe",
			"tags":  []any{"admin", "user"},
		},
	}

	// Unparsed mapping (parsedSources is nil)
	mSingle := Mapping{Source: "/traits/first", Type: "string"}
	val, ok := mappingValue(doc, mSingle)
	if !ok || val != "John" {
		t.Fatalf("mappingValue unparsed single: val = %#v, ok = %t", val, ok)
	}

	// Unparsed join_space mapping
	mJoin := Mapping{Sources: []string{"/traits/first", "/traits/last"}, Type: "string", Transform: TransformJoinSpace}
	val, ok = mappingValue(doc, mJoin)
	if !ok || val != "John Doe" {
		t.Fatalf("mappingValue unparsed join_space: val = %#v, ok = %t", val, ok)
	}

	// Array pointer resolution
	vArray, ok := resolvePointer(doc, "/traits/tags/0")
	if !ok || vArray != "admin" {
		t.Fatalf("resolvePointer array index 0: val = %#v, ok = %t", vArray, ok)
	}

	// Array pointer out of bounds
	if _, ok := resolvePointer(doc, "/traits/tags/99"); ok {
		t.Fatal("resolvePointer array out of bounds expected false")
	}

	// Invalid array pointer (non-integer token)
	if _, ok := resolvePointer(doc, "/traits/tags/invalid"); ok {
		t.Fatal("resolvePointer invalid array index token expected false")
	}

	// Invalid pointer format
	if _, ok := resolvePointer(doc, "invalid-pointer"); ok {
		t.Fatal("resolvePointer invalid pointer syntax expected false")
	}

	// Non-existent key
	if _, ok := resolvePointer(doc, "/traits/not_found"); ok {
		t.Fatal("resolvePointer not found key expected false")
	}
}
