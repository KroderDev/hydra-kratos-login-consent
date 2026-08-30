// Package identity derives opt-in OIDC claims from the safe part of a Kratos
// identity session.
package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/kroderdev/hydra-kratos-login-consent/internal/core/domain"
)

const (
	TransformJoinSpace = "join_space"

	maxMappings      = 64
	maxMappingBytes  = 64 << 10
	maxSources       = 8
	maxPointerBytes  = 512
	maxPointerTokens = 16
)

// Mapping describes one derived claim. Sources are exact RFC 6901 JSON
// Pointers into the sanitized Kratos source document.
type Mapping struct {
	Source        string   `json:"source,omitempty"`
	Sources       []string `json:"sources,omitempty"`
	Transform     string   `json:"transform,omitempty"`
	Type          string   `json:"type"`
	Format        string   `json:"format,omitempty"`
	parsedSources [][]string
}

// ClaimMappings is keyed by the output claim name.
type ClaimMappings map[string]Mapping

// ParseJSON parses and validates the environment representation of claim
// mapping definitions.
func ParseJSON(raw string, secureEnvironment bool) (ClaimMappings, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxMappingBytes {
		return nil, fmt.Errorf("identity claim mappings exceed %d bytes", maxMappingBytes)
	}
	if raw == "null" {
		return nil, fmt.Errorf("identity claim mappings must be a JSON object")
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var mappings ClaimMappings
	if err := decoder.Decode(&mappings); err != nil {
		return nil, fmt.Errorf("decode identity claim mappings: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("identity claim mappings contain trailing JSON")
		}
		return nil, fmt.Errorf("decode identity claim mappings after object: %w", err)
	}
	if err := mappings.Validate(secureEnvironment); err != nil {
		return nil, err
	}
	return mappings, nil
}

// Validate rejects unsupported, unsafe, or ambiguous mappings.
func (m ClaimMappings) Validate(_ bool) error {
	if len(m) > maxMappings {
		return fmt.Errorf("identity claim mappings contain more than %d claims", maxMappings)
	}
	claimNames := make([]string, 0, len(m))
	for name := range m {
		claimNames = append(claimNames, name)
	}
	sort.Strings(claimNames)
	for _, name := range claimNames {
		if err := validateClaimName(name); err != nil {
			return fmt.Errorf("identity claim %q: %w", name, err)
		}
		if IsReservedClaim(name) {
			return fmt.Errorf("identity claim %q is reserved by OAuth or OIDC", name)
		}
		mapping := m[name]
		parsedTokens, err := validateMapping(name, mapping)
		if err != nil {
			return fmt.Errorf("identity claim %q: %w", name, err)
		}
		mapping.parsedSources = parsedTokens
		m[name] = mapping
	}
	return nil
}

// Derive returns claims whose configured sources contain present and valid
// values. Missing or invalid source values are omitted because identity claims
// are optional; invalid mapping configuration is rejected by Validate.
func (m ClaimMappings) Derive(session domain.Session, secureEnvironment bool) map[string]any {
	if len(m) == 0 {
		return nil
	}
	document := sourceDocument(session)
	claims := make(map[string]any, len(m))
	for name, mapping := range m {
		value, ok := mappingValue(document, mapping)
		if !ok || !validClaimValue(name, mapping, value, secureEnvironment) {
			continue
		}
		claims[name] = cloneJSONValue(value)
	}
	if len(claims) == 0 {
		return nil
	}
	return claims
}

// IsReservedClaim reports whether name is owned by OAuth/OIDC protocol
// IsReservedClaim reports whether name is a reserved OAuth or OpenID Connect protocol claim.
// The comparison is case-insensitive.
func IsReservedClaim(name string) bool {
	_, ok := reservedClaims[strings.ToLower(name)]
	return ok
}

// RequiredScopes returns the protocol-required scopes for standard claims.
// RequiredScopes identifies the standard OIDC scope required for a claim name.
// It returns nil for claims without a corresponding standard scope.
func RequiredScopes(name string) []string {
	switch name {
	case "email", "email_verified":
		return []string{"email"}
	case "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at":
		return []string{"profile"}
	case "phone_number", "phone_number_verified":
		return []string{"phone"}
	case "address":
		return []string{"address"}
	default:
		return nil
	}
}

// validateClaimName validates that a claim name is non-empty and contains no surrounding whitespace or control characters.
func validateClaimName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return fmt.Errorf("claim name must be non-empty and contain no surrounding whitespace or control separators")
	}
	return nil
}

// validateMapping validates the source pointers, transformation, type, format, and standard-claim requirements for a claim mapping.
func validateMapping(name string, mapping Mapping) ([][]string, error) {
	sources, err := mappingSources(mapping)
	if err != nil {
		return nil, err
	}
	if len(sources) > maxSources {
		return nil, fmt.Errorf("has more than %d sources", maxSources)
	}
	parsedTokens := make([][]string, 0, len(sources))
	for _, source := range sources {
		if len(source) > maxPointerBytes {
			return nil, fmt.Errorf("source pointer exceeds %d bytes", maxPointerBytes)
		}
		tokens, err := parsePointer(source)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", source, err)
		}
		if len(tokens) < 2 || (tokens[0] != "traits" && tokens[0] != "metadata_public") {
			return nil, fmt.Errorf("source %q must select a value below /traits or /metadata_public", source)
		}
		if len(tokens) > maxPointerTokens {
			return nil, fmt.Errorf("source %q has more than %d pointer tokens", source, maxPointerTokens)
		}
		for _, token := range tokens {
			if strings.ContainsAny(token, "*[]{}$") {
				return nil, fmt.Errorf("source %q must not contain wildcard selectors", source)
			}
		}
		parsedTokens = append(parsedTokens, tokens)
	}
	if len(sources) > 1 && mapping.Transform != TransformJoinSpace {
		return nil, fmt.Errorf("multiple sources require transform %q", TransformJoinSpace)
	}
	if mapping.Transform != "" && mapping.Transform != TransformJoinSpace {
		return nil, fmt.Errorf("unsupported transform %q", mapping.Transform)
	}
	if mapping.Transform == TransformJoinSpace && mapping.Type != "string" {
		return nil, fmt.Errorf("transform %q requires type string", TransformJoinSpace)
	}
	if !validType(mapping.Type) {
		return nil, fmt.Errorf("unsupported type %q", mapping.Type)
	}
	if !validFormat(mapping.Type, mapping.Format) {
		return nil, fmt.Errorf("unsupported format %q for type %q", mapping.Format, mapping.Type)
	}
	if err := validateStandardMapping(name, mapping); err != nil {
		return nil, err
	}
	return parsedTokens, nil
}

// mappingSources returns the mapping's configured source pointers and validates their uniqueness and presence. It returns an error if the mapping defines both source forms, neither form, an empty pointer, or duplicate pointers.
func mappingSources(mapping Mapping) ([]string, error) {
	hasSource := mapping.Source != ""
	hasSources := len(mapping.Sources) > 0
	if hasSource == hasSources {
		return nil, fmt.Errorf("must define exactly one non-empty source or sources")
	}
	if hasSource {
		return []string{mapping.Source}, nil
	}
	for _, source := range mapping.Sources {
		if source == "" {
			return nil, fmt.Errorf("sources must not contain empty pointers")
		}
	}
	seen := make(map[string]struct{}, len(mapping.Sources))
	for _, source := range mapping.Sources {
		if _, ok := seen[source]; ok {
			return nil, fmt.Errorf("sources must not contain duplicate pointers")
		}
		seen[source] = struct{}{}
	}
	return append([]string(nil), mapping.Sources...), nil
}

// validateStandardMapping validates the type and format requirements for a standard OIDC claim mapping.
func validateStandardMapping(name string, mapping Mapping) error {
	switch name {
	case "email":
		if mapping.Type != "string" || (mapping.Format != "" && mapping.Format != "email") {
			return fmt.Errorf("email requires type string and optional format email")
		}
	case "email_verified":
		if mapping.Type != "boolean" || mapping.Format != "" {
			return fmt.Errorf("email_verified requires type boolean without a format")
		}
	case "picture":
		if mapping.Type != "string" || (mapping.Format != "" && mapping.Format != "uri" && mapping.Format != "url") {
			return fmt.Errorf("picture requires type string and optional format uri or url")
		}
	case "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "website", "gender", "birthdate", "zoneinfo", "locale":
		if mapping.Type != "string" || (mapping.Format != "" && mapping.Format != "string") {
			return fmt.Errorf("%s requires type string", name)
		}
	case "updated_at":
		if mapping.Type != "number" && mapping.Type != "integer" {
			return fmt.Errorf("updated_at requires a numeric type")
		}
	case "phone_number":
		if mapping.Type != "string" || (mapping.Format != "" && mapping.Format != "string") {
			return fmt.Errorf("phone_number requires type string")
		}
	case "phone_number_verified":
		if mapping.Type != "boolean" || mapping.Format != "" {
			return fmt.Errorf("phone_number_verified requires type boolean without a format")
		}
	case "address":
		if mapping.Type != "object" || mapping.Format != "" {
			return fmt.Errorf("address requires type object without a format")
		}
	}
	return nil
}

// validType reports whether value names a supported claim value type.
func validType(value string) bool {
	switch value {
	case "string", "boolean", "number", "integer", "array", "object":
		return true
	default:
		return false
	}
}

// validFormat reports whether the format is supported for the specified value type.
func validFormat(valueType, format string) bool {
	if format == "" {
		return true
	}
	if valueType != "string" {
		return false
	}
	switch format {
	case "email", "string", "uri", "url":
		return true
	default:
		return false
	}
}

// mappingValue resolves a mapping against a source document and returns its usable value.
// String values are trimmed, and join-space mappings combine non-empty string sources with spaces.
// The boolean is false when the value is missing, empty, or incompatible with the mapping transform.
func mappingValue(document map[string]any, mapping Mapping) (any, bool) {
	parsedSources := mapping.parsedSources
	if len(parsedSources) == 0 {
		sources, err := mappingSources(mapping)
		if err != nil {
			return nil, false
		}
		parsedSources = make([][]string, 0, len(sources))
		for _, source := range sources {
			tokens, err := parsePointer(source)
			if err != nil {
				return nil, false
			}
			parsedSources = append(parsedSources, tokens)
		}
	}
	if mapping.Transform == TransformJoinSpace {
		parts := make([]string, 0, len(parsedSources))
		for _, tokens := range parsedSources {
			value, ok := resolvePointerTokens(document, tokens)
			if !ok || value == nil {
				continue
			}
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			text = strings.TrimSpace(text)
			if text != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) == 0 {
			return nil, false
		}
		return strings.Join(parts, " "), true
	}
	value, ok := resolvePointerTokens(document, parsedSources[0])
	if !ok || value == nil {
		return nil, false
	}
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, false
		}
		return text, true
	}
	return value, true
}

// validClaimValue reports whether a claim value matches its declared type and format requirements.
func validClaimValue(name string, mapping Mapping, value any, secureEnvironment bool) bool {
	if !matchesType(mapping.Type, value) {
		return false
	}
	if mapping.Type != "string" {
		return true
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	switch {
	case name == "email" || mapping.Format == "email":
		parsed, err := mail.ParseAddress(text)
		return err == nil && parsed.Address == text && !strings.ContainsAny(text, "\r\n")
	case name == "picture":
		return validHTTPURL(text, secureEnvironment)
	case mapping.Format == "uri":
		return validHTTPURL(text, secureEnvironment)
	case mapping.Format == "url":
		return validHTTPURL(text, secureEnvironment)
	default:
		return true
	}
}

// validHTTPURL reports whether value is an HTTP or HTTPS URL without user information or a fragment, requiring HTTPS in secure environments.
func validHTTPURL(value string, secureEnvironment bool) bool {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return !secureEnvironment || parsed.Scheme == "https"
}

func matchesType(expected string, value any) bool {
	switch expected {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		return isNumber(value)
	case "integer":
		return isInteger(value)
	case "array":
		_, ok := value.([]any)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	default:
		return false
	}
}

func isNumber(value any) bool {
	switch number := value.(type) {
	case float64:
		return !math.IsNaN(number) && !math.IsInf(number, 0)
	case float32:
		return !math.IsNaN(float64(number)) && !math.IsInf(float64(number), 0)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case json.Number:
		_, err := number.Float64()
		return err == nil
	default:
		return false
	}
}

func isInteger(value any) bool {
	switch number := value.(type) {
	case float64:
		return !math.IsNaN(number) && !math.IsInf(number, 0) && math.Trunc(number) == number
	case float32:
		converted := float64(number)
		return !math.IsNaN(converted) && !math.IsInf(converted, 0) && math.Trunc(converted) == converted
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case json.Number:
		_, err := strconv.ParseInt(string(number), 10, 64)
		return err == nil
	default:
		return false
	}
}

// sourceDocument builds a source document containing identity traits and public metadata.
func sourceDocument(session domain.Session) map[string]any {
	return map[string]any{
		"traits":          session.IdentityTraits,
		"metadata_public": session.IdentityMetadataPublic,
	}
}

// resolvePointerTokens retrieves the value at pre-parsed RFC 6901 JSON Pointer tokens within a document.
func resolvePointerTokens(document any, tokens []string) (any, bool) {
	current := document
	for _, token := range tokens {
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[token]
			if !ok {
				return nil, false
			}
		case []any:
			index, ok := pointerIndex(token)
			if !ok || index >= len(value) {
				return nil, false
			}
			current = value[index]
		default:
			return nil, false
		}
	}
	return current, true
}

// resolvePointer retrieves the value at an RFC 6901 JSON Pointer within a document.
// It returns the value and true when the pointer resolves successfully, or nil and false otherwise.
func resolvePointer(document any, pointer string) (any, bool) {
	tokens, err := parsePointer(pointer)
	if err != nil {
		return nil, false
	}
	return resolvePointerTokens(document, tokens)
}

// parsePointer parses an RFC 6901 JSON pointer into its unescaped tokens. Empty
// pointers produce no tokens; malformed pointers return an error.
func parsePointer(pointer string) ([]string, error) {
	if pointer == "" {
		return []string{}, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("must be an RFC 6901 pointer")
	}
	rawTokens := strings.Split(pointer[1:], "/")
	tokens := make([]string, 0, len(rawTokens))
	for _, rawToken := range rawTokens {
		var token strings.Builder
		for index := 0; index < len(rawToken); index++ {
			if rawToken[index] != '~' {
				token.WriteByte(rawToken[index])
				continue
			}
			if index+1 >= len(rawToken) {
				return nil, fmt.Errorf("contains an invalid escape")
			}
			index++
			switch rawToken[index] {
			case '0':
				token.WriteByte('~')
			case '1':
				token.WriteByte('/')
			default:
				return nil, fmt.Errorf("contains an invalid escape")
			}
		}
		tokens = append(tokens, token.String())
	}
	return tokens, nil
}

func pointerIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	for _, character := range token {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(token)
	return index, err == nil
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, nested := range typed {
			cloned[key] = cloneJSONValue(nested)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, nested := range typed {
			cloned[index] = cloneJSONValue(nested)
		}
		return cloned
	default:
		return value
	}
}

var reservedClaims = map[string]struct{}{
	"acr":               {},
	"acr_values":        {},
	"access_token":      {},
	"amr":               {},
	"at_hash":           {},
	"aud":               {},
	"auth_time":         {},
	"azp":               {},
	"c_hash":            {},
	"client_id":         {},
	"code":              {},
	"consent":           {},
	"consent_challenge": {},
	"cty":               {},
	"error":             {},
	"error_description": {},
	"error_uri":         {},
	"exp":               {},
	"expires_in":        {},
	"grant_type":        {},
	"id_token":          {},
	"iat":               {},
	"iss":               {},
	"jti":               {},
	"login_challenge":   {},
	"logout_challenge":  {},
	"nbf":               {},
	"nonce":             {},
	"redirect_uri":      {},
	"refresh_token":     {},
	"response_type":     {},
	"scope":             {},
	"session":           {},
	"sid":               {},
	"s_hash":            {},
	"state":             {},
	"sub":               {},
	"token_type":        {},
	"typ":               {},
}
