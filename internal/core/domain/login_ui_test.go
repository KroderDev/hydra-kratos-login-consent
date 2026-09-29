package domain

import (
	"strings"
	"testing"
)

func TestSafeLoginUIHints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input LoginUIHints
		want  LoginUIHints
	}{
		{
			name:  "ordinary hints",
			input: LoginUIHints{LoginHint: " user+tag@example.test ", UILocales: "fr-CA  zh-Hant-TW", Display: "popup"},
			want:  LoginUIHints{LoginHint: "user+tag@example.test", UILocales: "fr-CA zh-Hant-TW", Display: "popup"},
		},
		{
			name:  "invalid hints omitted independently",
			input: LoginUIHints{LoginHint: "user\r\nInjected: x", UILocales: "en_US", Display: "javascript:alert(1)"},
		},
		{
			name:  "oversized hints",
			input: LoginUIHints{LoginHint: strings.Repeat("a", 257), UILocales: strings.Repeat("en ", 70), Display: "touch"},
			want:  LoginUIHints{Display: "touch"},
		},
		{
			name:  "malformed locale and unicode control",
			input: LoginUIHints{LoginHint: "user\u202e@example.test", UILocales: "en--US", Display: "wap"},
			want:  LoginUIHints{Display: "wap"},
		},
		{
			name:  "locale newline omitted",
			input: LoginUIHints{UILocales: "en\nfr", Display: "page"},
			want:  LoginUIHints{Display: "page"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SafeLoginUIHints(tt.input); got != tt.want {
				t.Fatalf("SafeLoginUIHints(%#v) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}
