package domain

import "testing"

func TestAALAtLeast(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		actual   string
		required string
		want     bool
	}{
		{name: "no requirement", actual: "", required: "", want: true},
		{name: "higher assurance", actual: "aal3", required: "aal2", want: true},
		{name: "same assurance with whitespace and case", actual: " AAL2 ", required: "aal2", want: true},
		{name: "lower assurance", actual: "aal1", required: "aal2", want: false},
		{name: "unknown actual assurance", actual: "password", required: "aal2", want: false},
		{name: "unknown required assurance", actual: "aal2", required: "password", want: false},
		{name: "out of range assurance", actual: "aal4", required: "aal2", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AALAtLeast(tt.actual, tt.required); got != tt.want {
				t.Fatalf("AALAtLeast(%q, %q) = %t, want %t", tt.actual, tt.required, got, tt.want)
			}
		})
	}
}

func TestHigherAAL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		first  string
		second string
		want   string
	}{
		{name: "first is stronger", first: "aal3", second: "aal2", want: "aal3"},
		{name: "second is stronger", first: "aal1", second: "aal2", want: "aal2"},
		{name: "equal keeps first value", first: " AAL2 ", second: "aal2", want: " AAL2 "},
		{name: "unknown first falls back to second", first: "custom", second: "aal2", want: "aal2"},
		{name: "unknown second keeps known first", first: "aal2", second: "custom", want: "aal2"},
		{name: "both unknown keeps second", first: "custom", second: "other", want: "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HigherAAL(tt.first, tt.second); got != tt.want {
				t.Fatalf("HigherAAL(%q, %q) = %q, want %q", tt.first, tt.second, got, tt.want)
			}
		})
	}
}
