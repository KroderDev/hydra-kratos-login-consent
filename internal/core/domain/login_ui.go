package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// LoginUIHints are optional, untrusted presentation hints from an OIDC request.
// They never participate in authentication or authorization decisions.
type LoginUIHints struct {
	LoginHint string
	UILocales string
	Display   string
}

// SafeLoginUIHints omits malformed or oversized hints before a browser handoff.
func SafeLoginUIHints(hints LoginUIHints) LoginUIHints {
	var safe LoginUIHints
	hint := strings.TrimSpace(hints.LoginHint)
	if len(hint) <= 256 && utf8.ValidString(hint) {
		valid := true
		for _, r := range hint {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				valid = false
				break
			}
		}
		if valid {
			safe.LoginHint = hint
		}
	}

	locales := strings.Fields(hints.UILocales)
	if len(hints.UILocales) <= 256 && len(locales) <= 8 && !strings.ContainsAny(hints.UILocales, "\r\n\t") {
		valid := true
		for _, locale := range locales {
			if !validLocale(locale) {
				valid = false
				break
			}
		}
		if valid {
			joined := strings.Join(locales, " ")
			if len(joined) <= 256 {
				safe.UILocales = joined
			}
		}
	}

	switch hints.Display {
	case "page", "popup", "touch", "wap":
		safe.Display = hints.Display
	}
	return safe
}

func validLocale(value string) bool {
	if len(value) < 2 || len(value) > 35 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if b == '-' {
			if i == 0 || value[i-1] == '-' {
				return false
			}
			continue
		}
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' {
			continue
		}
		if i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	return true
}
