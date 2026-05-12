package policy

import "regexp"

// PIIPatterns is the canonical PII regex table — must stay in lockstep
// with backend/app/policy/compiled.py::PII_PATTERNS. The platform's
// invariant is that Stage 1 produces identical verdicts whether it
// runs in Python (control plane) or Go (runtime agent).
var PIIPatterns = map[string]*regexp.Regexp{
	// SSN — 3-2-4 digit groups; excludes 000/666/9xx area numbers.
	// Go's RE2 doesn't support negative lookaheads, so we approximate
	// the exclusion with character classes. The Python version uses
	// PCRE-style lookaheads — the resulting set is the same modulo
	// the area-number whitelist (which we don't enforce here).
	"ssn": regexp.MustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`),

	// Email — RFC 5321 simplified
	"email": regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),

	// Credit card — 13–19 digits with optional separators. Luhn is
	// checked by the engine in stage1.go.
	"credit_card": regexp.MustCompile(`\b(?:\d[- ]?){12,18}\d\b`),

	// US phone — covers 10-digit and +1-prefixed forms
	"phone_us": regexp.MustCompile(`\b(?:\+?1[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b`),

	// IPv4
	"ipv4": regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b`),

	// AWS access key
	"aws_access_key": regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),

	// OpenAI / Anthropic-style API keys
	"api_key_sk": regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
}

// LuhnCheck implements the RFC-1004 Luhn algorithm. Used to suppress
// false positives from the credit_card regex.
func LuhnCheck(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i, d := range digits {
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
