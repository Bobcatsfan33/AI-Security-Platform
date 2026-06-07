package policy

import (
	"net"
	"regexp"
	"strings"
	"unicode"
)

// ───────────────────────────── regex tables

type weightedPat struct {
	re *regexp.Regexp
	w  float64
}

func scan(text string, table []weightedPat) (float64, int) {
	var score float64
	hits := 0
	for _, p := range table {
		if p.re.MatchString(text) {
			hits++
			score = maxF(score, p.w)
			score += p.w * 0.1
		}
	}
	if score > 1 {
		score = 1
	}
	return score, hits
}

var piSignals = []weightedPat{
	{regexp.MustCompile(`(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|the)\s+instructions?\b`), 0.8},
	{regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|the\s+above)\b`), 0.75},
	{regexp.MustCompile(`(?i)\brepeat\s+(?:the\s+)?(?:text|words|everything|prompt)\s+above\b`), 0.7},
	{regexp.MustCompile(`(?i)\b(?:reveal|print|show|output)\s+(?:your\s+)?(?:system|initial|the)\s+prompt\b`), 0.85},
	{regexp.MustCompile(`(?i)\bwhat\s+(?:are|were)\s+your\s+(?:original\s+)?instructions\b`), 0.6},
	{regexp.MustCompile(`(?i)\boverride\s+(?:your\s+)?(?:safety|guidelines|rules|system)\b`), 0.7},
	{regexp.MustCompile(`(?i)</?\s*(?:system|instructions?)\s*>`), 0.6},
}

var jbSignals = []weightedPat{
	{regexp.MustCompile(`(?i)\b(?:DAN|do\s+anything\s+now)\b`), 0.8},
	{regexp.MustCompile(`(?i)\bdeveloper\s+mode\b`), 0.6},
	{regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:an?\s+)?\w+`), 0.5},
	{regexp.MustCompile(`(?i)\bpretend\s+(?:to\s+be|you\s+are)\b`), 0.5},
	{regexp.MustCompile(`(?i)\bact\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|evil|jailbroken)\b`), 0.85},
	{regexp.MustCompile(`(?i)\bno\s+(?:rules|restrictions|filters|guidelines)\b`), 0.6},
	{regexp.MustCompile(`(?i)\bfor\s+(?:educational|research)\s+purposes\s+only\b`), 0.4},
}

var toxTerms = []struct {
	term string
	w    float64
}{
	{"kill yourself", 1.0}, {"kys", 0.9}, {"i will kill you", 1.0}, {"i'll kill you", 1.0},
	{"go die", 0.85}, {"you should die", 0.95}, {"retard", 0.7}, {"idiot", 0.4},
	{"moron", 0.4}, {"hate you", 0.5}, {"worthless", 0.5}, {"piece of shit", 0.8},
	{"bastard", 0.6}, {"bitch", 0.6}, {"asshole", 0.6}, {"fuck you", 0.8},
	{"fuck", 0.45}, {"dumbass", 0.55}, {"nazi", 0.7}, {"rape", 0.9},
}

var legalSignals = []weightedPat{
	{regexp.MustCompile(`(?i)\b(?:is|would)\s+(?:it|this|that)\s+(?:be\s+)?(?:il)?legal\b`), 0.7},
	{regexp.MustCompile(`(?i)\bcan\s+i\s+(?:sue|be\s+sued|press\s+charges)\b`), 0.8},
	{regexp.MustCompile(`(?i)\blegal\s+advice\b`), 0.75},
	{regexp.MustCompile(`(?i)\b(?:lawsuit|liability|breach\s+of\s+contract|custody|alimony|defamation)\b`), 0.45},
	{regexp.MustCompile(`(?i)\bwhat\s+are\s+my\s+(?:legal\s+)?rights\b`), 0.55},
}

var finSignals = []weightedPat{
	{regexp.MustCompile(`(?i)\bshould\s+i\s+(?:buy|sell|invest\s+in|short)\b`), 0.75},
	{regexp.MustCompile(`(?i)\bfinancial\s+advice\b`), 0.75},
	{regexp.MustCompile(`(?i)\b(?:which|what)\s+(?:stocks?|crypto|coins?|funds?)\s+(?:should|to)\s+(?:i\s+)?(?:buy|invest)\b`), 0.8},
	{regexp.MustCompile(`(?i)\b(?:investment|retirement|portfolio)\s+(?:advice|recommendation|strategy)\b`), 0.65},
	{regexp.MustCompile(`(?i)\bhow\s+(?:much|should)\s+i\s+invest\b`), 0.6},
}

var refusalSignals = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bi(?:'m| am)\s+sorry,?\s+but\s+i\s+(?:can'?t|cannot|won'?t)\b`),
	regexp.MustCompile(`(?i)\bi\s+can'?t\s+(?:help|assist|comply|provide|do)\b`),
	regexp.MustCompile(`(?i)\bi\s+cannot\s+(?:help|assist|comply|provide)\b`),
	regexp.MustCompile(`(?i)\bas\s+an?\s+(?:ai|language model|assistant)\b`),
	regexp.MustCompile(`(?i)\bi'?m\s+(?:not\s+able|unable)\s+to\b`),
	regexp.MustCompile(`(?i)\bi\s+(?:must|have to)\s+decline\b`),
}

var urlRe = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"')]+`)
var hostRe = regexp.MustCompile(`(?i)https?://([^/:\s]+)`)
var suspiciousTLD = map[string]struct{}{"zip": {}, "mov": {}, "xyz": {}, "top": {}, "tk": {}, "ml": {}, "ga": {}, "cf": {}, "gq": {}, "click": {}, "country": {}, "work": {}, "loan": {}}
var reservedTLD = map[string]struct{}{"invalid": {}, "test": {}, "example": {}, "localhost": {}, "local": {}, "internal": {}, "home": {}, "lan": {}}
var shorteners = map[string]struct{}{"bit.ly": {}, "tinyurl.com": {}, "t.co": {}, "ow.ly": {}, "is.gd": {}, "cutt.ly": {}}
var badKeywords = []string{"login", "verify", "account", "secure", "update", "confirm", "webscr", "wallet", "metamask"}

func urlHost(u string) string {
	s := u
	if !strings.HasPrefix(strings.ToLower(s), "http") {
		s = "http://" + s
	}
	m := hostRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

var secretPats = []struct {
	label string
	re    *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"github_pat", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"google_api", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)},
	{"password_assign", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*\S{6,}`)},
}

var piiPats = []struct {
	label string
	re    *regexp.Regexp
}{
	{"ssn", regexp.MustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`)},
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{"credit_card", regexp.MustCompile(`\b(?:\d[ -]?){13,18}\d\b`)},
	{"passport", regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`)},
	{"iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)},
}
var piiContext = regexp.MustCompile(`(?i)\b(?:patient|diagnos|medical|ssn|social\s+security|passport|salary|account|routing|date\s+of\s+birth|dob|home\s+address|customer|employee)\b`)

var codeSignals = []struct {
	lang string
	re   *regexp.Regexp
}{
	{"python", regexp.MustCompile(`(?m)\b(?:def|import|from)\s+\w+|print\(|self\.`)},
	{"javascript", regexp.MustCompile(`\b(?:function|const|let|var)\s+\w+|=>|console\.log\(`)},
	{"go", regexp.MustCompile(`\bfunc\s+\w+\s*\(|package\s+\w+|:=`)},
	{"java", regexp.MustCompile(`\b(?:public|private|protected)\s+(?:static\s+)?(?:class|void|int)\b`)},
	{"c", regexp.MustCompile(`#include\s*<\w+\.h>|\bint\s+main\s*\(`)},
	{"sql", regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b.+\b(?:FROM|INTO|WHERE|VALUES)\b`)},
	{"bash", regexp.MustCompile(`#!/(?:bin|usr/bin)/(?:bash|sh)|\bsudo\s+\w+`)},
}

func identifyCode(text string) (string, int) {
	best, bestN := "", 0
	for _, c := range codeSignals {
		n := len(c.re.FindAllString(text, -1))
		if n > bestN {
			best, bestN = c.lang, n
		}
	}
	return best, bestN
}

// invisible-text rune sets
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF:
		return true
	}
	return false
}
func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}
func isTagChar(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// ───────────────────────────── detector catalogue

func allDetectorsList() []Detector {
	return []Detector{
		{
			Name: "prompt_injection", Category: "prompt_injection", DefaultThreshold: 0.5,
			Severity: SeverityHigh, Directions: []Direction{DirectionInbound},
			Detect: func(text string, _ DetectorContext) DetectorResult {
				s, h := scan(text, piSignals)
				sev := SeverityHigh
				if s >= 0.85 {
					sev = SeverityCritical
				}
				return res("prompt_injection", "prompt_injection", s, sev, map[string]any{"signals": h})
			},
		},
		{
			Name: "jailbreak", Category: "jailbreak", DefaultThreshold: 0.5,
			Severity: SeverityHigh, Directions: []Direction{DirectionInbound},
			Detect: func(text string, _ DetectorContext) DetectorResult {
				s, h := scan(text, jbSignals)
				sev := SeverityHigh
				if s >= 0.85 {
					sev = SeverityCritical
				}
				return res("jailbreak", "jailbreak", s, sev, map[string]any{"signals": h})
			},
		},
		{
			Name: "invisible_text", Category: "invisible_text", DefaultThreshold: 0.5, Severity: SeverityHigh,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				zw, bidi, tags, homo := 0, 0, 0, 0
				total := 0
				for _, r := range text {
					total++
					switch {
					case isTagChar(r):
						tags++
					case isZeroWidth(r):
						zw++
					case isBidi(r):
						bidi++
					case r > 0x7F && unicode.IsLetter(r):
						homo++
					}
				}
				var s float64
				if tags > 0 {
					s = 0.95
				}
				if zw > 0 {
					s = maxF(s, minF(0.6+0.05*float64(zw), 0.95))
				}
				if bidi > 0 {
					s = maxF(s, 0.7)
				}
				if homo > 0 && float64(homo) < maxF(float64(total)*0.3, 3) {
					s = maxF(s, 0.4)
				}
				sev := SeverityMedium
				if s >= 0.7 {
					sev = SeverityHigh
				}
				return res("invisible_text", "invisible_text", s, sev,
					map[string]any{"zero_width": zw, "bidi": bidi, "tag_chars": tags})
			},
		},
		{
			Name: "toxicity", Category: "toxicity", DefaultThreshold: 0.5, Severity: SeverityHigh,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				norm := collapseObfuscation(text)
				var s float64
				hits := []string{}
				for _, t := range toxTerms {
					key := strings.ReplaceAll(t.term, " ", "")
					if strings.Contains(norm, t.term) || strings.Contains(norm, key) {
						hits = append(hits, t.term)
						s = maxF(s, t.w) + t.w*0.15
					}
				}
				sev := SeverityMedium
				if s >= 0.9 {
					sev = SeverityCritical
				} else if s >= 0.6 {
					sev = SeverityHigh
				}
				return res("toxicity", "toxicity", s, sev, map[string]any{"terms": hits})
			},
		},
		{
			Name: "malicious_url", Category: "malicious_url", DefaultThreshold: 0.5, Severity: SeverityHigh,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				urls := urlRe.FindAllString(text, -1)
				var worst float64
				reasons := []string{}
				for _, u := range urls {
					host := urlHost(u)
					var sc float64
					hp := strings.Split(host, ":")[0]
					if ip := net.ParseIP(hp); ip != nil {
						sc = maxF(sc, 0.6)
						reasons = append(reasons, "ip_host")
						if ip.IsPrivate() || ip.IsLoopback() {
							sc = maxF(sc, 0.7)
						}
					}
					tld := ""
					if i := strings.LastIndex(host, "."); i >= 0 {
						tld = host[i+1:]
					}
					if _, ok := suspiciousTLD[tld]; ok {
						sc = maxF(sc, 0.65)
						reasons = append(reasons, "suspicious_tld")
					}
					if _, ok := shorteners[host]; ok {
						sc = maxF(sc, 0.55)
					}
					if strings.Contains(host, "xn--") {
						sc = maxF(sc, 0.7)
						reasons = append(reasons, "punycode")
					}
					for _, k := range badKeywords {
						if strings.Contains(strings.ToLower(u), k) && sc > 0 {
							sc = maxF(sc, 0.6)
							reasons = append(reasons, "phishing_keyword")
							break
						}
					}
					worst = maxF(worst, sc)
				}
				sev := SeverityMedium
				if worst >= 0.6 {
					sev = SeverityHigh
				}
				return res("malicious_url", "malicious_url", worst, sev,
					map[string]any{"reasons": reasons, "url_count": len(urls)})
			},
		},
		{
			Name: "unreachable_url", Category: "unreachable_url", DefaultThreshold: 0.5, Severity: SeverityLow,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				urls := urlRe.FindAllString(text, -1)
				var worst float64
				for _, u := range urls {
					host := urlHost(u)
					var sc float64
					tld := host
					if i := strings.LastIndex(host, "."); i >= 0 {
						tld = host[i+1:]
					}
					if _, ok := reservedTLD[tld]; ok {
						sc = maxF(sc, 0.85)
					}
					if ip := net.ParseIP(strings.Split(host, ":")[0]); ip != nil {
						if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
							sc = maxF(sc, 0.8)
						}
					}
					if !strings.Contains(host, ".") {
						if _, ok := reservedTLD[host]; !ok {
							sc = maxF(sc, 0.6)
						}
					}
					worst = maxF(worst, sc)
				}
				return res("unreachable_url", "unreachable_url", worst, SeverityLow, nil)
			},
		},
		{
			Name: "off_topic", Category: "off_topic", DefaultThreshold: 0.6, Severity: SeverityLow,
			Directions: []Direction{DirectionInbound},
			Detect: func(text string, ctx DetectorContext) DetectorResult {
				if len(ctx.AllowedTopics) == 0 {
					return res("off_topic", "off_topic", 0, SeverityInfo, nil)
				}
				toks := map[string]struct{}{}
				for _, t := range tokens(text) {
					if _, ok := commonEN[t]; !ok {
						toks[t] = struct{}{}
					}
				}
				topic := map[string]struct{}{}
				for _, a := range ctx.AllowedTopics {
					for _, t := range tokens(a) {
						topic[t] = struct{}{}
					}
				}
				if len(toks) == 0 || len(topic) == 0 {
					return res("off_topic", "off_topic", 0, SeverityInfo, nil)
				}
				overlap := 0
				for t := range toks {
					if _, ok := topic[t]; ok {
						overlap++
					}
				}
				coverage := float64(overlap) / float64(len(topic))
				var s float64
				if overlap == 0 {
					s = 0.85
				} else if coverage < 0.15 {
					s = 0.55
				} else {
					s = maxF(0, 0.4-coverage)
				}
				return res("off_topic", "off_topic", s, SeverityLow, map[string]any{"coverage": coverage})
			},
		},
		{
			Name: "gibberish", Category: "gibberish", DefaultThreshold: 0.6, Severity: SeverityLow,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				st := strings.TrimSpace(text)
				if len(st) < 8 {
					return res("gibberish", "gibberish", 0, SeverityInfo, nil)
				}
				ws := words(st)
				if len(ws) == 0 {
					return res("gibberish", "gibberish", 0.8, SeverityLow, nil)
				}
				var avgV float64
				for _, w := range ws {
					avgV += vowelRatio(w)
				}
				avgV /= float64(len(ws))
				en := englishWordRatio(st)
				ent := shannonEntropy(strings.ToLower(strings.Join(strings.Fields(st), "")))
				var s float64
				if avgV < 0.18 {
					s += 0.4
				}
				if en < 0.15 {
					s += 0.35
				}
				if ent > 4.2 && en < 0.2 {
					s += 0.2
				}
				return res("gibberish", "gibberish", s, SeverityLow,
					map[string]any{"avg_vowel": avgV, "english_ratio": en})
			},
		},
		{
			Name: "legal_advice", Category: "legal_advice", DefaultThreshold: 0.5, Severity: SeverityMedium,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				s, h := scan(text, legalSignals)
				return res("legal_advice", "legal_advice", s, SeverityMedium, map[string]any{"signals": h})
			},
		},
		{
			Name: "financial_advice", Category: "financial_advice", DefaultThreshold: 0.5, Severity: SeverityMedium,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				s, h := scan(text, finSignals)
				return res("financial_advice", "financial_advice", s, SeverityMedium, map[string]any{"signals": h})
			},
		},
		{
			Name: "programming_language", Category: "programming_language", DefaultThreshold: 0.5, Severity: SeverityLow,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				lang, n := identifyCode(text)
				if lang == "" {
					return res("programming_language", "programming_language", 0, SeverityInfo, nil)
				}
				s := minF(0.4+0.2*float64(n), 0.97)
				return res("programming_language", "programming_language", s, SeverityLow,
					map[string]any{"language": lang, "hits": n})
			},
		},
		{
			Name: "source_code", Category: "source_code", DefaultThreshold: 0.5, Severity: SeverityMedium,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				lang, n := identifyCode(text)
				fenced := strings.Count(text, "```") >= 2
				braces := strings.Count(text, "{") + strings.Count(text, "}") + strings.Count(text, ";")
				var s float64
				if lang != "" {
					s = minF(0.45+0.18*float64(n), 0.95)
				}
				if fenced {
					s = maxF(s, 0.6)
				}
				if braces >= 6 {
					s = maxF(s, 0.5)
				}
				return res("source_code", "source_code", s, SeverityMedium,
					map[string]any{"language": lang, "fenced": fenced})
			},
		},
		{
			Name: "llm_refusal", Category: "llm_refusal", DefaultThreshold: 0.5, Severity: SeverityInfo,
			Directions: []Direction{DirectionOutbound},
			Detect: func(text string, _ DetectorContext) DetectorResult {
				hits := 0
				for _, p := range refusalSignals {
					if p.MatchString(text) {
						hits++
					}
				}
				var s float64
				if hits > 0 {
					s = minF(0.55+0.2*float64(hits-1), 0.98)
				}
				return res("llm_refusal", "llm_refusal", s, SeverityInfo, map[string]any{"cues": hits})
			},
		},
		{
			Name: "context_aware_pii", Category: "pii", DefaultThreshold: 0.5, Severity: SeverityHigh,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				found := map[string]int{}
				for _, p := range piiPats {
					n := len(p.re.FindAllString(text, -1))
					if n > 0 {
						found[p.label] += n
					}
				}
				if len(found) == 0 {
					return res("context_aware_pii", "pii", 0, SeverityInfo, nil)
				}
				hasCtx := piiContext.MatchString(text)
				total := 0
				for _, v := range found {
					total += v
				}
				base := minF(0.45+0.12*float64(len(found)-1)+0.06*float64(total-1), 0.85)
				s := base
				if hasCtx {
					s = minF(base+0.2, 0.99)
				}
				sev := SeverityHigh
				if _, ok := found["ssn"]; ok {
					sev = SeverityCritical
				}
				if _, ok := found["credit_card"]; ok {
					sev = SeverityCritical
				}
				return res("context_aware_pii", "pii", s, sev, map[string]any{"context_boost": hasCtx})
			},
		},
		{
			Name: "credentials_secrets", Category: "credentials", DefaultThreshold: 0.5, Severity: SeverityCritical,
			Detect: func(text string, _ DetectorContext) DetectorResult {
				hits := []string{}
				for _, p := range secretPats {
					if p.re.MatchString(text) {
						hits = append(hits, p.label)
					}
				}
				if len(hits) == 0 {
					return res("credentials_secrets", "credentials", 0, SeverityInfo, nil)
				}
				s := minF(0.7+0.1*float64(len(hits)-1), 0.99)
				return res("credentials_secrets", "credentials", s, SeverityCritical, map[string]any{"types": hits})
			},
		},
		{
			Name: "brand_reputation", Category: "brand_reputation", DefaultThreshold: 0.5, Severity: SeverityLow,
			Directions: []Direction{DirectionOutbound},
			Detect: func(text string, ctx DetectorContext) DetectorResult {
				if len(ctx.BrandTerms) == 0 {
					return res("brand_reputation", "brand_reputation", 0, SeverityInfo, nil)
				}
				low := strings.ToLower(text)
				mentioned := []string{}
				for _, b := range ctx.BrandTerms {
					if strings.Contains(low, strings.ToLower(b)) {
						mentioned = append(mentioned, b)
					}
				}
				if len(mentioned) == 0 {
					return res("brand_reputation", "brand_reputation", 0, SeverityInfo, nil)
				}
				neg := regexp.MustCompile(`(?i)\b(?:terrible|awful|scam|fraud|lawsuit|hate|worst|broken|garbage|sucks|disaster)\b`).MatchString(text)
				s := 0.4
				sev := SeverityLow
				if neg {
					s = 0.7
					sev = SeverityMedium
				}
				return res("brand_reputation", "brand_reputation", s, sev, map[string]any{"brands": mentioned, "negative": neg})
			},
		},
		{
			Name: "competition", Category: "competition", DefaultThreshold: 0.5, Severity: SeverityLow,
			Detect: func(text string, ctx DetectorContext) DetectorResult {
				if len(ctx.CompetitorTerms) == 0 {
					return res("competition", "competition", 0, SeverityInfo, nil)
				}
				low := strings.ToLower(text)
				mentioned := []string{}
				for _, c := range ctx.CompetitorTerms {
					if strings.Contains(low, strings.ToLower(c)) {
						mentioned = append(mentioned, c)
					}
				}
				if len(mentioned) == 0 {
					return res("competition", "competition", 0, SeverityInfo, nil)
				}
				s := minF(0.55+0.15*float64(len(mentioned)-1), 0.95)
				return res("competition", "competition", s, SeverityLow, map[string]any{"competitors": mentioned})
			},
		},
	}
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
