package panel

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// maxErrorSummary bounds panel response text copied into errors and logs.
const maxErrorSummary = 200

var (
	whitespaceRun = regexp.MustCompile(`\s+`)
	urlQuery      = regexp.MustCompile(`\?[^\s"']*`)
)

// summarizeBody returns a bounded, single-line description of a panel error
// body. An HTML page (a Cloudflare or reverse-proxy error page) is reported by
// size only; other text is collapsed to one line and truncated.
func summarizeBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "(empty body)"
	}
	lower := strings.ToLower(text[:min(len(text), 512)])
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") || strings.Contains(lower, "<head") {
		return "(HTML error page, " + itoa(len(body)) + " bytes)"
	}
	return truncateSummary(whitespaceRun.ReplaceAllString(text, " "))
}

// summarizeText bounds a panel-provided message.
func summarizeText(s string) string {
	return truncateSummary(whitespaceRun.ReplaceAllString(strings.TrimSpace(s), " "))
}

// redactTransportError removes URL query strings (which carry secret_key)
// from a transport error and bounds its length.
func redactTransportError(err error) string {
	if err == nil {
		return ""
	}
	return truncateSummary(urlQuery.ReplaceAllString(err.Error(), "?<redacted>"))
}

func truncateSummary(s string) string {
	if utf8.RuneCountInString(s) <= maxErrorSummary {
		return s
	}
	r := []rune(s)
	return string(r[:maxErrorSummary]) + "…"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
