// Package redact removes credentials and identifying data from diagnostic text.
//
// Redaction is deliberately conservative: support reports should lose a little
// context rather than disclose a credential or identify a user's machine.
package redact

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	secretMarker = "[REDACTED_SECRET]"
	emailMarker  = "[REDACTED_EMAIL]"
	homeMarker   = "[REDACTED_HOME]"
	userMarker   = "[REDACTED_USER]"
	ipMarker     = "[REDACTED_IP]"
	macMarker    = "[REDACTED_MAC]"
	hostMarker   = "[REDACTED_HOST]"
)

var (
	headerSecretRE = regexp.MustCompile(`(?im)^([\t ]*(?:authorization|proxy-authorization|cookie|set-cookie)[\t ]*:[\t ]*)[^\r\n]*`)
	bearerRE       = regexp.MustCompile(`(?i)\bbearer[\t ]+[^\s,;]+`)
	basicAuthRE    = regexp.MustCompile(`(?i)\bbasic[\t ]+[A-Za-z0-9+/=]{6,}`)
	urlUserInfoRE  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
	privateKeyRE   = regexp.MustCompile(`(?s)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`)

	// secretAssignmentRE covers environment variables, key/value output, and
	// JSON-like snippets. Keeping the key makes a preview useful while dropping
	// the value completely.
	secretAssignmentRE = regexp.MustCompile(`(?i)("?(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|id[ _-]?token|auth[ _-]?token|token|password|passwd|pwd|passphrase|client[ _-]?secret|secret|cookie|session(?:[ _-]?id)?|authorization)"?)([\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^,;\r\n]+)`)
	secretOptionRE     = regexp.MustCompile(`(?i)(--?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|pwd|secret|cookie|session(?:[_-]?id)?)(?:[\t ]+|=))(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)`)
	secretPhraseRE     = regexp.MustCompile(`(?i)(\b(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|token|password|passwd|passphrase|client[ _-]?secret|secret|cookie|session[ _-]?id)[\t ]+)[^,;\r\n]+`)
	jwtRE              = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`)
	knownTokenRE       = regexp.MustCompile(`(?i)\b(?:RGAPI-|gh[pousr]_|glpat-|npm_|pypi-|xox[baprs]-|sk-(?:proj-)?)[A-Za-z0-9_-]{8,}\b|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIza[A-Za-z0-9_-]{20,}\b`)

	emailRE       = regexp.MustCompile(`(?i)\b[A-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*\b`)
	windowsHomeRE = regexp.MustCompile(`(?i)\b[A-Z]:[\\/]+(?:Users|Profiles|Documents[\t ]+and[\t ]+Settings)[\\/]+[^\\/\s"'<>|]+`)
	uncHomeRE     = regexp.MustCompile(`(?i)(?:\\\\)+[^\\\s]+\\+(?:Users|Profiles)\\+[^\\/\s"'<>|]+`)
	unixHomeRE    = regexp.MustCompile(`(?:/home/|/usr/home/|/Users/|/var/home/)[^/\s"']+|/root\b`)
	wineUserRE    = regexp.MustCompile(`(?i)[\\/]+users[\\/]+[^\\/\s"'<>|]+`)
	tildeHomeRE   = regexp.MustCompile(`(?:^|[\s=:])~[A-Za-z0-9._-]*`)
	runtimeUserRE = regexp.MustCompile(`/run/user/[0-9]+`)
	userValueRE   = regexp.MustCompile(`(?i)("?(?:user(?:name)?|account|login)"?[\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)`)

	macRE           = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	ipv4CandidateRE = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	// Candidates are validated with netip.ParseAddr before replacement, which
	// prevents times and other colon-delimited text from being redacted.
	ipv6CandidateRE = regexp.MustCompile(`(?i)\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[A-Za-z0-9_.-]+)?\]?`)

	hostValueRE = regexp.MustCompile(`(?i)("?(?:host(?:[ _-]?(?:name|id))?|computer(?:[ _-]?name)?|machine(?:[ _-]?(?:name|id))?|node(?:[ _-]?name)?|device[ _-]?id|product[ _-]?uuid|serial[ _-]?(?:number|no)|peer|server|endpoint|remote)"?[\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)`)
	// Phrase matching is deliberately limited to explicit identifier labels.
	// Generic prose such as "host is ready", "machine indicator", or "remote
	// handoff" must not be damaged by defense-in-depth redaction. Generic keys
	// remain covered by hostValueRE when they use ':' or '='.
	hostPhraseRE  = regexp.MustCompile(`(?i)(\b(?:host[ _-]?(?:name|id)|computer[ _-]?name|machine[ _-]?(?:name|id)|node[ _-]?name|device[ _-]?id|product[ _-]?uuid|serial[ _-]?(?:number|no)|remote[ _-]?host)[\t ]+)[A-Za-z0-9._-]+`)
	privateHostRE = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,62})(?:\.(?:local|lan|internal|home|corp))\b`)
)

// String returns text with credential, account, home-path, and network
// identifiers replaced by stable markers. It is safe to call more than once;
// already-redacted text is unchanged.
func String(value string) string {
	if value == "" {
		return ""
	}

	value = headerSecretRE.ReplaceAllString(value, `${1}`+secretMarker)
	value = privateKeyRE.ReplaceAllString(value, secretMarker)
	value = urlUserInfoRE.ReplaceAllString(value, `${1}`+secretMarker+`@`)
	value = bearerRE.ReplaceAllString(value, "Bearer "+secretMarker)
	value = basicAuthRE.ReplaceAllString(value, "Basic "+secretMarker)
	value = secretAssignmentRE.ReplaceAllString(value, `${1}${2}"`+secretMarker+`"`)
	value = secretOptionRE.ReplaceAllString(value, `${1}`+secretMarker)
	value = secretPhraseRE.ReplaceAllString(value, `${1}`+secretMarker)
	value = jwtRE.ReplaceAllString(value, secretMarker)
	value = knownTokenRE.ReplaceAllString(value, secretMarker)

	value = emailRE.ReplaceAllString(value, emailMarker)
	value = uncHomeRE.ReplaceAllString(value, homeMarker)
	value = windowsHomeRE.ReplaceAllString(value, homeMarker)
	value = unixHomeRE.ReplaceAllString(value, homeMarker)
	value = wineUserRE.ReplaceAllString(value, "/"+homeMarker)
	value = tildeHomeRE.ReplaceAllStringFunc(value, func(match string) string {
		prefix := match[:len(match)-len(strings.TrimLeft(match, "\t =:"))]
		return prefix + homeMarker
	})
	value = runtimeUserRE.ReplaceAllString(value, userMarker)
	value = userValueRE.ReplaceAllString(value, `${1}"`+userMarker+`"`)

	value = macRE.ReplaceAllString(value, macMarker)
	value = ipv6CandidateRE.ReplaceAllStringFunc(value, redactIPv6Candidate)
	value = ipv4CandidateRE.ReplaceAllStringFunc(value, redactIPv4Candidate)
	value = hostValueRE.ReplaceAllString(value, `${1}"`+hostMarker+`"`)
	value = hostPhraseRE.ReplaceAllString(value, `${1}`+hostMarker)
	value = privateHostRE.ReplaceAllString(value, hostMarker)
	return value
}

// Host redacts a value known by its caller to identify a host. It exists for
// structured fields where guessing from surrounding text would be unnecessary.
func Host(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return hostMarker
}

func redactIPv4Candidate(candidate string) string {
	parts := strings.Split(candidate, ".")
	if len(parts) != 4 {
		return candidate
	}
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return candidate
		}
	}
	return ipMarker
}

func redactIPv6Candidate(candidate string) string {
	trimmed := strings.Trim(candidate, "[]")
	addr, err := netip.ParseAddr(trimmed)
	if err == nil && addr.Is6() {
		return ipMarker
	}
	return candidate
}
