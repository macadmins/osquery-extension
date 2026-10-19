package mcp_servers

import (
	"net/url"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/redact"
)

// Free-text secret redaction lives in pkg/redact so every table applies the same rule. These
// names keep this package's call sites and tests unchanged.
var (
	redactSecret     = redact.Secret
	isSecretFlagName = redact.IsSecretFlagName
)

const maxAssignmentDepth = redact.MaxAssignmentDepth

// redactArgs returns a sanitized copy of args. The two-arg flag form (`--token VALUE`)
// is detected by looking back at the previous element. Allocates one slice; element
// values are reused unchanged when no redaction is needed.
func redactArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, len(args))
	for i, a := range args {
		// No exemption for a dash prefix. `--token -opaque` is a secret whose value happens
		// to start with a dash, and skipping it left the raw value in place. Distinguishing
		// that from `--token --verbose`, where the flag has no value, needs a real option
		// parser with per-flag arity; absent one, this over-redacts. That is the documented
		// preference for this file, and args are counted rather than emitted, so the cost of
		// redacting one argument too many is nil.
		if i > 0 && isSecretFlagName(args[i-1]) {
			out[i] = redact.RedactedMark
			continue
		}
		out[i] = redactSecret(a)
	}
	return out
}

// sanitizeRemoteURL returns the scheme+host portion of a remote MCP endpoint and
// nothing else. Path, query, fragment, and userinfo are all dropped because tokens
// are commonly embedded in any of them (e.g., "/mcp/<token>/sse" in the path, or
// "?api_key=..." in the query). Regex-based token detection cannot reliably catch
// opaque tokens in path segments; the conservative strategy is "keep only what we
// know is safe to record."
//
// Returns "" if no host can be recovered: better to emit nothing than risk leaking a raw URL.
func sanitizeRemoteURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		return ""
	}
	// Strip userinfo defensively even though u.Host is supposed to exclude it.
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if parsed.Scheme != "" {
		return parsed.Scheme + "://" + host
	}
	// Scheme-less network-path reference ("//host/path"): preserve "//host" form.
	if strings.HasPrefix(raw, "//") {
		return "//" + host
	}
	return ""
}
