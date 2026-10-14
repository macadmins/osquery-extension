package mcp_servers

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Codex stores its MCP configuration in ~/.codex/config.toml under [mcp_servers.<name>]
// sections rather than in JSON, which is what this file reads.
//
// The dependency is carried rather than hand-rolled because a real parser is correct on the
// whole grammar rather than on the subset someone anticipated, and Codex's config exercises
// more of it than a reader would guess -- inline tables, heterogeneous arrays, quoted keys. A
// no-dependency comparison implementation lives in toml_test.go and is diffed against this one
// over a corpus, so the option of dropping the dependency stays open and is decided on
// evidence.

// tomlServerEntry is the TOML projection of a server entry. Separate from rawServerEntry so
// the two formats' key names stay independent: TOML uses snake_case where the JSON configs use
// camelCase, and conflating them would make one format's rename silently break the other.
type tomlServerEntry struct {
	Command   string            `toml:"command"`
	Args      []string          `toml:"args"`
	Env       map[string]string `toml:"env"`
	URL       string            `toml:"url"`
	Type      string            `toml:"type"`
	Transport string            `toml:"transport"`

	// Codex spells this `enabled`, not `disabled`, and the two mean opposite things. A
	// config carrying `enabled = false` previously read as an enabled server, because the
	// key matched nothing. Measured against a real config.toml: 11 `enabled` keys, zero
	// `disabled`. Both are accepted, with `enabled` taking precedence when present, so a
	// file written by either convention is read correctly.
	Enabled  *bool `toml:"enabled"`
	Disabled *bool `toml:"disabled"`

	// Other places Codex names an environment variable rather than holding a value. These
	// are the useful half of a credential inventory: they identify what a server depends on
	// without exposing it. A remote server authenticated through bearer_token_env_var
	// previously reported an empty env_keys.
	EnvVars           []tomlEnvVar      `toml:"env_vars"`
	BearerTokenEnvVar string            `toml:"bearer_token_env_var"`
	EnvHTTPHeaders    map[string]string `toml:"env_http_headers"`

	// Deliberately no timeout fields. Codex's schema allows a float for tool_timeout_sec,
	// and declaring it as an int made one valid `tool_timeout_sec = 0.5` fail the whole
	// document: every server in the file collapsed into a single parse-warning row. The
	// table does not use timeouts, and BurntSushi ignores keys it has no field for, so the
	// correct number of fields here is none. Do not re-add them without a use.
}

// extractCodexTOML parses a Codex config.toml and returns one Server per [mcp_servers.<name>].
func extractCodexTOML(data []byte) ([]Server, error) {
	// Each server is held as a primitive and decoded on its own, the same way the JSON
	// extractors decode each entry from a json.RawMessage.
	//
	// Decoding the whole mcp_servers map in one Unmarshal meant one entry with a wrong field
	// type failed the file and replaced every healthy sibling with a single parse warning --
	// the same failure already fixed for JSON envelopes and Claude projects, still present
	// here because the TOML path was written later and copied the wrong shape.
	var doc struct {
		MCPServers map[string]toml.Primitive `toml:"mcp_servers"`
	}
	metadata, err := toml.Decode(string(data), &doc)
	if err != nil {
		return nil, err
	}
	if len(doc.MCPServers) == 0 {
		// Valid TOML with no MCP section. Not an error, and not a warning either: config.toml
		// carries plenty of unrelated settings.
		return nil, nil
	}
	entries := make(map[string]tomlServerEntry, len(doc.MCPServers))
	skipped := 0
	for name, primitive := range doc.MCPServers {
		var entry tomlServerEntry
		if err := metadata.PrimitiveDecode(primitive, &entry); err != nil {
			skipped++
			continue
		}
		// A shape check after decoding, matching what the JSON extractors do. An empty
		// [mcp_servers.placeholder] table decodes without error into a zero entry and became
		// a clean row: a server name, transport unknown, no command, no warning. A server
		// that declares nothing is not a server.
		if !looksLikeTOMLServerEntry(entry) {
			skipped++
			continue
		}
		entries[name] = entry
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("mcp_servers present but no decodable entries (%d skipped)", skipped)
	}
	return append(materializeTOML(entries), skippedEntryWarning(skipped)...), nil
}

// materializeTOML applies the same sanitization materialize() applies to the JSON shapes, so
// a TOML-sourced row is redacted identically to a JSON-sourced one.
func materializeTOML(in map[string]tomlServerEntry) []Server {
	out := make([]Server, 0, len(in))
	for name, entry := range in {
		rawURL := entry.URL
		server := Server{
			// The TOML section these came from, so source_context describes a real location
			// here the same way mcpServers and servers do for the JSON shapes.
			SourceContext: "mcp_servers",
			rawName:       name,
			rawContext:    "mcp_servers",
			ServerName:    redactSecret(name),
			Command:       redactSecret(entry.Command),
			Args:          redactArgs(entry.Args),
			URL:           sanitizeRemoteURL(rawURL),
			Transport: firstNonEmpty(normalizeTransport(entry.Type, entry.Transport),
				transportFromRawURL(rawURL, entry.Args)),
		}
		switch {
		case entry.Enabled != nil:
			server.Disabled = !*entry.Enabled
		case entry.Disabled != nil:
			server.Disabled = *entry.Disabled
		}
		keys, droppedKeys, literalHeaders := tomlEnvKeys(entry)
		server.EnvKeys = keys
		// A row carries one warning, so when an entry does both things the more serious one
		// is reported: a header written as a literal value means the configuration file on
		// disk holds the credential, while a dropped name means this column could not
		// publish an identifier. The counts were wrong in both directions before -- the
		// dropped names were not reported at all, and a literal header was reported as
		// Count: 1 however many of them the entry had -- which left the TOML path quieter
		// than the JSON one on identical configurations, since materialize() has always
		// reported a real dropped count.
		switch {
		case literalHeaders > 0:
			server.Warning = warning{Code: warnEnvHeaderLiteral, Count: literalHeaders}
		case droppedKeys > 0:
			server.Warning = warning{Code: warnEnvKeyDropped, Count: droppedKeys}
		}
		out = append(out, server)
	}
	return out
}

// tomlEnvVar is one entry of Codex's env_vars, which its schema allows to be either a bare
// string naming a variable or an object of the form { name, source }.
//
// Decoding it as []string made a valid object-form entry fail the whole document: because the
// entire mcp_servers map decodes in one operation, one such entry hid every other server in
// the file behind a single parse-warning row. That is the second time a too-narrow type here
// cost an entire file, after tool_timeout_sec, so the rule this encodes is that a field the
// table *does* read has to accept every shape the schema permits.
type tomlEnvVar struct {
	Name string
}

// UnmarshalTOML accepts both permitted shapes. An unrecognised shape yields an empty name and
// no error, deliberately: skipping one unreadable reference is a far smaller loss than failing
// the file, which is the mistake being corrected here.
func (v *tomlEnvVar) UnmarshalTOML(data any) error {
	switch value := data.(type) {
	case string:
		v.Name = value
	case map[string]any:
		// `source` names where the value comes from (keychain, env, ...). It is metadata
		// about the reference, not a value, and the table does not use it.
		if name, ok := value["name"].(string); ok {
			v.Name = name
		}
	}
	return nil
}

// tomlEnvKeys collects every environment variable name an entry references, from all four
// places Codex can name one. Values are never read: env holds them inline and is deliberately
// consulted for its keys only, while the other three name variables by design.
//
// droppedKeys counts the names envKeyAllowed refused, and literalHeaders the env_http_headers
// values that were not variable names at all. Counting them is the whole point of gating here
// rather than only at the row boundary: the add closure used to discard a rejected name
// silently, so an invalid key in env, in env_vars or in bearer_token_env_var left no trace in
// the row while the JSON path reported the identical configuration as a real drop count. A
// name this table refuses to publish is still evidence of how the server is configured, and a
// column that goes quiet is indistinguishable from a server that references nothing.
//
// A name that is absent rather than rejected is not counted, which is why the two reference
// sources test for it first: UnmarshalTOML deliberately yields an empty name for an env_vars
// element whose shape it does not recognise, and bearer_token_env_var is simply unset on most
// entries. Neither is a key the file asked this table to publish. An empty key in the env
// table itself is left to envKeyAllowed, which rejects it, so that source counts exactly what
// materialize() counts for the JSON shapes.
func tomlEnvKeys(entry tomlServerEntry) (keys []string, droppedKeys, literalHeaders int) {
	total := len(entry.Env) + len(entry.EnvVars) + len(entry.EnvHTTPHeaders)
	if entry.BearerTokenEnvVar != "" {
		total++
	}
	if total == 0 {
		return nil, 0, 0
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	// Gated here as well as at the row boundary. Two gates in series, and this is the one
	// that can say *which* source the rejected name came from -- the boundary gate sees a
	// flat list and can only report a count.
	//
	// Rejections are counted per occurrence rather than per distinct name, so two sources
	// naming the same invalid variable count twice. That matches what the count means: how
	// many of the names the entry supplied could not be published.
	add := func(name string) {
		if !envKeyAllowed(name) {
			droppedKeys++
			return
		}
		if _, duplicate := seen[name]; duplicate {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for key := range entry.Env {
		add(key)
	}
	for _, reference := range entry.EnvVars {
		if reference.Name == "" {
			continue
		}
		add(reference.Name)
	}
	// env_http_headers maps a header name to the *name* of the variable holding its value,
	// so the variable names are the values here rather than the keys.
	//
	// A value that is not a variable name means the user wrote the credential into the
	// configuration file instead of naming where it lives -- `Authorization = "Bearer abc"`
	// rather than `Authorization = "MY_TOKEN"`. That is reported with its own code rather
	// than folded into a generic drop count, because the two call for different responses:
	// a dropped malformed name is a note, and a credential sitting in a config file is the
	// thing a security inventory exists to surface.
	//
	// Codex also supports a literal `http_headers` table. No reader is added for it
	// deliberately: its values are credentials by design, so there is nothing this table
	// could usefully publish from it.
	for _, variable := range entry.EnvHTTPHeaders {
		if variable == "" {
			// A header mapped to nothing names no variable and holds no credential.
			continue
		}
		if !envKeyAllowed(variable) {
			// Counted separately from the dropped names, and per header rather than once
			// per entry: an operator told that one header holds a literal value has to be
			// told when three do, because each is a credential to move out of the file.
			literalHeaders++
			continue
		}
		add(variable)
	}
	if entry.BearerTokenEnvVar != "" {
		add(entry.BearerTokenEnvVar)
	}
	return out, droppedKeys, literalHeaders
}

// looksLikeTOMLServerEntry reports whether a decoded entry declares anything that identifies a
// server. The TOML counterpart of looksLikeServerEntry, kept separate because the two formats'
// field sets differ: env_vars, bearer_token_env_var and env_http_headers exist only here.
func looksLikeTOMLServerEntry(entry tomlServerEntry) bool {
	return entry.Command != "" || entry.URL != "" || entry.Type != "" || entry.Transport != "" ||
		len(entry.Args) > 0 || len(entry.Env) > 0 || namesAnEnvVar(entry.EnvVars) ||
		entry.BearerTokenEnvVar != "" || len(entry.EnvHTTPHeaders) > 0 ||
		entry.Enabled != nil || entry.Disabled != nil
}

// namesAnEnvVar reports whether env_vars holds at least one reference that decoded to a real
// variable name.
//
// Counting the slice length was enough to make an entry a server, and UnmarshalTOML
// deliberately yields an empty name for a shape it does not recognise rather than failing the
// file. `env_vars = [123]` therefore declared a server: one element, no name, and a row with a
// server name, no command, no endpoint and no env keys -- the same phantom the zero-valued
// JSON entries produced before they were counted as skipped.
func namesAnEnvVar(references []tomlEnvVar) bool {
	for _, reference := range references {
		if reference.Name != "" {
			return true
		}
	}
	return false
}
