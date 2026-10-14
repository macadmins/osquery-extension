package mcp_servers

import (
	"bytes"
	"encoding/json"
	"errors"
)

// rawServerEntry is the union of fields any MCP client uses per-server. Env values are
// accepted (so unmarshalling succeeds) but never re-emitted: only env keys are exported.
type rawServerEntry struct {
	Command   string         `json:"command,omitempty"`
	Args      []string       `json:"args,omitempty"`
	Env       map[string]any `json:"env,omitempty"`
	URL       string         `json:"url,omitempty"`
	ServerURL string         `json:"serverUrl,omitempty"`
	HTTPURL   string         `json:"httpUrl,omitempty"`
	Type      string         `json:"type,omitempty"`
	Transport string         `json:"transport,omitempty"`
	Disabled  *bool          `json:"disabled,omitempty"`
}

// extractEnvelope parses a JSON document and returns the union of servers found
// under {mcpServers: {...}} and {servers: {...}}, with mcpServers winning on key
// collision. Returns nil if the file has neither shape (the caller may then try a
// client-specific extractor).
//
// Both shapes are accepted because real-world files mix them (Codex uses `servers`,
// most others use `mcpServers`).
// envelopeEntries carries each envelope's entries separately, because the two spellings are
// not interchangeable to a reader: VS Code writes `servers` and most others write
// `mcpServers`, and source_context is supposed to say where in the file a row came from.
// Merging them and labelling everything "mcpServers" described the wrong location.
type envelopeEntries struct {
	MCPServers map[string]rawServerEntry
	Servers    map[string]rawServerEntry
	// Present records that a recognised envelope key existed, independently of whether it
	// yielded anything. An envelope that is present and legitimately empty must not fall
	// through to the flat parser, or an unrelated sibling gets emitted as a server; but it
	// must not be an error either, because a configuration with no servers in it is a
	// perfectly ordinary thing for a user to have.
	Present bool
}

// errNoDecodableEntries means the document does have an mcpServers or servers envelope and
// every entry in it failed to decode.
//
// It is distinguished from a document that is not JSON at all because the two need opposite
// handling. Invalid JSON can fall through to the flat shape, which will fail the same way. A
// malformed *envelope* must not: falling back let an unrelated top-level object such as
// {"other": {"command": "node"}} satisfy the flat parser, so the broken envelope was silently
// reinterpreted, its entries dropped, and no diagnostic emitted.
var errNoDecodableEntries = errors.New("envelope present but no decodable server entries")

func extractEnvelope(raw []byte) (envelopeEntries, int, error) {
	var out envelopeEntries

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return out, 0, err
	}
	out.MCPServers = map[string]rawServerEntry{}
	out.Servers = map[string]rawServerEntry{}

	// Four states are tracked separately because they mean different things to a consumer:
	// whether a recognised key was present at all, how many entries were unreadable, how many
	// whole envelopes were the wrong type, and how many servers came out usable. An earlier
	// version collapsed all of them into one error, which reported {"mcpServers": {}} -- a
	// valid zero-server configuration -- as a malformed file.
	skipped, malformedEnvelopes := 0, 0
	// Names the high-priority envelope *declares*, as opposed to the ones it successfully
	// decodes. Precedence is a property of the declaration: a name spelled in mcpServers is
	// spoken for whether or not its entry is readable.
	declaredByMCPServers := map[string]struct{}{}
	for key, target := range map[string]map[string]rawServerEntry{
		"servers": out.Servers, "mcpServers": out.MCPServers,
	} {
		value, present := top[key]
		if !present {
			continue
		}
		out.Present = true
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(value, &entries); err != nil {
			// Present but the wrong shape: an array, a string, a number. This envelope is
			// malformed. The other one, if there is one, is unaffected -- returning here
			// discarded a healthy `servers` alongside a malformed `mcpServers`.
			malformedEnvelopes++
			continue
		}
		if key == "mcpServers" {
			for name := range entries {
				declaredByMCPServers[name] = struct{}{}
			}
		}
		// A nil map covers both {} and null. Neither is a failure: the key is present and
		// declares no servers.
		skipped += decodeInto(target, entries)
	}
	if !out.Present {
		// No recognised envelope key. The only case where reading the document as flat is a
		// legitimate interpretation.
		return out, 0, nil
	}
	// mcpServers wins on collision, so drop the duplicate from the servers side rather than
	// emitting the same server twice under two contexts.
	//
	// Keyed on the declared names, not out.MCPServers. Those differ exactly when a
	// high-priority entry is unreadable, and that is the case where the distinction decides
	// what the table says: suppressing only decoded names let the shadowed `servers` entry
	// take the broken entry's place and be reported as the effective configuration, which
	// inverts the precedence this comment claims. An entry that is declared but unreadable
	// is already counted in skipped, so the loss is reported rather than papered over.
	for name := range declaredByMCPServers {
		delete(out.Servers, name)
	}
	if len(out.MCPServers)+len(out.Servers) == 0 && (malformedEnvelopes > 0 || skipped > 0) {
		// Recognised content existed and none of it could be recovered.
		return out, skipped, errNoDecodableEntries
	}
	if malformedEnvelopes > 0 {
		// Healthy rows survive; the failure is reported alongside them rather than instead
		// of them.
		skipped += malformedEnvelopes
	}
	return out, skipped, nil
}

// decodeInto decodes each entry on its own, skips the ones that fail, and reports how many it
// skipped so the caller can say so.
//
// Decoding the whole map in one Unmarshal meant a single entry with a wrong field type -- one
// `"command": 123` -- failed the document and took every healthy server in the file with it.
// A per-entry decode keeps the healthy ones. The skip count matters because a server that is
// configured but unreadable is not the same as one that is absent, so the shortfall is said
// out loud on a row of its own. Note what that does and does not buy: the diagnostic is a
// separate row, so `warning = ”` selects the healthy servers and discards the notice with
// the rest. Counting here is what makes the notice exist at all; reading it is the
// operator's second query, and the README says so.
//
// The skip count is now also what makes scan_complete answerable for this file.
//
// This carried a KNOWN GAP saying no single predicate expressed "complete": `warning = ”`
// selects the healthy servers and discards the notice along with them, so a short list was
// indistinguishable from a full one. The two ways out were propagating incompleteness onto
// every row -- which makes a partly read home unreachable through the documented filter --
// or adding a column. The column was added, scoped: warnEntriesSkipped is source-scope, so
// it marks the rows of this file and not the rest of the account, which is what makes
// `WHERE scan_complete = 1` select a usable partial inventory rather than nothing.
func decodeInto(out map[string]rawServerEntry, in map[string]json.RawMessage) int {
	skipped := 0
	for name, value := range in {
		var entry rawServerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			skipped++
			continue
		}
		// A shape check, not just a decode check. `null` and `{}` unmarshal without error
		// into a zero entry, which became a row with a server name, transport=unknown and no
		// warning: a phantom server that was never configured. The flat extractor already
		// applied this test; the envelope path did not.
		if !looksLikeServerEntry(entry) {
			skipped++
			continue
		}
		out[name] = entry
	}
	return skipped
}

// skippedEntryWarning renders the diagnostic row that accompanies healthy rows when some
// entries in the same file could not be decoded.
//
// The one funnel of the four that was already safe: a count is an integer. It is now a code
// plus that count, which buys something the sentence did not -- warnEntriesSkipped is
// source-scope, so finishProcessing marks every row from this file as an incomplete listing
// of it. That is what closes the gap recorded below: `warning = ”` selects the healthy
// servers and discards this notice with the rest, so before scan_complete existed there was
// no single predicate for "this file was read in full".
func skippedEntryWarning(skipped int) []Server {
	if skipped == 0 {
		return nil
	}
	// User, SourcePath and Client are stamped by finishProcessing, which also runs
	// inferIdentity over these rows; the identity columns are set here regardless so the row
	// satisfies the contract even if a future caller returns it without that pass.
	return []Server{diagnosticRow("", "", "",
		warning{Code: warnEntriesSkipped, Count: skipped})}
}

// extractFlat parses a flat shape: {"<name>": {<entry>}, ...}. Used by project-local
// .mcp.json files. Only entries that look like a real server entry are kept: this
// avoids misclassifying arbitrary JSON objects.
//
// Values are decoded one at a time rather than as map[string]rawServerEntry, because a flat
// config legitimately carries non-object siblings: "$schema" is the common one. Decoding the
// whole map at once fails on the first string it meets, and the caller treats that failure as
// "this file is not MCP configuration", so every real server in the file was discarded with
// it and no warning row was emitted to say so.
//
// A value that is an object but does not decode is skipped rather than returned as an error,
// for the same reason: one malformed entry must not take its healthy siblings down with it.
func extractFlat(raw []byte) (map[string]rawServerEntry, int, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, 0, err
	}
	skipped := 0
	out := make(map[string]rawServerEntry, len(top))
	for name, value := range top {
		// Only an object can be a server entry. encoding/json has already validated that
		// value is well-formed JSON, so inspecting the first byte is enough to classify it.
		if trimmed := bytes.TrimLeft(value, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}
		var entry rawServerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			// An object that does not decode was meant to be a server entry and is not
			// readable. Counted, so the caller can say the listing is short, rather than
			// dropped the way a non-object metadata sibling is.
			skipped++
			continue
		}
		if looksLikeServerEntry(entry) {
			out[name] = entry
			continue
		}
		// Decoded cleanly but holds nothing usable. In the envelope shapes every key under
		// `mcpServers` is a server by construction, so decodeInto counts all of these. Here
		// the siblings are arbitrary -- `$schema`, `inputs` -- and counting them would
		// attach a "could not be decoded" warning to files that are perfectly fine.
		//
		// The distinguishing question is whether the object was *trying* to be a server
		// entry. `{"command": null}` names a server key and produces nothing; `{"note":
		// "hi"}` names none and is metadata. Before this, the first was dropped in silence:
		// a file holding only that entry returned no rows and no warning, which reads as a
		// file with no MCP servers in it.
		if namesServerKey(value) {
			skipped++
		}
	}
	if len(out) == 0 {
		return nil, skipped, nil
	}
	return out, skipped, nil
}

// namesServerKey reports whether a decoded-but-unusable object carried any of the keys that
// would have made it a server entry, so the caller can tell a broken entry from a metadata
// sibling. Keys only -- the values are what failed, so their contents say nothing.
func namesServerKey(value json.RawMessage) bool {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(value, &keys); err != nil {
		return false
	}
	// The same set looksLikeServerEntry reads, by their JSON names. `env` and `disabled` are
	// deliberately absent: neither makes an entry a server on its own, and an object holding
	// only those is as likely to be configuration for something else.
	for _, key := range []string{"command", "args", "url", "serverUrl", "httpUrl", "type", "transport"} {
		if _, ok := keys[key]; ok {
			return true
		}
	}
	return false
}

func looksLikeServerEntry(e rawServerEntry) bool {
	return e.Command != "" || e.URL != "" || e.ServerURL != "" || e.HTTPURL != "" ||
		e.Type != "" || e.Transport != "" || len(e.Args) > 0
}
