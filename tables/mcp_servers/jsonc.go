package mcp_servers

// stripJSONC removes // line comments and /* */ block comments from a JSON-with-comments
// document. The stripper is string-aware: it does not touch sequences that appear inside
// double-quoted strings, so values like "https://example.com" or "// note" survive.
//
// Trailing commas are removed too. They are not rare: the VS Code family documents its
// mcp.json as JSON-with-comments and accepts them, so a config a user edited in the editor
// that wrote it could be perfectly valid to that editor and rejected outright here --
// encoding/json refuses a trailing comma, and the whole file became one parse-warning row.
//
// It does not support single-quoted strings, which JSONC does not either.
//
// Returns terminated=false when a block comment was opened and never closed. Such a file is
// malformed, and the stripped prefix in front of the opener can still be valid JSON on its own,
// so silently returning it would report a truncated file as a clean one. The caller turns a
// false here into a parse warning.
//
// Two passes over the input, one allocation: comments are removed into a new buffer, then
// trailing commas are compacted within that same buffer.
func stripJSONC(in []byte) (out []byte, terminated bool) {
	out = make([]byte, 0, len(in))
	inString := false
	escape := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escape:
				escape = false
			case c == '\\':
				escape = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(in) {
			next := in[i+1]
			if next == '/' {
				i += 2
				for i < len(in) && in[i] != '\n' {
					i++
				}
				if i < len(in) {
					out = append(out, '\n')
				}
				continue
			}
			if next == '*' {
				// Leave a separator behind, the same way the // branch above preserves its
				// newline. Valid JSON never places two value tokens adjacent with only a
				// comment between them, so this is hardening rather than a fix, but the
				// asymmetry with the line-comment branch is not worth keeping.
				out = append(out, ' ')
				i += 2
				closed := false
				// Scan forward to the closing */. Written as a positive break
				// rather than a negated conjunction: the condition is "have we
				// reached the terminator", which this states directly rather than as
				// either form of "not not at it".
				for i+1 < len(in) {
					if in[i] == '*' && in[i+1] == '/' {
						closed = true
						break
					}
					i++
				}
				if !closed {
					return out, false
				}
				i++
				continue
			}
		}
		out = append(out, c)
	}
	return compactTrailingCommas(out), true
}

// compactTrailingCommas removes a comma that is followed, ignoring whitespace, by the close
// of the object or array it sits in. Run after comment removal, so only whitespace can
// separate the comma from its closer.
//
// Rewrites buf in place and returns the shortened slice. Removal only ever shrinks, so a
// write index trailing the read index is safe, and it keeps the whole stripper to a single
// allocation. Only ever called with the buffer stripJSONC just allocated, which nothing
// else holds a reference to.
//
// String-aware for the same reason the comment stripper is: a comma inside a value such as
// "a,}" is data, and dropping it would corrupt the very configuration this is rescuing.
func compactTrailingCommas(buf []byte) []byte {
	in := buf
	out := buf[:0]
	inString, escape := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escape:
				escape = false
			case c == '\\':
				escape = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' && closesNext(in[i+1:]) {
			continue // trailing: drop it and keep the whitespace that follows
		}
		out = append(out, c)
	}
	return out
}

// closesNext reports whether the next non-whitespace byte closes an object or array.
func closesNext(rest []byte) bool {
	for _, c := range rest {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '}', ']':
			return true
		default:
			return false
		}
	}
	return false
}
