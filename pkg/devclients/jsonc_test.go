package devclients

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStripJSONC(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no comments", `{"a": 1}`, `{"a": 1}`},
		{"line comment", "{\n// hi\n\"a\": 1\n}", "{\n\n\"a\": 1\n}"},
		// Two spaces: the separator the stripper substitutes for the comment, then the
		// space that followed it in the input. The line-comment case above substitutes a
		// newline for the same reason.
		{"block comment", `{/* hi */ "a": 1}`, `{  "a": 1}`},
		{"slash inside string", `{"url": "https://example.com"}`, `{"url": "https://example.com"}`},
		{"escaped quote in string", `{"a": "he said \"hi\" // joke"}`, `{"a": "he said \"hi\" // joke"}`},
		{"line comment at EOF", `{"a": 1} // trailing`, `{"a": 1} `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stripped, terminated := StripJSONC([]byte(c.in))
			if !terminated {
				t.Fatalf("%s: unexpected unterminated block comment", c.name)
			}
			got := string(stripped)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestStripJSONCBlockCommentDoesNotFuseAdjacentTokens: removing a block comment must not let its
// neighbors fuse into one token. Two numbers with only a comment between them are malformed, and
// stay malformed; without the separator they would become {"a":12}, a value never in the file.
func TestStripJSONCBlockCommentDoesNotFuseAdjacentTokens(t *testing.T) {
	for _, malformed := range []string{`{"a":1/*c*/2}`, `{"a":[1/*c*/2]}`} {
		stripped, _ := StripJSONC([]byte(malformed))
		var parsed any
		if err := json.Unmarshal(stripped, &parsed); err == nil {
			t.Errorf("%s stripped to %q, which parsed to %v: malformed input must stay "+
				"malformed rather than fusing into a different value", malformed, stripped, parsed)
		}
	}
	// The well-formed case still has to survive the separator unharmed.
	stripped, _ := StripJSONC([]byte(`{"a":1/*c*/,"b":2}`))
	var parsed map[string]int
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("valid JSONC broke: %v (%q)", err, stripped)
	}
	if parsed["a"] != 1 || parsed["b"] != 2 {
		t.Errorf("values wrong: %v", parsed)
	}
}

// An unterminated block comment makes a file malformed. The prefix before the opener can be
// valid JSON on its own, so returning it silently would report a truncated file as clean.
func TestStripJSONCReportsUnterminatedBlockComment(t *testing.T) {
	stripped, terminated := StripJSONC([]byte(`{"mcpServers":{"a":{"command":"npx"}}} /* oops`))
	if terminated {
		t.Errorf("unterminated comment reported as terminated; stripped=%q", stripped)
	}
	// A properly closed comment still reports terminated.
	if _, ok := StripJSONC([]byte(`{"a":1/*c*/}`)); !ok {
		t.Error("a closed block comment must report terminated")
	}
}

// TestStripJSONCRemovesTrailingCommasOutsideStrings: a trailing comma before a closer is removed,
// and a comma inside a string value is data and stays.
func TestStripJSONCRemovesTrailingCommasOutsideStrings(t *testing.T) {
	stripped, terminated := StripJSONC([]byte(`{"folders":[{"path":"a,}"},],"x":["b, ]",],}`))
	var parsed struct {
		Folders []struct{ Path string }
		X       []string
	}
	if err := json.Unmarshal(stripped, &parsed); err != nil || !terminated {
		t.Fatalf("stripped %q: %v", stripped, err)
	}
	if len(parsed.Folders) != 1 || parsed.Folders[0].Path != "a,}" ||
		!reflect.DeepEqual(parsed.X, []string{"b, ]"}) {
		t.Errorf("values wrong: %+v", parsed)
	}
}
