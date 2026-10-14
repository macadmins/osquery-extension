package mcp_servers

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Every declared code has a sentence and a completeness classification.
//
// The two cannot be allowed to drift, and nothing in the compiler would say so. A code with
// no sentence renders as "unclassified finding", which is a row an operator cannot act on. A
// code with no entry in the scope switch falls to the default, which marks the row incomplete
// -- the safe direction, but silently wrong for a code that describes a dropped column rather
// than a missing row, and a column that is almost always zero is a column nobody reads.
//
// Derived from warnSentences rather than from a hand-written list, so the enumeration cannot
// itself be the thing that goes stale.
func TestWarnCodesAreExhaustivelyClassified(t *testing.T) {
	codes := warnCodes()
	if len(codes) == 0 {
		t.Fatal("no warning codes are declared")
	}
	// A code must be classified explicitly. The default branch exists so an unclassified
	// code fails safe at runtime, not so one can be left unclassified -- which is why this
	// compares against a list of the cases that are written out.
	classified := map[warnCode]warnScope{}
	for _, code := range codes {
		classified[code] = code.scope()
	}
	for _, code := range codes {
		sentence, ok := warnSentences[code]
		if !ok || sentence == "" {
			t.Errorf("code %q has no sentence", code)
		}
		// A sentence has to say what was lost, not merely that something happened. Checked
		// crudely -- a minimum length -- because the useful property is impossible to
		// assert and the useless one ("") is what actually goes wrong.
		if len(sentence) < 20 {
			t.Errorf("code %q has a sentence too short to be useful: %q", code, sentence)
		}
		switch classified[code] {
		case scopeDescriptive, scopeSource, scopeHome:
		default:
			t.Errorf("code %q has no scope", code)
		}
		// And the two derived answers must agree, since degradesCompleteness is what
		// scan_complete is computed from.
		wantDegrades := classified[code] != scopeDescriptive
		if code.degradesCompleteness() != wantDegrades {
			t.Errorf("code %q: degradesCompleteness = %v, scope = %v",
				code, code.degradesCompleteness(), classified[code])
		}
	}

	// A sentence with no code is the other direction of drift: dead text nothing emits.
	// Cheap to catch here, because warnCodes is derived from the same map.
	if len(warnSentences) != len(codes) {
		t.Errorf("warnSentences holds %d entries for %d codes", len(warnSentences), len(codes))
	}
}

// No user byte reaches the warning column, over a corpus built to leak one.
//
// This is the strong form of the Ask-2 assertion and the reason the catalogue exists. Each
// case is a real file shape that used to put its own bytes in the column: the TOML parser
// quotes the token it failed on, encoding/json names the offending value, and the read path
// carried the operating system's message with the path in it.
//
// Asserted as the absence of the secret bytes rather than as the presence of a marker,
// because the value is supposed never to enter the column at all. A marker would mean it got
// there and was caught, which is a weaker guarantee resting on redaction recognising the
// shape -- and an opaque secret is exactly what redaction cannot recognise.
func TestWarningColumnCarriesNoInputBytes(t *testing.T) {
	// Deliberately shapeless. A recognisable issuer prefix would be redacted on the way out
	// and the test would pass for the wrong reason.
	const secret = "Zq7xPlmNvBc2WdEr9TyUiOp0AsDfGhJk"

	for _, tc := range []struct {
		name string
		run  func() warning
	}{
		{
			// The case the review named. `env = { TOKEN = <bare> }` is invalid TOML, and
			// ParseError.Message is the field carrying `found "..."`.
			name: "TOML carrying a token in an unquoted value",
			run: func() warning {
				doc := "[mcp_servers.x]\ncommand = \"npx\"\nenv = { TOKEN = " + secret + " }\n"
				var into struct {
					MCPServers map[string]toml.Primitive `toml:"mcp_servers"`
				}
				_, err := toml.Decode(doc, &into)
				if err == nil {
					t.Fatal("the fixture is wrong: this TOML must fail to parse")
				}
				return parseWarning(err)
			},
		},
		{
			// A quoted TOML key, which is where LastKey becomes a sentence rather than an
			// identifier. This is the step past what the review suggested.
			name: "TOML with the secret in a quoted key",
			run: func() warning {
				doc := "[mcp_servers.x]\n\"my token is " + secret + "\" = \n"
				var into map[string]any
				_, err := toml.Decode(doc, &into)
				if err == nil {
					t.Fatal("the fixture is wrong: this TOML must fail to parse")
				}
				return parseWarning(err)
			},
		},
		{
			name: "JSON malformed around a token",
			run: func() warning {
				var into map[string]any
				err := json.Unmarshal([]byte(`{"mcpServers":{"x":`+secret+`}}`), &into)
				if err == nil {
					t.Fatal("the fixture is wrong: this JSON must fail to parse")
				}
				return parseWarning(err)
			},
		},
		{
			name: "JSON with the wrong type carrying a token",
			run: func() warning {
				var into struct {
					MCPServers map[string]rawServerEntry `json:"mcpServers"`
				}
				err := json.Unmarshal(
					[]byte(`{"mcpServers":{"x":{"command":["`+secret+`"]}}}`), &into)
				if err == nil {
					t.Fatal("the fixture is wrong: this JSON must fail to unmarshal")
				}
				return parseWarning(err)
			},
		},
		{
			name: "a read failure on a path containing a token",
			run: func() warning {
				_, err := fsscan.ReadBoundedUnder(t.TempDir(),
					filepath.Join("--token="+secret, "mcp.json"), probeReadOpts(MaxFileSize))
				if err == nil {
					t.Fatal("the fixture is wrong: this read must fail")
				}
				return warning{Code: warnSourceUnreadable, Class: fsscan.ClassifyError(err)}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.run()
			if w.empty() {
				t.Fatal("no warning was produced, so the column says nothing went wrong")
			}
			rendered := w.render()
			if strings.Contains(rendered, secret) {
				t.Errorf("the rendered warning carries the input: %q", rendered)
			}
			// Stronger than the secret alone: no substantial run of the input may survive.
			// A truncated secret is still a secret, and the 8-byte window catches a
			// message that quoted only part of the value.
			for i := 0; i+8 <= len(secret); i++ {
				if strings.Contains(rendered, secret[i:i+8]) {
					t.Errorf("the rendered warning carries an 8-byte run of the input "+
						"(%q): %q", secret[i:i+8], rendered)
					break
				}
			}
			// And it must still be useful. A warning that is safe because it says nothing
			// would pass every assertion above.
			if len(rendered) < 20 {
				t.Errorf("the rendered warning says nothing: %q", rendered)
			}
		})
	}
}

// The one user-chosen field that may be reported, and the grammar that lets it through.
func TestWarningKeyGrammar(t *testing.T) {
	for _, tc := range []struct {
		candidate string
		allowed   bool
	}{
		// Real configuration keys.
		{"mcp_servers", true},
		{"github", true},
		{"my-server.v2", true},
		{"_internal", true},
		// A TOML quoted key carrying a sentence. Permitted by the format, refused here.
		{"my token is Zq7xPlmNvBc2WdEr", false},
		// The shapes a credential needs and an identifier cannot have.
		{"TOKEN=abc123", false},
		{"user:password", false},
		{"/path/to/thing", false},
		{"sk-ant-api03-ZZZZ", true}, // an identifier by shape; redaction is the second gate
		{"", false},
		{"1leading-digit", false},
		{strings.Repeat("a", maxReportedKeyLength+1), false},
		// A control character, which breaks a log line and reads as two rows.
		{"name\nwith-newline", false},
	} {
		got := warning{Code: warnParseFailed}.withKey(tc.candidate)
		if (got.Key != "") != tc.allowed {
			t.Errorf("withKey(%q) set Key=%q, allowed=%v", tc.candidate, got.Key, tc.allowed)
		}
		// And the render must agree with the field, since render re-checks rather than
		// trusting it -- the struct is assignable within the package.
		rendered := got.render()
		if tc.allowed && !strings.Contains(rendered, tc.candidate) {
			t.Errorf("an allowed key did not reach the column: %q", rendered)
		}
		if !tc.allowed && tc.candidate != "" && strings.Contains(rendered, tc.candidate) {
			t.Errorf("a refused key reached the column: %q", rendered)
		}
	}
}

// A key assigned directly, bypassing withKey, is still refused at render.
//
// withKey is the only intended setter, but warning is a struct in the same package, so a
// future call site can assign the field. The render-time re-check is what makes the grammar a
// property of the column rather than of one function's discipline.
func TestRenderRefusesAnUngatedKey(t *testing.T) {
	w := warning{Code: warnParseFailed, Key: "TOKEN=Zq7xPlmNvBc2WdEr"}
	if strings.Contains(w.render(), "Zq7xPlmNvBc2WdEr") {
		t.Errorf("a directly-assigned key bypassed the grammar: %q", w.render())
	}
}

// The JSON value kind is validated against a closed set rather than trusted.
func TestWarningValueIsAClosedSet(t *testing.T) {
	for candidate, allowed := range map[string]bool{
		"string": true, "number": true, "bool": true, "array": true,
		"object": true, "null": true,
		// Not a JSON value kind. encoding/json documents Value as a description, not an
		// enum, so a future release putting something richer there must not widen the
		// column's alphabet.
		"something else entirely": false,
		"Zq7xPlmNvBc2WdEr":        false,
		"":                        false,
	} {
		got := warning{Code: warnParseFailed}.withValue(candidate)
		if (got.Value != "") != allowed {
			t.Errorf("withValue(%q) set Value=%q, allowed=%v", candidate, got.Value, allowed)
		}
	}
}

// Every warning code has a sentence, and the catalogue has no members this test does not know
// about.
//
// The column is assembled from a fixed sentence chosen by code, so a code with no entry in
// warnSentences publishes an empty warning -- a row that says something was lost without
// saying what. Three rounds of new codes were checked by hand instead, which is the sort of
// step that belongs in a test.
//
// The count assertion is what makes this self-maintaining: adding a constant without adding it
// here fails, rather than silently going unchecked.
func TestEveryWarningCodeHasASentence(t *testing.T) {
	codes := []warnCode{
		warnRosterUnreachable, warnRosterQueryFailed, warnRosterAccountUnnamed,
		warnAccountNotInRoster, warnAccountNonLogin, warnAccountNoHome, warnAccountHomeMissing,
		warnAccountHomeUnstattable, warnAccountHomeRedirected, warnAccountHomeNotDirectory,
		warnAccountsHomeUnusable, warnHomeUnreadable, warnBudgetExhaustedPreHome,
		warnCancelledPreHome, warnBudgetExhaustedOpening, warnBudgetExhaustedInHome,
		warnCancelledInHome, warnAppDataUndetermined, warnAppDataRedirectedOut,
		warnProfileListUnreadable, warnProjectListUnreadable, warnProjectListTruncated,
		warnProjectOutsideHome, warnProjectMalformed, warnProjectRemoteOrigin,
		warnProjectCloudPlaceholder, warnProjectUserspaceFS, warnProjectRefused,
		warnProjectUntrusted, warnProjectTrustUnknown, warnApprovalSettingsUnreadable,
		warnWorkspaceListUnreadable, warnWorkspaceListTruncated, warnWorkspaceRecordUnreadable,
		warnWorkspaceRecordMalformed, warnPluginListUnreadable, warnPluginListTruncated,
		warnPluginSettingsUnreadable, warnPluginRecordsUnreadable, warnPluginSuperseded,
		warnPluginManifestUnreadable, warnPluginManifestUnsupported, warnPluginManifestTruncated,
		warnPluginManifestMissing, warnPluginManifestInvalid, warnPluginShadowedDecl, warnPluginSelectionUnknown,
		warnSourceUnreadable, warnSourceTooLarge, warnParseFailed, warnEntriesSkipped,
		warnCommandBasenameDropped, warnServerNameUnrepresentable, warnSourceContextPathDropped,
		warnURLEndpointDropped, warnEnvKeyDropped, warnEnvHeaderLiteral, warnIdentityDropped,
		warnUserIDDropped, warnUnknownLauncherOption,
	}
	if len(codes) != len(warnSentences) {
		t.Fatalf("this test knows %d codes and the catalogue holds %d; a code was added "+
			"without being accounted for here", len(codes), len(warnSentences))
	}
	seen := map[warnCode]bool{}
	for _, code := range codes {
		if seen[code] {
			t.Errorf("%s listed twice", code)
		}
		seen[code] = true
		if rendered := (warning{Code: code}).render(); rendered == "" {
			t.Errorf("%s renders an empty warning, so a row would report a loss with no "+
				"statement of what was lost", code)
		}
	}
}
