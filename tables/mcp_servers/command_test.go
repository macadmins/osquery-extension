package mcp_servers

import (
	"runtime"
	"strings"
	"testing"
)

// TestCommandFieldSplitting pins the whole split decision on both platforms.
//
// Four things were wrong before, each producing a confident answer from data that did not
// support it: a Windows path was not split at all, so the identity switch never matched;
// `C:\Program Files\...` was cut at the space, reporting the launcher of an ordinary nodejs
// install as "Program"; `npx.cmd`, which is what Windows resolves `npx` to, matched nothing
// because the executable suffix was never removed; and a field that embedded arguments
// alongside an args array had its final path component -- an argument -- reported as the
// launcher.
//
// goos is a parameter because the separator sets differ and a backslash is a legal
// character in a POSIX filename. Both dialects have to be reachable from a test on any host.
func TestCommandFieldSplitting(t *testing.T) {
	for _, tc := range []struct {
		goos, cmd    string
		argsPresent  bool
		wantBasename string
		wantLauncher string
		wantEmbedded []string
	}{
		// A spaced Windows executable is one path whether or not an args array was
		// supplied. Both spellings of "no arguments" -- the field omitted and an explicit
		// empty array -- reach here as argsPresent=false.
		{"windows", `C:\Program Files\nodejs\npx.cmd`, true, "npx.cmd", "npx", nil},
		{"windows", `C:\Program Files\nodejs\npx.cmd`, false, "npx.cmd", "npx", nil},
		{"windows", `C:\tools\NPX.CMD`, true, "NPX.CMD", "npx", nil},
		{"windows", `C:\tools\uvx.exe`, true, "uvx.exe", "uvx", nil},
		{"windows", `C:\tools\npx`, true, "npx", "npx", nil},
		// Windows with embedded arguments. Unquoted, the launcher has to be recognised for
		// the field to be readable at all; quoted, it is unambiguous, and quoting is what
		// Windows itself requires for a spaced program path followed by arguments.
		{"windows", `C:\tools\npx -y pkg`, false, "npx", "npx", []string{"-y", "pkg"}},
		{"windows", `C:\tools\node.exe C:\srv\x.js`, false, "node.exe", "node", []string{`C:\srv\x.js`}},
		{"windows", `"C:\Program Files\nodejs\node.exe" server.js`, false, "node.exe", "node", []string{"server.js"}},
		{"windows", `C:\tools\node.exe \\server\share\x.js`, false, "node.exe", "node", []string{`\\server\share\x.js`}},
		// An opening quote with no closing one is not a quoted span, and what remains
		// resolves to neither a filename nor a launcher. Reporting nothing is the point:
		// the alternative readings are "server.js" and a drive-qualified fragment.
		{"windows", `"C:\Program Files\nodejs\node.exe server.js`, false, "", "", nil},
		// POSIX: a backslash is part of the filename, not a separator.
		{"darwin", `foo\uvx`, true, `foo\uvx`, `foo\uvx`, nil},
		{"linux", "/usr/local/bin/npx", true, "npx", "npx", nil},
		{"linux", "/opt/bin/thing.exe", true, "thing.exe", "thing.exe", nil},
		// A spaced POSIX executable, with and without an args array.
		{"darwin", "/Applications/My Server/bin/uvx", true, "uvx", "uvx", nil},
		{"darwin", "/Applications/My Server/bin/uvx", false, "uvx", "uvx", nil},
		// Embedded arguments with no args array, the documented Cursor quirk. The bare
		// name, the known launcher behind an absolute path, and the unknown launcher
		// identified only by its arguments each take a different route through isInvocation.
		{"darwin", "uvx some-pkg@latest", false, "uvx", "uvx", []string{"some-pkg@latest"}},
		// A bare command name is a launcher whether or not this table knows it, and its
		// argument may be a relative path: nothing but the shape of the first token says
		// this is an invocation rather than a path with a space in its first component.
		{"linux", "mcp-server config/prod.json", false, "mcp-server", "mcp-server", []string{"config/prod.json"}},
		{"linux", "/usr/bin/uvx some-pkg@latest", false, "uvx", "uvx", []string{"some-pkg@latest"}},
		{"linux", "/usr/bin/node src/server.js", false, "node", "node", []string{"src/server.js"}},
		{"linux", "/usr/bin/some-tool --flag x", false, "some-tool", "some-tool", []string{"--flag", "x"}},
		{"linux", "node\n--api-key=leak", false, "node", "node", []string{"--api-key=leak"}},
		// A field that embeds arguments next to an args array that also supplies them. The
		// launcher the field names is still reported; the embedded arguments give way to
		// the declared array, and the final path component never wins -- "opaque-value" is
		// an argument, and "npx" would be a package manager this config never named.
		{"linux", "node /tmp/opaque-value", true, "node", "node", nil},
		{"linux", "node /tmp/npx", true, "node", "node", nil},
		{"linux", "/usr/bin/node /tmp/--api-key=leak", true, "node", "node", nil},
		{"linux", "npx --api-key=" + strings.Repeat("A", 32), true, "npx", "npx", nil},
		{"linux", "node\n--api-key=leak", true, "node", "node", nil},
		{"windows", `C:\tools\npx --api-key=secret`, true, "npx", "npx", nil},
		// Read as a path, but no reading yields a filename: the last component is itself
		// two whitespace-separated words, and the basename floor reports none.
		{"linux", "/opt/a b/c d", true, "", "", nil},
		// An executable whose own filename contains a space. `command` and `args` are
		// separate structured fields, so this needs no quoting and is an ordinary config;
		// it is read as a path, not as the launcher "My". command_basename cannot carry
		// the space, so it reports nothing rather than a fragment of the name.
		{"windows", `C:\Tools\My Server.exe`, false, "", "", nil},
		{"windows", `C:\Tools\My Server.exe`, true, "", "", nil},
		{"darwin", "/opt/bin/My Server", false, "", "", nil},
		{"darwin", "/opt/bin/My Server", true, "", "", nil},
		// An unrecognised launcher with an embedded relative-path argument. This is the
		// same shape as `/Applications/My Server/bin/uvx` character for character, so the
		// path reading is only taken when it names a launcher this table knows. Otherwise
		// the argument's filename would be the reported launcher, and an opaque one at
		// that: "prod.json" and "opaque-value" are user-chosen strings that redact.String
		// cannot recognise as anything.
		{"linux", "/opt/bin/mytool config/prod.json", false, "", "", nil},
		{"linux", "/opt/bin/mytool config/prod.json", true, "", "", nil},
		{"linux", "/opt/bin/mytool relative/opaque-value", false, "", "", nil},
		{"linux", "/opt/bin/mytool relative/opaque-value", true, "", "", nil},
		// A legitimate unknown executable in a spaced directory. Nothing distinguishes it
		// from the two above, so it is reported as unknown rather than guessed at.
		{"windows", `C:\Program Files\vendor\server.exe`, false, "", "", nil},
		{"windows", `C:\Program Files\vendor\server.exe`, true, "", "", nil},
		// The residue of that rule, pinned so it stays deliberate: an argument path ending
		// in a launcher name is read as the path's own filename. Wrong, but the only values
		// this branch can emit are the fixed names in launcherIdentity, so no user-chosen
		// string escapes through it.
		{"linux", "/opt/bin/mytool bin/npx", false, "npx", "npx", nil},
		{"linux", "", false, "", "", nil},
		{"linux", "   ", true, "", "", nil},
	} {
		exe, embedded := commandFieldsFor(tc.goos, tc.cmd, tc.argsPresent)
		if got := executableNameFor(tc.goos, exe); got != tc.wantBasename {
			t.Errorf("basename of %s %q (argsPresent=%v) = %q, want %q",
				tc.goos, tc.cmd, tc.argsPresent, got, tc.wantBasename)
		}
		if got := launcherNameFor(tc.goos, exe); got != tc.wantLauncher {
			t.Errorf("launcher of %s %q (argsPresent=%v) = %q, want %q",
				tc.goos, tc.cmd, tc.argsPresent, got, tc.wantLauncher)
		}
		if !sameArgs(embedded, tc.wantEmbedded) {
			t.Errorf("embedded args of %s %q (argsPresent=%v) = %q, want %q",
				tc.goos, tc.cmd, tc.argsPresent, embedded, tc.wantEmbedded)
		}
	}
}

func sameArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestCommandBasenameHostRules covers the plain cases through the exported-to-the-package
// entry point, which reads runtime.GOOS. Only POSIX spellings appear, because that is the
// dialect a POSIX host can legitimately be asked about.
func TestCommandBasenameHostRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX spellings; the Windows rules are covered by TestCommandFieldSplitting")
	}
	for _, c := range []struct{ in, want string }{
		{"npx", "npx"},
		{"/usr/local/bin/npx", "npx"},
		{"uvx some-package@latest", "uvx"},
		{"/Users/x/.claude/mcp-wrappers/atlassian.sh", "atlassian.sh"},
		{"node --token=abc server.js", "node"},
		// Embedded control characters must separate exactly as a space does. A hostile
		// config can JSON-encode "\n" inside the command field, which would otherwise let
		// an opaque token ride along behind "node".
		{"node\n--api-key=AAAA1234567890ABCD", "node"},
		{"node\r--key=Y", "node"},
		{"node\v--foo", "node"},
		{"node\f--foo", "node"},
		{"  /usr/bin/node\n--api-key=X", "node"},
		{"", ""},
	} {
		if got := commandBasename(c.in, false); got != c.want {
			t.Errorf("commandBasename(%q, false) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCommandBasenameNeverEmitsArguments guards the column's contract against the
// malformed-but-possible config that supplies both an args array and a command that embeds
// its own arguments.
//
// The assertion is the exact value, not merely the absence of whitespace: an implementation
// that returned the first token would satisfy a whitespace check while naming a launcher the
// config never invoked, which is the failure mode this case exists to describe.
func TestCommandBasenameNeverEmitsArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX spellings; the Windows rules are covered by TestCommandFieldSplitting")
	}
	for _, tc := range []struct{ in, want string }{
		{"npx --api-key=" + strings.Repeat("A", 32), "npx"},
		{"node\n--api-key=leak", "node"},
		{"/usr/bin/node /tmp/--api-key=leak", "node"},
		{"/opt/homebrew/bin/npx --api-key=secret", "npx"},
	} {
		if got := commandBasename(tc.in, true); got != tc.want {
			t.Errorf("commandBasename(%q, true) = %q, want %q -- the launcher the field "+
				"names, never any part of its arguments", tc.in, got, tc.want)
		}
	}
}

// TestCommandFieldReachesTheIdentityColumns runs the cases through inferIdentity and
// serverToRow rather than the parser alone.
//
// The parser was correct in isolation before this and still produced "Program" in a row,
// because two callers split the field again with rules of their own: serverToRow tokenised
// on whitespace and identity inference ran its own pre-split first. A helper-level test
// cannot see that.
//
// The spellings here are POSIX because inferIdentity and serverToRow read runtime.GOOS and
// can only be asked about the host's dialect. `/Applications/My Server/bin/npx` is the
// structural twin of `C:\Program Files\nodejs\npx.cmd` -- an absolute path with a space in a
// directory component -- and the Windows spelling of every case below is pinned in
// TestCommandFieldSplitting.
func TestCommandFieldReachesTheIdentityColumns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX spellings; see TestCommandFieldSplitting for the Windows dialect")
	}
	for _, tc := range []struct {
		name           string
		server         Server
		wantBasename   string
		wantManager    string
		wantName       string
		wantConfidence string
	}{
		{
			name:         "spaced absolute executable, args field omitted",
			server:       Server{Command: "/Applications/My Server/bin/npx"},
			wantBasename: "npx", wantManager: "npx", wantConfidence: "low",
		},
		{
			name:         "spaced absolute executable, args field present but empty",
			server:       Server{Command: "/Applications/My Server/bin/npx", Args: []string{}},
			wantBasename: "npx", wantManager: "npx", wantConfidence: "low",
		},
		{
			name:         "spaced absolute executable with a separate args array",
			server:       Server{Command: "/Applications/My Server/bin/npx", Args: []string{"-y", "pkg@1.2.3"}},
			wantBasename: "npx", wantManager: "npx", wantName: "pkg", wantConfidence: "high",
		},
		{
			// Confidence is medium rather than high because `@latest` is a moving tag
			// and so pins no version; the package is still identified. See pinsOneVersion.
			name:         "embedded invocation with no args array still identifies",
			server:       Server{Command: "/usr/bin/uvx some-pkg@latest"},
			wantBasename: "uvx", wantManager: "uvx", wantName: "some-pkg",
			wantConfidence: "medium",
		},
		{
			// An args array says the field is one executable path; the field says
			// otherwise. Reporting the last component would put an opaque argument in
			// command_basename, where redact.String cannot recognise it as anything. The
			// launcher the field does name is reported, and identity stops there.
			name:         "contradictory field does not emit an argument as the launcher",
			server:       Server{Command: "node /tmp/opaque-value", Args: []string{"--serve"}},
			wantBasename: "node", wantManager: "node", wantConfidence: "low",
		},
		{
			// The same shape, but the trailing component is the name of a real package
			// manager. Taking it would report an npx invocation nothing in this config
			// asked for, at high confidence, with a package name to match.
			name:         "contradictory field is not classified by its trailing component",
			server:       Server{Command: "node /tmp/npx", Args: []string{"-y", "pkg@1.2.3"}},
			wantBasename: "node", wantManager: "node", wantConfidence: "low",
		},
		{
			// An unrecognised launcher with a relative-path argument: the path reading
			// would have put the argument's filename in the column, where an operator
			// would read it as the thing that runs.
			name:         "unknown launcher with an embedded relative path reports nothing",
			server:       Server{Command: "/opt/bin/mytool config/prod.json"},
			wantBasename: "", wantManager: "", wantConfidence: "low",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.server
			inferIdentity(&server)
			if server.PackageManager != tc.wantManager {
				t.Errorf("package_manager = %q, want %q", server.PackageManager, tc.wantManager)
			}
			if server.PackageName != tc.wantName {
				t.Errorf("package_name = %q, want %q", server.PackageName, tc.wantName)
			}
			if server.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q", server.Confidence, tc.wantConfidence)
			}
			if row := serverToRow(server); row["command_basename"] != tc.wantBasename {
				t.Errorf("command_basename = %q, want %q", row["command_basename"], tc.wantBasename)
			}
		})
	}
}

// TestSpacedPathsAndLauncherCollisionsAreIndistinguishable pins the cost of reading a
// whitespace-bearing field as a path when its final component names a known launcher.
//
// Two configurations take that branch. One is the reason the branch exists: an executable
// inside a directory whose name contains a space, which is what every `C:\Program
// Files\nodejs\npx.cmd` install looks like. The other is a collision: an unrecognised
// launcher whose path-shaped argument happens to end in a launcher name. Nothing in either
// string distinguishes them, so this asserts the rows are byte-identical rather than
// pretending one can be preferred.
//
// The exposure that buys: if the collision is what a config meant, package_manager,
// package_name and version are wrong together, not just command_basename, because the
// declared args array is handed to the handler for the launcher that was read. Suppressing
// identity for this shape would take those columns off the common case at the same time,
// which is why the trade is made this way and pinned here rather than left implicit.
//
// The second half bounds it: with no args array there is nothing to attribute, so the
// collision cannot reach high confidence.
func TestSpacedPathsAndLauncherCollisionsAreIndistinguishable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX spellings; C:\\Program Files\\nodejs\\npx.cmd is the same shape")
	}
	args := []string{"-y", "pkg@1.2.3"}
	spacedDirectory := Server{Command: "/Applications/My Server/bin/npx", Args: args}
	collision := Server{Command: "/opt/bin/mytool bin/npx", Args: args}
	inferIdentity(&spacedDirectory)
	inferIdentity(&collision)

	if spacedDirectory.PackageManager != "npx" || spacedDirectory.PackageName != "pkg" ||
		spacedDirectory.PinnedVersion != "1.2.3" || spacedDirectory.Confidence != "high" {
		t.Errorf("an executable in a spaced directory lost its identity: %+v", spacedDirectory)
	}
	for column, pair := range map[string][2]string{
		"command_basename": {serverToRow(spacedDirectory)["command_basename"],
			serverToRow(collision)["command_basename"]},
		"package_manager": {spacedDirectory.PackageManager, collision.PackageManager},
		"package_name":    {spacedDirectory.PackageName, collision.PackageName},
		"pinned_version":  {spacedDirectory.PinnedVersion, collision.PinnedVersion},
		"confidence":      {spacedDirectory.Confidence, collision.Confidence},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s differs between the two readings (%q vs %q); if a rule now "+
				"separates them, this trade-off no longer has to be made",
				column, pair[0], pair[1])
		}
	}

	// No args array, so nothing to attribute: the collision cannot claim a package.
	bare := Server{Command: "/opt/bin/mytool bin/npx"}
	inferIdentity(&bare)
	if bare.PackageName != "" || bare.PinnedVersion != "" || bare.Confidence != "low" {
		t.Errorf("a collision with no arguments still produced package identity: %+v", bare)
	}
}

// TestLauncherAliasesReportTheirCanonicalManager pins the two names that report a
// package_manager other than themselves.
//
// `case "docker", "podman":` made divergence impossible to write; two map entries do not,
// and an operator's `WHERE package_manager = 'docker'` would silently stop matching podman
// hosts. Same for python3, which reports "python".
func TestLauncherAliasesReportTheirCanonicalManager(t *testing.T) {
	for _, tc := range []struct{ command, wantManager, wantName string }{
		{"docker", "docker", "alpine"},
		{"podman", "docker", "alpine"},
	} {
		server := Server{Command: tc.command, Args: []string{"run", "-i", "alpine:3"}}
		inferIdentity(&server)
		if server.PackageManager != tc.wantManager || server.PackageName != tc.wantName {
			t.Errorf("%s: package_manager = %q / package_name = %q, want %q / %q",
				tc.command, server.PackageManager, server.PackageName,
				tc.wantManager, tc.wantName)
		}
	}
	for _, command := range []string{"python", "python3"} {
		server := Server{Command: command, Args: []string{"-m", "mymod"}}
		inferIdentity(&server)
		if server.PackageManager != "python" || server.PackageName != "mymod" {
			t.Errorf("%s: package_manager = %q / package_name = %q, want python / mymod",
				command, server.PackageManager, server.PackageName)
		}
	}
}

// TestEveryLauncherAssignsAPackageManager walks launcherIdentity and checks each handler
// does the one thing every caller assumes it does.
//
// Dispatch and the splitter's launcher set are the same map now, so they cannot disagree
// about which names exist. What a shared map cannot enforce is that an entry actually
// claims a package manager: a handler that returns without assigning one would still steer
// the split, and the row would come back with a command_basename and nothing else.
//
// `-m mod` is supplied because python is the one launcher that needs arguments before it
// claims anything; the rest ignore them.
func TestEveryLauncherAssignsAPackageManager(t *testing.T) {
	for name := range launcherIdentity {
		server := Server{Command: name, Args: []string{"-m", "mod"}}
		inferIdentity(&server)
		if server.PackageManager == "" {
			t.Errorf("launcherIdentity[%q] left package_manager empty; the splitter treats "+
				"the name as a launcher, so the row claims one and reports none", name)
		}
	}
}

// TestEmbeddedArgumentsAreRedactedLikeDeclaredOnes pins the two spellings of one
// configuration against each other.
//
// A declared args array is redacted in materialize, before identity inference ever sees it,
// so `["--token", "SECRET", "pkg"]` reaches the scanner as `["--token", "[REDACTED]", "pkg"]`
// and pkg is reported. Arguments embedded in the command field are split inside
// inferIdentity and skipped that pass entirely, so SECRET was the first package-shaped
// positional and was copied into package_name and requested_spec -- an opaque value, which
// is precisely what the final known-token redactor cannot recognise.
//
// The inline form `--token=SECRET` was never exposed: it is a single dash-prefixed token, so
// the scanner skips it. Only the two-argument form leaked, which is why both appear here.
func TestEmbeddedArgumentsAreRedactedLikeDeclaredOnes(t *testing.T) {
	const secret = "opaqueSecretValue"
	for _, tc := range []struct{ name, body string }{
		{"declared", `{"mcpServers":{"a":{"command":"npx","args":["--token","` + secret + `","real-package"]}}}`},
		{"embedded two-argument", `{"mcpServers":{"a":{"command":"npx --token ` + secret + ` real-package"}}}`},
		{"embedded inline", `{"mcpServers":{"a":{"command":"npx --token=` + secret + ` real-package"}}}`},
		{"embedded api-key", `{"mcpServers":{"a":{"command":"uvx --api-key ` + secret + ` real-package"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := finishProcessing("", []byte(tc.body), nil, "/p/.mcp.json", "alice", "claude-code",
				true, MaxFileSize, extractEnvelopeSimple)
			if len(rows) != 1 {
				t.Fatalf("want one row, got %d", len(rows))
			}
			for column, value := range serverToRow(rows[0]) {
				if strings.Contains(value, secret) {
					t.Errorf("%s = %q, which carries the secret", column, value)
				}
			}
			if got := rows[0].PackageName; got != "real-package" {
				t.Errorf("package_name = %q, want real-package: the argument after the "+
					"secret-bearing flag is the package", got)
			}
		})
	}
}

// TestNonASCIIWhitespaceSplitsLikeASpace pins every whitespace test in command.go to the
// same definition strings.Fields and strings.TrimSpace already use.
//
// An ASCII-only list disagreed with them: a command separated by U+00A0 or U+2028 was seen
// as holding no whitespace, so it was returned whole and the entire invocation -- flag,
// secret and package -- was emitted as command_basename. The floor meant to keep argument
// text out of that column never fired, because it was looking for the same ASCII bytes it
// had already failed to find. A no-break space is what copying a command out of
// documentation or a chat client produces, so this is an ordinary accident and not only a
// hostile input.
//
// Separators are built from rune values rather than written literally: a literal U+00A0 in
// source is invisible to a reviewer and indistinguishable from the space beside it.
//
// The assertion is equality with the ASCII spelling rather than a property, so a later
// change cannot satisfy it by emptying the column for every separator at once.
func TestNonASCIIWhitespaceSplitsLikeASpace(t *testing.T) {
	const secret = "opaqueSecretValue"
	body := func(separator string) []byte {
		return []byte(`{"mcpServers":{"a":{"command":"npx` + separator + `--token` + separator +
			secret + separator + `pkg"}}}`)
	}
	identity := func(raw []byte) map[string]string {
		t.Helper()
		rows := finishProcessing("", raw, nil, "/p/.mcp.json", "alice", "claude-code", true, MaxFileSize, extractEnvelopeSimple)
		if len(rows) != 1 {
			t.Fatalf("want one row, got %d", len(rows))
		}
		return serverToRow(rows[0])
	}

	want := identity(body(" "))
	if want["command_basename"] != "npx" || want["package_name"] != "pkg" {
		t.Fatalf("the ASCII baseline is itself wrong: %v", want)
	}
	for _, separator := range []struct {
		name string
		code rune
	}{
		{"U+0085 next line", 0x0085},
		{"U+00A0 no-break space", 0x00A0},
		{"U+2028 line separator", 0x2028},
		{"U+2029 paragraph separator", 0x2029},
		{"U+3000 ideographic space", 0x3000},
	} {
		got := identity(body(string(separator.code)))
		for _, column := range []string{"command_basename", "package_name", "requested_spec"} {
			if got[column] != want[column] {
				t.Errorf("%s: %s = %q, want %q as with an ordinary space",
					separator.name, column, got[column], want[column])
			}
		}
		for column, value := range got {
			if strings.Contains(value, secret) {
				t.Errorf("%s: %s = %q, which carries the secret", separator.name, column, value)
			}
		}
	}
}

// A quoted argument embedded in `command` is one argument, not one per word.
//
// strings.Fields split it, and the pieces went two places that both matter. redactArgs
// redacts a credential by looking back at the option before it, so it redacted only the
// first fragment and left the rest standing: `--token "opaque superSecret value"` put
// superSecret in the row as its own argument, where looksLikePackageSpec accepted it and
// reported it as package_name. The same split reported `--out "a b c" real-package` as
// package_name=b. Both are fixed by keeping the span together: redaction covers all of it,
// and a value holding whitespace can no longer pass as a package.
func TestQuotedEmbeddedArgumentIsOneArgument(t *testing.T) {
	const secret = "superSecretValue"
	cases := []struct{ name, command, wantSpec string }{
		{"quoted credential stays whole", `npx --token "opaque ` + secret + ` value" real-package`, "real-package"},
		{"single quotes too", `npx --token 'opaque ` + secret + ` value' real-package`, "real-package"},
		// The span stays whole, which is this test's subject. Identity is empty because
		// --out is not a known value option, so `a b c` reads as the first operand and an
		// operand that is not package-shaped ends the scan. The arity gap used to be
		// masked here by walking past it to real-package, which was right by luck and is
		// the same walk that reported a script's argument as an installed package.
		{"quoted value of an unknown option yields no identity",
			`npx --out "a b c" real-package`, ""},
		// The same shape with an option whose arity is known: the value is consumed and the
		// real package is still reported.
		{"quoted value of a known value option", `npx --registry "a b c" real-package`, "real-package"},
		{"quoted launcher and quoted credential",
			`"/opt/my tool/npx" --token "opaque ` + secret + ` value" real-package`, "real-package"},
		{"inline quoted value", `npx --flag="a b" real-package`, "real-package"},
		// Where the argument ends is unknowable, so every boundary after it is a guess.
		// The launcher was settled before the quote and still stands.
		{"unterminated quote yields no identity", `npx --token "opaque ` + secret + ` real-package`, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, args := commandFieldsFor("darwin", testCase.command, false)
			redacted := redactArgs(args)
			for _, arg := range redacted {
				if strings.Contains(arg, secret) {
					t.Errorf("a credential fragment survived as an argument: %q", redacted)
				}
			}
			if spec, _, _ := npxIdentity(redacted); spec != testCase.wantSpec {
				t.Errorf("identity = %q, want %q (args %q)", spec, testCase.wantSpec, redacted)
			}
		})
	}
}

// Backslash is a path separator here, not an escape. Treating it as one would corrupt every
// Windows command this table reads.
func TestWindowsPathInCommandSurvivesSplitting(t *testing.T) {
	base, args := commandFieldsFor("windows", `C:\Users\x\npx.cmd real-package`, false)
	if base != `C:\Users\x\npx.cmd` {
		t.Errorf("launcher = %q, want the path unchanged", base)
	}
	if len(args) != 1 || args[0] != "real-package" {
		t.Errorf("args = %q, want [real-package]", args)
	}
}

// Backslash means opposite things on the two platforms, so the splitter is told which one it
// is reading for.
//
// On POSIX an escaped space joins rather than separates, and not honouring that leaked the
// same way the quoted form did: `--token opaque\ secret\ finalPiece` split into four tokens,
// redactArgs covered only the first, and finalPiece passed the package grammar. On Windows
// the byte is a path separator and has to stay literal.
func TestEscapedWhitespaceIsPlatformAware(t *testing.T) {
	const secret = "superSecretValue"
	t.Run("posix honours the escape", func(t *testing.T) {
		_, args := commandFieldsFor("darwin",
			`npx --token opaque\ `+secret+`\ finalPiece real-package`, false)
		redacted := redactArgs(args)
		for _, arg := range redacted {
			if strings.Contains(arg, secret) || strings.Contains(arg, "finalPiece") {
				t.Errorf("a credential fragment survived: %q", redacted)
			}
		}
		if spec, _, _ := npxIdentity(redacted); spec != "real-package" {
			t.Errorf("identity = %q, want real-package (args %q)", spec, redacted)
		}
	})
	t.Run("an escaped value of an ordinary option stays whole", func(t *testing.T) {
		_, args := commandFieldsFor("darwin", `npx --out a\ b\ c real-package`, false)
		if len(args) != 3 || args[1] != "a b c" {
			t.Errorf("args = %q, want [--out \"a b c\" real-package]", args)
		}
	})
	t.Run("a trailing backslash fails closed", func(t *testing.T) {
		_, args := commandFieldsFor("darwin", `npx real-package trailing\`, false)
		if len(args) != 0 {
			t.Errorf("args = %q, want none: where the argument ends is unknowable", args)
		}
	})
	t.Run("windows keeps backslashes literal", func(t *testing.T) {
		base, args := commandFieldsFor("windows",
			`C:\Users\x\npx.cmd --token "opaque `+secret+`" real-package`, false)
		if base != `C:\Users\x\npx.cmd` {
			t.Errorf("launcher = %q, want the path unchanged", base)
		}
		redacted := redactArgs(args)
		for _, arg := range redacted {
			if strings.Contains(arg, secret) {
				t.Errorf("a credential survived: %q", redacted)
			}
		}
		if spec, _, _ := npxIdentity(redacted); spec != "real-package" {
			t.Errorf("identity = %q, want real-package", spec)
		}
	})
}

// Inside double quotes POSIX escapes only five characters. Before anything else the
// backslash is literal and both bytes survive.
//
// Treating it as an escape before every character turned `"foo\bar"` into `foobar`, which
// the package grammar accepts -- so a value a shell would have passed through unchanged, and
// which no grammar would have accepted, was reported as the configured package.
func TestDoubleQuotedBackslashFollowsPOSIXRules(t *testing.T) {
	cases := []struct{ name, command, wantArg, wantSpec string }{
		{"literal before an ordinary character", `npx "foo\bar"`, `foo\bar`, ""},
		{"escape before a dollar", `npx "a\$b"`, `a$b`, ""},
		{"escape before a quote", `npx "say \"hi\""`, `say "hi"`, ""},
		{"escape before a backslash", `npx "back\\slash"`, `back\slash`, ""},
		// Single quotes take no escapes at all, and outside quotes the escape applies to
		// anything -- which is what makes an escaped space join rather than separate.
		// Identity is empty, not real-package: `lit\eral` is npx's first operand and is not
		// package-shaped, so npx was not asked to install a registry package and
		// real-package is an argument to whatever it was asked to run.
		{"single quotes keep it literal", `npx 'lit\eral' real-package`, `lit\eral`, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, args := commandFieldsFor("darwin", testCase.command, false)
			if len(args) == 0 || args[0] != testCase.wantArg {
				t.Errorf("args = %q, want first %q", args, testCase.wantArg)
			}
			if spec, _, _ := npxIdentity(redactArgs(args)); spec != testCase.wantSpec {
				t.Errorf("identity = %q, want %q", spec, testCase.wantSpec)
			}
		})
	}
}
