package mcp_servers

import (
	"runtime"
	"strings"
	"unicode"
)

// The `command` field of an MCP config is one JSON string holding either of two shapes:
//
//   - a path to the executable, spaces and all. Windows installs live under
//     `C:\Program Files\...`, and splitting that on whitespace reported the launcher of an
//     ordinary nodejs install as "Program", emptying every identity column with it.
//   - an invocation with its arguments embedded, which configs do write in the wild --
//     Cursor's mcp.json carries {"command": "uvx some-pkg@latest"} -- where the first token
//     is the launcher and the rest are arguments.
//
// The presence of an `args` array does not decide which: a spaced path appears with one, and
// an embedded invocation appears without one. So the shape is read from the field itself,
// and the array only decides who owns the arguments. That decision lives in one function,
// commandFieldsFor, and both the command_basename column and identity inference take their
// answer from it -- they used to decide separately, the column splitting on whitespace and
// inference splitting again on its own rules, which is how one config could report basename
// "Program" alongside package_manager "".

// containsWhitespace reports whether s holds any Unicode space character.
//
// Unicode-aware rather than a list of ASCII bytes, and every whitespace test in this file
// goes through it or through unicode.IsSpace directly. Two separate reasons:
//
//   - a split that knew only about " \t" let "node\n--api-key=AAAA..." through as one token,
//     because a config can JSON-encode a literal newline into the command field;
//   - an ASCII-only list disagreed with strings.Fields and strings.TrimSpace, which are
//     Unicode-aware, so a field separated by U+00A0 or U+2028 was seen as having no
//     whitespace at all. It was then returned whole, and the entire invocation -- flag,
//     secret and package -- landed in command_basename, which is the one thing that column
//     exists to prevent. A non-breaking space is what a copy-paste from documentation or a
//     chat client produces, so this is an ordinary accident and not only a hostile input.
func containsWhitespace(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) >= 0
}

// commandFields splits the command field into the executable and any arguments embedded in
// it. embedded is empty when the field carries none, or when the config declared its own
// args array, which is then left in charge.
func commandFields(cmd string, argsPresent bool) (exe string, embedded []string) {
	return commandFieldsFor(runtime.GOOS, cmd, argsPresent)
}

// commandFieldsFor takes the OS as a parameter so both platforms' rules are reachable from a
// test on any host. Nothing here consults the filesystem: a config can name a UNC path, and
// stat-ing `\\attacker\share\x` to find out whether it exists would send this host's
// credentials to whoever the config names.
func commandFieldsFor(goos, cmd string, argsPresent bool) (string, []string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", nil
	}
	// Quoting first: it is the only unambiguous form, so it outranks every heuristic below.
	if quoted, rest, ok := cutQuoted(cmd); ok {
		if argsPresent {
			return quoted, nil
		}
		tailArgs, parsed := splitCommandFields(goos, rest)
		if !parsed {
			return quoted, nil
		}
		return quoted, tailArgs
	}
	if !containsWhitespace(cmd) {
		return cmd, nil
	}
	// Which shape the field has is decided from the field alone, the same way in both
	// modes. The args array does not settle it -- both shapes turn up with and without one
	// -- it only settles who owns the arguments.
	switch commandShapeOf(goos, cmd) {
	case shapeInvocation:
		head, tail := cutWhitespace(cmd)
		if argsPresent {
			// The field embeds arguments and an args array was supplied too, e.g.
			// {"command": "node /tmp/opaque-value", "args": [...]}. The field still names
			// its launcher, so report that; the declared array stays authoritative for the
			// arguments themselves.
			return head, nil
		}
		tailArgs, parsed := splitCommandFields(goos, tail)
		if !parsed {
			// Quoting this function cannot resolve. The launcher name is still unambiguous
			// -- it was settled before the first quote -- so the basename stands, but the
			// arguments do not, and inference runs on nothing rather than on a guess.
			return head, nil
		}
		return head, tailArgs
	case shapePath:
		return cmd, nil
	default:
		// Ambiguous: see commandShapeOf. No basename, so no identity and low confidence.
		return "", nil
	}
}

// commandShape is what a whitespace-bearing command field turned out to be.
type commandShape int

const (
	// shapeInvocation: the first token is the executable and the rest are arguments.
	shapeInvocation commandShape = iota
	// shapePath: the whole field is one path and the spaces are path characters.
	shapePath
	// shapeAmbiguous: both readings fit and nothing in the string chooses between them.
	shapeAmbiguous
)

// commandShapeOf classifies a command field that contains whitespace.
//
// Three independent pieces of evidence make it an invocation, any one of which is enough.
// Each exists because a real configuration shape fails without it:
//
//  1. The first token is a bare command name -- no separator and not rooted. `node
//     src/server.js`. A single relative path whose *first* component contained a space would
//     look the same, but a bare command followed by arguments is the documented quirk and
//     `My Dir/bin/tool` is not a shape these configs use.
//  2. The first token's filename is a launcher this table knows: `/usr/bin/node src/server.js`.
//  3. The text after the space begins with a dash, or is itself rooted. Neither can continue
//     a path: an option is not a path component, and a rooted path does not appear halfway
//     through another one. This keeps an unknown launcher's options out of command_basename
//     -- `/usr/bin/some-tool --flag` reports some-tool, not --flag.
//
// A separator-free tail was a fourth signal until review showed the cost: `C:\Tools\My
// Server.exe` is an ordinary executable -- `command` and `args` are separate structured
// fields, so a filename containing a space needs no quoting -- and that rule read it as the
// launcher "My". Dropping it costs nothing in the common case, because `C:\Program
// Files\...` has a separator after the space and is a path by that alone.
//
// With no invocation evidence the field is read as a path, but only when the path reading
// names a launcher this table knows -- `/Applications/My Server/bin/uvx`, `C:\Program
// Files\nodejs\npx.cmd`. Otherwise both readings fit and neither is reported.
//
// That last rule is what keeps arguments out of the column. Without it,
// `/opt/bin/mytool config/prod.json` read as a path and emitted "prod.json": an argument,
// and an opaque one that redact.String cannot recognise as anything. With it, no
// user-chosen string escapes through the path branch at all -- the only basenames it can
// produce are the fixed names in launcherIdentity. An unrecognised executable under
// `C:\Program Files\vendor\` reports nothing, which is the conservative half of the trade.
//
// What it does not bound is identity. `/opt/bin/mytool bin/npx` with an args array of
// ["-y", "pkg@1.2.3"] reports npx, pkg, 1.2.3 at high confidence, because once the launcher
// is read as npx the declared array is handed to the npx handler. If mytool was the real
// launcher, all four columns are wrong together, not just the name.
//
// That case is kept anyway, because it is the same branch as the one this whole file exists
// for: `C:\Program Files\nodejs\npx.cmd` and `/Applications/My Server/bin/npx`, each with
// their own args array, are classified by exactly this rule and are indistinguishable from
// it -- see TestSpacedPathsAndLauncherCollisionsAreIndistinguishable, which asserts the two
// produce byte-identical rows. Both ways of hedging cost the common case rather than the
// contrived one: suppressing identity takes package_name and version off the most ordinary
// Windows configuration there is, and capping confidence leaves the columns but demotes
// those rows out of every `confidence = 'high'` query, which is the same information an
// administrator loses, by a different route. Without an args array the collision cannot
// reach high confidence at all, since there are then no arguments to attribute.
func commandShapeOf(goos, cmd string) commandShape {
	head, tail := cutWhitespace(cmd)
	separators := pathSeparators(goos)
	if !strings.ContainsAny(head, separators) && !isRootedPath(goos, head) {
		return shapeInvocation
	}
	if _, known := launcherIdentity[launcherNameFor(goos, head)]; known {
		return shapeInvocation
	}
	first, _ := cutWhitespace(strings.TrimLeftFunc(tail, unicode.IsSpace))
	if strings.HasPrefix(first, "-") || isRootedPath(goos, first) {
		return shapeInvocation
	}
	if _, known := launcherIdentity[launcherNameFor(goos, cmd)]; known {
		return shapePath
	}
	return shapeAmbiguous
}

// cutQuoted splits a leading double-quoted span from the rest of the field.
//
// This is the form Windows itself requires to run a program whose path contains a space with
// arguments after it: `"C:\Program Files\nodejs\node.exe" server.js`. Unquoted, that command
// line is not parseable by Windows either, so honouring the quotes is not indulgence of
// sloppy input -- it is the only spelling that works.
func cutQuoted(field string) (quoted, rest string, ok bool) {
	if !strings.HasPrefix(field, `"`) {
		return "", "", false
	}
	end := strings.IndexByte(field[1:], '"')
	if end < 0 {
		return "", "", false
	}
	return field[1 : end+1], field[end+2:], true
}

// splitCommandFields splits an embedded argument tail into arguments, keeping a quoted span
// together as one argument. ok is false when the quoting cannot be resolved, which is the
// caller's signal to report no arguments at all.
//
// strings.Fields was doing this before, and it splits on whitespace wherever it appears,
// including inside quotes. Two things went wrong with that, and the first is the reason this
// exists. `npx --token "opaque secret value" real-package` became
// ["--token", `"opaque`, "secret", `value"`, "real-package"]: redactArgs redacts the token's
// value by looking back at the option before it, so it redacted `"opaque` and left `secret`
// standing as its own argument -- which then passed looksLikePackageSpec and was reported as
// package_name. A fragment of a credential became the inventory's idea of what was
// installed. The second is milder and the same shape: `--out "a b c" real-package` reported
// package_name=b, an interior word of an ordinary option's value.
//
// A quoted span becomes one argument, so redactArgs redacts all of it and
// looksLikePackageSpec rejects it for holding whitespace.
//
// Backslash handling is decided by goos, because the same byte means opposite things on the
// two platforms. On Windows it separates path components -- this field routinely holds
// `C:\Users\x\tool.exe` -- and treating it as an escape would corrupt every one of them. On
// POSIX it escapes the next character, and not honouring that did more than lose a row:
// `npx --token opaque\ secret\ finalPiece real-package` split into four tokens, redactArgs
// covered only the first, and `finalPiece` -- the tail of a credential -- passed the package
// grammar and was reported as package_name. Escaped whitespace is the same leak the quoted
// form had, spelled differently.
func splitCommandFields(goos, tail string) ([]string, bool) {
	escapes := goos != "windows"
	var (
		out     []string
		current strings.Builder
		quote   rune
		open    bool
	)
	escaped := false
	for _, r := range tail {
		if escaped {
			// Inside double quotes POSIX escapes only five characters; before anything
			// else the backslash is itself literal and both bytes survive. Dropping it
			// unconditionally turned `"foo\bar"` into `foobar`, which the package grammar
			// accepts -- so a value a shell would have passed through as `foo\bar`, and
			// which no grammar would have accepted, was reported as the configured
			// package. Outside quotes the escape applies to any character, which is what
			// makes `opaque\ secret` one argument.
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", r) {
				current.WriteRune('\\')
			}
			current.WriteRune(r)
			open = true
			escaped = false
			continue
		}
		switch {
		case escapes && r == '\\' && quote != '\'':
			// Inside single quotes a backslash is literal even on POSIX; everywhere else
			// it introduces the next character.
			escaped = true
			open = true
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
		case r == '"' || r == '\'':
			// A quote starts a span wherever it appears, including mid-argument, so
			// --flag="a b" is one argument rather than two.
			quote = r
			open = true
		case unicode.IsSpace(r):
			if open || current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
				open = false
			}
		default:
			current.WriteRune(r)
			open = true
		}
	}
	if escaped {
		// A trailing backslash with nothing to escape. In a shell this continues the line;
		// here there is no next line, so the field is as unparseable as an open quote.
		return nil, false
	}
	if quote != 0 {
		// An unterminated quote. Where the argument ends is unknowable, so every boundary
		// after it is a guess, and a guess here is what puts part of a secret in a column.
		return nil, false
	}
	if open || current.Len() > 0 {
		out = append(out, current.String())
	}
	return out, true
}

// cutWhitespace splits a field at its first run of whitespace.
func cutWhitespace(field string) (head, tail string) {
	i := strings.IndexFunc(field, unicode.IsSpace)
	if i < 0 {
		return field, ""
	}
	return field[:i], field[i:]
}

// isRootedPath reports whether s begins at a filesystem root.
//
// filepath.IsAbs cannot be used: it answers for the running platform, and the entire reason
// goos is threaded through this file is that the Windows rules have to be reachable from a
// test on a Mac, and the POSIX rules from a test on Windows.
func isRootedPath(goos, s string) bool {
	if s == "" {
		return false
	}
	if goos != "windows" {
		return s[0] == '/'
	}
	// A leading separator is rooted on the current drive; two of them is a UNC path.
	if s[0] == '\\' || s[0] == '/' {
		return true
	}
	// Drive-qualified: letter, colon, separator. `C:x` is relative to the current directory
	// on drive C and is not a root.
	return len(s) >= 3 && isDriveLetter(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}

func isDriveLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// pathSeparators is deliberately not `/\` everywhere. A backslash is a legal character in a
// POSIX filename, so treating it as a separator there would report an executable genuinely
// named `foo\uvx` as `uvx` -- a confident wrong answer about what is running, which is worse
// than the Windows paths the change was meant to fix.
func pathSeparators(goos string) string {
	if goos == "windows" {
		return `/\`
	}
	return "/"
}

// executableNameFor reduces a resolved executable path to its filename.
//
// command_basename never contains whitespace. That is the column's contract, and it is
// absolute: a value with a space in it is indistinguishable from argument text by any rule
// this file has found, so an empty result is reported instead.
//
// Two inputs reach it. One is malformed -- whitespace survived a split that claimed the
// field was a path, so it was not the path it claimed to be. The other is legitimate and
// under-reported: an executable whose own filename contains a space, `C:\Tools\My
// Server.exe`. Naming it would mean letting whitespace into the column for every input,
// including the malformed ones, so it is reported as unknown and source_path is how an
// operator goes and looks.
func executableNameFor(goos, exe string) string {
	if i := strings.LastIndexAny(exe, pathSeparators(goos)); i >= 0 {
		exe = exe[i+1:]
	}
	if containsWhitespace(exe) {
		return ""
	}
	return exe
}

// commandBasename reports the launcher's filename for the command_basename column.
func commandBasename(cmd string, argsPresent bool) string {
	return commandBasenameFor(runtime.GOOS, cmd, argsPresent)
}

func commandBasenameFor(goos, cmd string, argsPresent bool) string {
	exe, _ := commandFieldsFor(goos, cmd, argsPresent)
	return executableNameFor(goos, exe)
}

// windowsExecutableSuffixes are stripped before a launcher name is matched against a known
// package manager. Windows resolves `npx` on PATH to `npx.cmd`, and a config naming the
// resolved file rather than the bare command is both legal and common.
var windowsExecutableSuffixes = []string{".exe", ".cmd", ".bat", ".com"}

// launcherName normalises a resolved executable path for matching against known launcher
// names.
//
// On Windows the executable suffix is removed and the name is lowercased, because `npx`,
// `npx.cmd` and `NPX.CMD` are one launcher and only the first would match a switch case.
// Elsewhere the filename is already the name. The unnormalised filename is what
// command_basename reports; this form is only for deciding identity.
func launcherName(exe string) string {
	return launcherNameFor(runtime.GOOS, exe)
}

func launcherNameFor(goos, exe string) string {
	name := executableNameFor(goos, exe)
	if goos != "windows" {
		return name
	}
	lower := strings.ToLower(name)
	for _, suffix := range windowsExecutableSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return strings.TrimSuffix(lower, suffix)
		}
	}
	return lower
}
