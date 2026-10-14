package mcp_servers

import (
	"net/url"
	"regexp"
	"strings"
)

// shellVarRe matches unresolved shell expansions such as ${HOME}, $HOME, %APPDATA%.
// If a candidate package_name or requested_spec contains one of these, identity is
// considered unreliable and the inferred fields are cleared so we don't emit garbage.
var shellVarRe = regexp.MustCompile(`\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z0-9_]+%`)

// inferIdentity inspects a Server's Command+Args and fills in PackageManager,
// PackageName, RequestedSpec, and Version where possible. It also picks the transport
// when the input doesn't tell us directly. Designed to be allocation-light: it
// does not modify Args.
func inferIdentity(s *Server) {
	if s.Transport == "" {
		switch {
		case s.URL != "":
			s.Transport = guessRemoteTransport(s.URL, s.Args)
		case s.Command != "":
			s.Transport = "stdio"
		default:
			s.Transport = "unknown"
		}
	}

	if s.Transport != "stdio" {
		if s.URL != "" {
			s.PackageManager = "mcp-remote"
			// From the *validated* endpoint, not from the sanitized string. sanitizeRemoteURL
			// drops everything but scheme and host, which is why s.URL was considered safe
			// here -- but a host is user-controlled through DNS, so `aws.AKIA....example.com`
			// satisfied it, and requested_spec inherited no grammar of its own. Routing both
			// columns through validatedEndpoint means url_endpoint's grammar covers this one
			// too, rather than two columns carrying the same value under different rules.
			s.RequestedSpec = validatedEndpoint(s.URL)
			s.Confidence = "high"
		} else {
			// A remote transport with no endpoint, e.g. {"type": "http"} and nothing else.
			// There is nothing to identify, but the row still has to declare a confidence:
			// the column's contract is high, medium or low, and an empty value silently
			// drops out of every query that filters on it.
			s.Confidence = "low"
		}
		return
	}

	// commandFields resolves the two shapes a `command` field takes: an executable path, or
	// an invocation with its arguments embedded, which some configs (e.g. Cursor) write as
	// {"command": "uvx some-pkg@latest"} with no args array. The original fields are not
	// mutated; they are still surfaced verbatim to the operator.
	exe, embedded := commandFields(s.Command, len(s.Args) > 0)
	argTok := s.Args
	if len(embedded) > 0 {
		// Redacted here because these arguments never passed through materialize, which is
		// where the declared args array gets the same treatment. Without it the two forms
		// of the same configuration behaved differently: `{"args": ["--token", "SECRET",
		// "pkg"]}` had SECRET replaced before inference and reported package_name=pkg,
		// while {"command": "npx --token SECRET pkg"} handed SECRET to the identity scanner
		// as the first package-shaped positional and copied it into package_name and
		// requested_spec. An opaque secret is exactly what the final redactor cannot
		// recognise, so it reached the row intact.
		argTok = redactArgs(embedded)
	}
	// launcherName, not the plain filename: on Windows `npx` resolves to `npx.cmd`, and a
	// config naming the resolved file is legal and common.
	cmd := launcherName(exe)
	if identify, known := launcherIdentity[cmd]; known {
		identify(s, argTok)
	}

	// Sanity: if identity contains an unresolved shell variable, clear the fields,
	// we'd otherwise emit nonsense like "${MCP_HOME}/bin/server".
	if shellVarRe.MatchString(s.RequestedSpec) || shellVarRe.MatchString(s.PackageName) {
		s.RequestedSpec = ""
		s.PackageName = ""
		s.PinnedVersion = ""
		s.Confidence = "low"
		return
	}

	switch {
	case s.PackageName != "" && s.PinnedVersion != "":
		s.Confidence = "high"
	case s.PackageName != "":
		s.Confidence = "medium"
	default:
		s.Confidence = "low"
	}
}

// noteWarning records a finding without displacing one already present.
//
// Identity inference runs last, after the file has been parsed and the row materialized, so
// anything already here came from a stage that knew more about the entry than this one can:
// an environment variable name that is not an identifier, or an HTTP header holding the
// credential itself rather than the name of the variable that holds it. Those name something
// in the file an administrator has to go and change. Both sites below assigned over them
// unconditionally, replacing that with warnUnknownLauncherOption -- which says only that this
// table could not read a command line -- and the remediation went with it.
//
// The row also stops describing itself. scan_complete is computed from the warning one
// statement before inference runs, so the flag reflects the warning that was erased while the
// column reports the one that replaced it; every code reachable here today is descriptive, so
// that inconsistency is latent rather than observed, and it is latent only by coincidence.
//
// A row carries one warning, so the choice is which of the two survives, and it is the
// earlier and more specific one.
func (s *Server) noteWarning(w warning) {
	if s.Warning.empty() {
		s.Warning = w
	}
}

// launcherIdentity is the one list of launchers this table understands. It dispatches
// identity inference, and its keys are the names commandFieldsFor treats as launchers while
// deciding whether a `command` field is a path or an invocation.
//
// One table rather than a switch beside a parallel set, because the two have to agree and
// nothing in the compiler would have said otherwise. Membership is what lets the splitter
// read `/usr/bin/node src/server.js` as an invocation rather than as one path containing a
// space; a launcher dispatched here but absent from the set would have had that field read
// as a path, reporting the argument's filename -- "server.js" -- as the launcher.
var launcherIdentity = map[string]func(s *Server, args []string){
	"npx": func(s *Server, args []string) {
		s.PackageManager = "npx"
		cand, ver, unknown := npxIdentity(args)
		if unknown {
			s.noteWarning(warning{Code: warnUnknownLauncherOption})
		}
		if looksLikePackageSpec(cand) {
			s.RequestedSpec = cand
			s.PackageName, _ = splitNPMSpec(cand)
			s.PinnedVersion = ver
		}
	},
	"bunx": func(s *Server, args []string) {
		s.PackageManager = "bunx"
		candidate, unknown := firstPositional(args)
		assignIfClean(s, candidate, unknown, splitNPMSpec)
	},
	"uvx": func(s *Server, args []string) {
		s.PackageManager = "uvx"
		candidate, unknown := uvxIdentity(args)
		assignIfClean(s, candidate, unknown, splitPyPISpec)
	},
	"uv": func(s *Server, args []string) {
		s.PackageManager = "uv"
		candidate, unknown := uvRunIdentity(args)
		assignIfClean(s, candidate, unknown, splitPyPISpec)
	},
	"pipx": func(s *Server, args []string) {
		s.PackageManager = "pipx"
		candidate, unknown := pipxIdentity(args)
		assignIfClean(s, candidate, unknown, splitPyPISpec)
	},
	"docker": dockerIdentity,
	"podman": dockerIdentity,
	// python is the one launcher that claims no package manager unless its arguments say
	// what is being run: `python` alone is a script host, not a package installer.
	"python":  pythonIdentity,
	"python3": pythonIdentity,
	// node, deno and bun run a local script or binary rather than fetching a package, so
	// the launcher is the whole of the identity they can support.
	"node": plainLauncher("node"),
	"deno": plainLauncher("deno"),
	"bun":  plainLauncher("bun"),
}

// assignIfClean sets RequestedSpec only if the candidate passes looksLikePackageSpec,
// otherwise we'd leak URL credentials, file paths, etc. that the launcher happens to accept
// as positional args. PackageName is set from the split result, which already rejects bad
// shapes.
// unknown is threaded in rather than inferred, because the two reasons an identity comes out
// empty are indistinguishable from the result: a candidate that is not package-shaped means
// the launcher was not asked to install a registry package, which is ordinary, and an
// unrecognised option means this table could not tell, which is a finding.
func assignIfClean(s *Server, cand string, unknown bool, splitter func(string) (string, string)) {
	if unknown {
		s.noteWarning(warning{Code: warnUnknownLauncherOption})
	}
	if !looksLikePackageSpec(cand) {
		return
	}
	s.RequestedSpec = cand
	name, ver := splitter(cand)
	s.PackageName = name
	s.PinnedVersion = ver
}

func dockerIdentity(s *Server, args []string) {
	s.PackageManager = "docker"
	// Docker refs aren't package specs in the npm/pypi sense; splitDockerRef returns
	// (name, version) for valid refs and "", "" otherwise. We accept whatever it produces.
	//
	// Validated against the reference grammar before anything is assigned. The old guard
	// only excluded "://", so user:secret@reg/img was emitted verbatim as both
	// requested_spec and package_name.
	if ref := dockerRunIdentity(args); dockerRefRe.MatchString(ref) {
		s.RequestedSpec = ref
		s.PackageName, s.PinnedVersion = splitDockerRef(ref)
	}
}

func pythonIdentity(s *Server, args []string) {
	if mod := pythonModule(args); mod != "" && looksLikePackageSpec(mod) {
		s.PackageManager = "python"
		s.PackageName = mod
		s.RequestedSpec = "python:" + mod
	}
}

// plainLauncher reports the launcher as the package manager and infers nothing else.
func plainLauncher(name string) func(*Server, []string) {
	return func(s *Server, _ []string) { s.PackageManager = name }
}

// guessRemoteTransport returns "sse" if the args or URL hint at server-sent events,
// otherwise "http". MCP currently uses Streamable HTTP and SSE.
//
// The URL is parsed and only whole path segments are compared. Matching the substring "/sse"
// anywhere classified /sse-notify, /sse2 and even a query string containing /sse as SSE, and
// that value is emitted as the server's transport.
func guessRemoteTransport(u string, args []string) string {
	parsed, err := url.Parse(u)
	// Only an http or https endpoint may be guessed at. Falling through to "http" for
	// anything else reported `wss://example.test/mcp` as transport=http, and a URL with no
	// recoverable host as transport=http with no endpoint at all -- a row claiming a
	// protocol its own config never named, which is what normalizeTransport was changed to
	// stop doing for an explicitly declared unknown transport. The same answer is owed when
	// the scheme rather than the type field is the thing this table does not support.
	//
	// "unknown" rather than empty: it is one of the four documented values of the column,
	// and an empty transport drops out of every query that filters on it.
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "unknown"
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		switch strings.ToLower(segment) {
		case "sse", "events":
			return "sse"
		}
	}
	for _, a := range args {
		if strings.EqualFold(a, "--transport=sse") || strings.EqualFold(a, "sse") {
			return "sse"
		}
	}
	return "http"
}

// runnerValueFlags are options whose *next* argument is a value rather than the package. A
// scan that does not know this attributes the value instead: `uvx --python 3.12 real-server`
// reported package_name=3.12 at medium confidence, which in an inventory is worse than an
// empty answer, because nothing marks it as wrong.
//
// Only options that take a separate value need listing; the `--flag=value` form carries its
// own value and is skipped by the dash prefix.
//
// Two rules govern what may be added here, both learned the hard way.
//
// An option whose value IS the package must never be listed. `uvx --from httpx httpx-cli`
// names httpx as the package and httpx-cli as the command to run inside it, so listing
// `--from` here would skip the package and report the command. Both launchers read it
// explicitly instead -- uvxIdentity and uvRunIdentity -- and this map has to stay out of
// their way. Leaving it to the generic positional scan was the earlier arrangement and it
// was wrong: it worked only while the value happened to be package-shaped, and a Git spec
// is not, so the scan walked past it and reported the command.
//
// A boolean must never be listed either, because it would consume the real package and
// empty the identity. `--quiet`/`-q` and `--verbose`/`-v` are the trap: uv documents them
// with an argument-looking `<COLOR_CHOICE>`-style signature in some renderings, and they are
// counters that take nothing.
//
// KNOWN GAP: one map is shared by npx, uvx and pipx,
// which do not share a grammar, and no launcher's grammar is modelled completely. Docker is
// not among them: dockerRunIdentity enumerates the booleans instead and assumes everything
// else consumes a value, which is the inversion that made its scan stable.
// The decision this used to defer has been made: an unrecognised option fails closed.
//
// The gap was that all three scanners treated an unlisted flag as taking no value, so
// `npx -y --pat <secret> pkg` made the secret the first operand and copied it into
// package_name and requested_spec. An opaque credential is exactly what the final redactor
// cannot recognise, so it reached the row intact. The two ways out were per-launcher arity --
// correct, large, and permanently behind whatever options npm and uv added last month -- or
// treating an unrecognised option as disqualifying.
//
// The second is now what happens: sawUnknownOption is set, the scan returns "", and the row
// reports confidence=low with an empty identity triple and warnUnknownLauncherOption saying
// why. The cost is real and is the point of recording it here: a legitimate unlisted boolean
// -- some new `--quiet` -- now empties the identity for that row rather than being walked
// past. That is a missing answer where the alternative is a confidently wrong one, and for a
// column that may be a credential the missing answer is the only acceptable direction.
//
// dockerRunIdentity is unaffected and needed no change. It already inverts this, enumerating
// the booleans and assuming everything else consumes a value, which is why its scan was the
// stable one.
var runnerValueFlags = map[string]struct{}{
	"--python": {}, "-p": {}, "--with": {}, "--index": {}, "--index-url": {},
	"--extra-index-url": {}, "--find-links": {}, "--constraint": {}, "-c": {},
	"--registry": {}, "--cache-dir": {}, "--refresh-package": {}, "--prerelease": {},
	"--resolution": {}, "--exclude-newer": {}, "--config-file": {}, "--directory": {},
	"--project": {}, "--package": {},
	// Added from the uv CLI reference after `uvx --color always real-server` was reported
	// as package_name=always. Short spellings included because the separated form accepts
	// either.
	"--color": {}, "--index-strategy": {}, "--keyring-provider": {}, "--link-mode": {},
	"--python-platform": {}, "--with-editable": {}, "--with-requirements": {}, "-w": {},
	"--default-index": {}, "-i": {}, "-f": {}, "--config-setting": {},
	"--config-settings": {}, "-C": {}, "--no-binary-package": {},
	"--prerelease-package": {}, "--reinstall-package": {}, "--upgrade-package": {},
	"-P": {}, "--upgrade-group": {}, "--allow-insecure-host": {}, "--trusted-host": {},
	// pipx. This was in launcherBooleanFlags, so every scanner assumed it consumed nothing
	// and read the arguments meant for pip as the launcher's first operand:
	// `pipx run --pip-args <value> real-package` reported the value whenever it was
	// name-shaped, which an opaque credential is. pipx documents --pip-args as taking the
	// arguments to hand to pip, and those arguments are where an authenticated index URL or
	// a token is passed, so the one token this option is most likely to carry is the one the
	// final redactor cannot recognise. It reached package_name and requested_spec verbatim.
	"--pip-args": {},
}

// firstPositional returns the launcher's first operand, and only if it is package-shaped.
// Arguments consumed as a value by the option before them are skipped and are not operands.
//
// It does not look past that operand. An earlier version did, on the reasoning that a
// credential URL appearing before the real package should not permanently mask inference --
// but the example it cited, `--registry https://u:p@h pkg`, is handled by arity: --registry
// is in runnerValueFlags, so its value is consumed and never reaches the grammar check. What
// walking past actually did was cross the launcher boundary. `npx ./server.js real-package`
// reported real-package, which is an argument to the script npx ran, not something npx
// installed -- the same mistake as reading the launched program's --package, --from or -m.
// The first operand is the package or there is no package.
//
// The launchers that take a subcommand need the same scan starting one token later, so there
// is one implementation and this names the no-subcommand case. Two byte-identical copies of
// the loop lived here before, which is one copy too many for a scan that decides what lands
// in package_name: a guard added to either would have protected only its own callers.
func firstPositional(args []string) (string, bool) {
	return firstOperandAfter(args, "")
}

func npxIdentity(args []string) (spec, ver string, unknown bool) {
	// Honor `--package <name>` and `--package=<name>` explicitly when present.
	//
	// The scan covers every argument including the last. Only the two-token form has to look
	// ahead, so only that branch is guarded; bounding the whole loop at len(args)-1 meant an
	// inline `--package=pkg@1.2.3` in final position was never seen.
	//
	// Bounded at the first positional, because past that point the options belong to the
	// program npx launched rather than to npx. `npx real-package --package evil` reported
	// evil: the server's own --package option, read as though npx had been asked to install
	// it. Whatever a launched MCP server chooses to call its flags is outside this table's
	// control, so the scan has to stop where the launcher's grammar does.
	if value, found := launcherOptionValue(args, npxGrammar, npxPackageFlags); found {
		spec = value
		_, ver = splitNPMSpec(spec)
		return
	}
	// The full list, not the option prefix: the package npx runs *is* the first positional,
	// so the fallback has to see past where the option walk stops.
	spec, unknown = firstPositional(args)
	_, ver = splitNPMSpec(spec)
	return
}

// uvxIdentity resolves `uvx`, where --from names the package and the trailing token names
// the command inside it.
//
// firstPositional was doing this, and it was right only while the package happened to be
// package-shaped: `uvx --from httpx httpx-cli` reported httpx because the option was skipped
// as a flag and its value was simply the first positional. Give --from a value the grammar
// rejects -- `uvx --from git+https://github.com/acme/mcp-suite.git actual-server`, the
// Git-backed form Astral documents -- and the scan walked past it and reported
// actual-server, the command the package exports, as the package itself.
//
// When --from is present it *is* the identity. If its value cannot be represented, the
// identity is empty: assignIfClean rejects it and nothing after it is consulted.
func uvxIdentity(args []string) (string, bool) {
	if value, found := launcherOptionValue(args, uvGrammar, uvFromFlag); found {
		return value, false
	}
	return firstPositional(args)
}

// uvRunIdentity resolves `uv run --from <pkg>` and `uv tool run <pkg>`.
//
// Both halves used to cross the boundary. The --from search now stops at the first operand,
// and the tool-run fallback no longer rescans the whole vector for the words: it searched
// for any adjacent `tool run` anywhere, so `uv run actual-command tool run fake-package`
// found the pair inside the launched command's own arguments and reported fake-package. The
// other direction was broken too -- subcommands were recognised only at argument zero, so
// `uv --color always run --from real-package command` lost the identity to a global option.
func uvRunIdentity(args []string) (string, bool) {
	rest, toolRun, found := uvSubcommandArgs(args)
	if !found {
		// Either there is no run subcommand, or an unrecognised global option before it
		// may have consumed the subcommand word. uvSubcommandArgs collapses those into one
		// answer, and the second is a refusal rather than an absence -- reported as such,
		// because the whole point of the fail-closed change is that an undecidable scan
		// says so instead of returning a confident nothing.
		_, unknown := skipLeadingOptions(args, uvGrammar)
		return "", unknown
	}
	if value, ok := launcherOptionValue(rest, uvGrammar, uvFromFlag); ok {
		return value, false
	}
	if toolRun {
		// `uv tool run <pkg>`: the package is the first operand of the subcommand.
		return firstPositional(rest)
	}
	// Plain `uv run <cmd>` runs a command from the project environment. That names no
	// package, and reporting the command as one is the confusion this function exists to
	// avoid.
	return "", false
}

// uvSubcommandArgs skips uv's global options and the one top-level subcommand path,
// returning what follows it. found is false when neither `run` nor `tool run` is reached
// before the first operand, so a later occurrence among the launched command's arguments is
// never mistaken for the subcommand.
func uvSubcommandArgs(args []string) (rest []string, toolRun, found bool) {
	index, unknown := skipLeadingOptions(args, uvGrammar)
	if unknown {
		// An unrecognised global option before the subcommand may have consumed the
		// subcommand word itself, so `run` appearing at this index proves nothing. Reporting
		// not-found empties the identity, which is the fail-closed direction the KNOWN GAP
		// above now resolves to.
		return nil, false, false
	}
	switch {
	case index+1 < len(args) && args[index] == "tool" && args[index+1] == "run":
		return args[index+2:], true, true
	case index < len(args) && args[index] == "run":
		return args[index+1:], false, true
	}
	return nil, false, false
}

// skipLeadingOptions returns the index of the first argument that is not one of the
// launcher's own options, consuming the value of any option that takes one.
//
// unknown reports that an option this table does not recognise was seen, which makes the
// operand that follows unreliable: an unrecognised option may or may not consume it.
func skipLeadingOptions(args []string, grammar launcherGrammar) (index int, unknown bool) {
	for index < len(args) {
		argument := args[index]
		if argument == "--" || !strings.HasPrefix(argument, "-") {
			return index, unknown
		}
		name, _, hasInline := strings.Cut(argument, "=")
		if hasInline {
			// The inline form carries its own value and consumes nothing, so an
			// unrecognised one is harmless: whatever follows is still an operand.
			index++
			continue
		}
		_, takesValue := grammar.valueFlags[name]
		if !takesValue {
			_, takesValue = runnerValueFlags[name]
		}
		if takesValue {
			index += 2
			continue
		}
		if !knownLauncherOption(name) {
			unknown = true
		}
		index++
	}
	return index, unknown
}

// knownLauncherOption reports whether this table knows what a separated option does with the
// token after it. An option it does not know is what makes the scan fail closed.
//
// Four sources, and each is a different kind of knowledge:
//
//   - launcherBooleanFlags: takes no value, so the next token is an operand.
//   - runnerValueFlags: takes a value, so the next token is not.
//   - launcherPackageFlags: takes a value and that value IS the package, which is why these
//     must not be in runnerValueFlags -- consuming `--from httpx` would report the command
//     `httpx-cli` as the package instead of the package `httpx`.
//   - isSecretFlagName: the option's own name announces that it carries a value. Arity is
//     known here without a list, which is the point: runnerValueFlags can never be complete,
//     and a credential-named option is exactly the one whose value must not be read as an
//     operand. firstOperandAfter and launcherOptionValue both consume those values; this
//     stops the same options being counted as unknown and emptying the identity they were
//     about to protect.
//
// Being explicit about all four matters because the fail-closed behaviour fires on anything
// absent from them, and an option like `-y` appears in essentially every real MCP config for
// a scoped package. Leaving one out makes the refusal fire on the common case rather than on
// the unusual one.
func knownLauncherOption(name string) bool {
	if _, ok := launcherBooleanFlags[name]; ok {
		return true
	}
	if _, ok := runnerValueFlags[name]; ok {
		return true
	}
	if _, ok := launcherPackageFlags[name]; ok {
		return true
	}
	return isSecretFlagName(name)
}

// launcherPackageFlags are the options whose value names the package to install.
//
// The union of the three per-launcher sets below, which exist separately because each
// scanner asks for its own. This set answers a different question -- "is this option known
// at all" -- and keeping it derived from the same names means a new one cannot be known to
// one and unknown to the other.
var launcherPackageFlags = map[string]struct{}{
	"--package": {}, "-p": {}, "--from": {}, "--spec": {},
}

// launcherBooleanFlags are the value-less options of npx, uvx, uv and pipx.
//
// Shared the same way runnerValueFlags is, and with the same caveat: these launchers do not
// share a grammar, and an option that is boolean for one and value-taking for another would
// be wrong here. What this comment used to claim is that the direction of error is the safe
// one. It is the opposite: a value-taking option listed here does not empty the identity, it
// hands the option's value to the operand scan and publishes it as the package. --pip-args
// was listed and pipx documents it as taking a value, which is the defect that moved it to
// runnerValueFlags.
//
// Every remaining entry was re-checked against its own launcher's reference for the same
// class of error. npm's -y, --yes, --no, --no-install, the cache-preference switches and -q
// take nothing -- -q is a --loglevel shorthand, so it carries its own value rather than
// consuming the next token. uv's entries are counters and negations, and where uv has a
// value-taking relative it is a separately spelled option rather than the same name with an
// argument: --refresh against --refresh-package, --no-binary against --no-binary-package,
// --no-build against --no-build-package, --no-cache against --cache-dir. pipx leaves
// --force, --include-deps, --system-site-packages and --no-cache-dir, none of which takes a
// value.
//
// An option whose arity is not certain belongs in runnerValueFlags rather than here, because
// consuming one token too many yields an empty identity and a warning, while consuming one
// too few can publish a credential as a package name.
var launcherBooleanFlags = map[string]struct{}{
	// npx
	"-y": {}, "--yes": {}, "--no": {}, "--no-install": {}, "--prefer-online": {},
	"--prefer-offline": {}, "--offline": {}, "--ignore-existing": {}, "-q": {},
	// uv / uvx
	"--quiet": {}, "--verbose": {}, "-v": {}, "--native-tls": {}, "--no-cache": {},
	"-n": {}, "--no-progress": {}, "--offline-mode": {}, "--isolated": {},
	"--no-config": {}, "--preview": {}, "--system": {}, "--no-managed-python": {},
	"--no-python-downloads": {}, "--help": {}, "-h": {}, "--version": {}, "-V": {},
	"--frozen": {}, "--locked": {}, "--no-sync": {}, "--refresh": {}, "--upgrade": {},
	"-U": {}, "--reinstall": {}, "--compile-bytecode": {}, "--no-build": {},
	"--no-binary": {}, "--no-build-isolation": {}, "--no-sources": {}, "--no-dev": {},
	"--all-extras": {}, "--no-editable": {}, "--exact": {}, "--inexact": {},
	// pipx
	"--force": {}, "--include-deps": {}, "--system-site-packages": {},
	"--no-cache-dir": {},
}

func pipxIdentity(args []string) (string, bool) {
	// Bounded like the others: `pipx run server --spec evil` names the server's option.
	if value, found := launcherOptionValue(args, pipxGrammar, pipxSpecFlag); found {
		return value, false
	}
	// `pipx run --python 3.12 actual-server` returned 3.12: the scan skipped flags but not
	// the values they consume, and 3.12 is name-shaped so no grammar rejects it either.
	return firstOperandAfter(args, "run")
}

// firstOperandAfter returns the first positional argument following subcommand, skipping any
// argument consumed as a value by the option before it, and requiring the result to be
// package-shaped.
//
// One scanner for the launchers that take a subcommand. pipx and uv each had their own
// partial version before: pipx skipped flags but not their values, and uv indexed blindly to
// run+2. Arity comes from runnerValueFlags, which they share. Docker went the other way and
// kept its own parser -- a hand-written list of value-taking options needed an addition every
// time one produced a wrong image, so dockerRunIdentity enumerates the booleans instead.
// unknown reports that the scan declined because an option this table does not recognise
// appeared before the operand, as distinct from declining because the operand was not
// package-shaped. The two look identical in the result -- an empty identity -- and call for
// different rows: one says "this launcher was not asked to install a package", which is
// ordinary, and the other says "this table could not tell", which is a finding.
func firstOperandAfter(args []string, subcommand string) (operand string, unknown bool) {
	started := subcommand == ""
	sawUnknownOption := false
	for i, argument := range args {
		if !started {
			if argument == subcommand {
				started = true
			}
			continue
		}
		if strings.HasPrefix(argument, "-") {
			// An option this table does not recognise, in the separated form, may consume
			// the token after it. That token is then not an operand, and reading it as one
			// is how `npx -y --pat <secret> pkg` reported the secret as the package. Noted
			// rather than acted on here, because the loop has to reach the operand before
			// there is anything to refuse.
			name, _, hasInline := strings.Cut(argument, "=")
			if !hasInline && argument != "--" {
				if _, takesValue := runnerValueFlags[name]; !takesValue {
					if !knownLauncherOption(name) {
						sawUnknownOption = true
					}
				}
			}
			continue
		}
		if i > 0 {
			if _, consumed := runnerValueFlags[args[i-1]]; consumed {
				continue
			}
			// A value belonging to an option whose *name* says it carries a credential.
			// runnerValueFlags cannot be complete -- every launcher keeps adding options,
			// and the entries here were each added after a wrong package name was seen --
			// so the arity list alone lets `uvx --auth-token opaquevalue real-server`
			// report the token as the package. An opaque value is exactly what redactSecret
			// cannot recognise on its way out, and package_name is emitted verbatim.
			//
			// Skipping the whole dangerous subset needs no arity knowledge: the option
			// named it. redactArgs already refuses the same values for the same reason.
			if isSecretFlagName(args[i-1]) {
				continue
			}
		}
		// An unrecognised option was seen before this token, so whether this is an operand
		// or that option's value cannot be decided. Fail closed: an empty identity at low
		// confidence is honest, and a credential reported as a package name is not.
		if sawUnknownOption {
			return "", true
		}
		// The first operand decides it. Not package-shaped -- a URL, a script path, a
		// tarball -- means this launcher was not asked to install a registry package,
		// and everything after it belongs to whatever it was asked to run.
		if looksLikePackageSpec(argument) {
			return argument, false
		}
		return "", false
	}
	// Ran out of arguments without reaching an operand. If an unrecognised option was seen
	// on the way, that is still why nothing was identified.
	return "", sawUnknownOption
}

// dockerRunIdentity returns the image reference from a `docker run` invocation.
//
// Option arity is decided by listing the *boolean* options and assuming everything else takes
// a value. That is the inversion of the obvious approach and the reason it works: docker run
// has dozens of value-bearing options and the list of them kept needing additions, each found
// only when it produced a wrong package name -- --pull, then --cap-add, then --publish. The
// boolean set is small, stable, and its members are the ones a reader can actually recall.
//
// Values that satisfy the image grammar are what made the previous approach fail silently
// rather than loudly: `--publish 8080:80` reads as a tagged reference, `--memory 512m` and
// `--dns 1.1.1.1` as one-component ones. No grammar distinguishes those from an image, because
// they are valid images.
//
// An unrecognised option is therefore assumed to consume its next token. That can swallow the
// real image and yield nothing, which is the intended direction of error: an empty identity at
// low confidence is honest, a confident wrong one is not.
func dockerRunIdentity(args []string) string {
	sawRun := false
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if !sawRun {
			if argument == "run" {
				sawRun = true
			}
			continue
		}
		if argument == "--" {
			// Everything after this is the image and the container's command.
			if i+1 < len(args) && dockerRefRe.MatchString(args[i+1]) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(argument, "-") {
			if strings.Contains(argument, "=") {
				continue // the inline form carries its own value
			}
			if _, isBoolean := dockerBooleanFlags[argument]; isBoolean {
				continue
			}
			// A handful of options take a value that can legitimately begin with a dash,
			// so for those the next token is consumed unconditionally.
			if _, negatable := dockerNegatableValueFlags[argument]; negatable {
				i++
				continue
			}
			// A grouped short-option cluster. `docker run -it image` is the most common
			// invocation of the lot, and "-it" is in neither flag table, so the generic rule
			// below consumed the image and returned nothing at low confidence.
			if consumesNext, recognised := dockerShortCluster(argument); recognised {
				if consumesNext && i+1 < len(args) {
					i++
				}
				continue
			}
			// Otherwise: assumed to consume the next token, but never when that token is
			// itself an option. A boolean missing from the list below would otherwise
			// swallow the following option and hand back *its* value as the image:
			// `docker run --sig-proxy --publish 8080:80 img` skipped --publish and returned
			// 8080:80. An option is not a value, so declining to consume one costs nothing
			// and repairs the whole chain.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		if dockerRefRe.MatchString(argument) {
			return argument
		}
		// A positional that is not reference-shaped means the arity assumptions and reality
		// have diverged. Stop, rather than keep looking and risk returning the container's
		// command as the image.
		return ""
	}
	return ""
}

// dockerShortCluster interprets a single-dash short-option group such as -it or -itv.
//
// Docker's flag parser (pflag) walks a cluster left to right: a boolean shorthand yields to
// the next character, while the first value-taking one takes the rest of the cluster as its
// value (-p8080:80) or, when it ends the cluster, the next token (-p 8080:80).
//
// recognised is false when the group holds a character that is not a known `docker run`
// shorthand, which leaves the caller's conservative consume-the-next-token default in charge
// rather than guessing. That keeps an unfamiliar cluster failing toward an empty identity.
func dockerShortCluster(argument string) (consumesNext, recognised bool) {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false, false
	}
	group := argument[1:]
	for index := 0; index < len(group); index++ {
		switch {
		case strings.IndexByte(dockerBooleanShorts, group[index]) >= 0:
			continue
		case strings.IndexByte(dockerValueShorts, group[index]) >= 0:
			return index == len(group)-1, true
		default:
			return false, false
		}
	}
	return false, true
}

// dockerBooleanShorts and dockerValueShorts are the single-character `docker run`
// shorthands, split by whether they take a value. Case matters: -P is --publish-all and
// takes none, while -p is --publish and takes one. Only shorthands belong here; the long
// forms stay in the maps below.
const (
	dockerBooleanShorts = "ditqP"
	dockerValueShorts   = "acehlmpuvw"
)

// dockerBooleanFlags are the `docker run` options that take no value. Everything else is
// assumed to consume its next argument.
//
// Enumerating these rather than their complement is what makes the scan stable: this set
// changes rarely, while the value-bearing set is large and grew three times during review.
var dockerBooleanFlags = map[string]struct{}{
	"-d": {}, "--detach": {},
	"-i": {}, "--interactive": {},
	"-t": {}, "--tty": {},
	"--rm": {}, "--privileged": {}, "--init": {}, "--read-only": {},
	"-q": {}, "--quiet": {}, "--no-healthcheck": {}, "--oom-kill-disable": {},
	"--publish-all": {}, "-P": {}, "--help": {}, "--disable-content-trust": {},
	// --sig-proxy is documented with a default of true and takes no value in the common
	// form. Omitting it is what produced the chained-option failure above.
	"--sig-proxy": {}, "--no-trunc": {},
}

// dockerNegatableValueFlags take a value that can begin with a dash, so the general rule of
// never consuming an option-looking token would leave their value unconsumed.
//
// --oom-score-adj accepts -1000 to 1000, and --pids-limit and --memory-swap use -1 for
// unlimited. Getting this wrong fails in both directions: classifying --oom-score-adj as
// boolean made `--oom-score-adj 100 myorg/s:1` report 100 as the image, and merely removing it
// from the boolean set left `--oom-score-adj -100 myorg/s:1` returning nothing, because -100
// was then read as an option that consumed the image.
var dockerNegatableValueFlags = map[string]struct{}{
	"--oom-score-adj": {}, "--pids-limit": {}, "--memory-swap": {}, "--kernel-memory": {},
	"--blkio-weight": {}, "--cpu-period": {}, "--cpu-quota": {},
}

// launcherGrammar is the little that has to be known about a launcher's command line to walk
// its own options without straying into the launched program's.
//
// An index into the argument list is not enough, which is how the first attempt at this went
// wrong: the caller rescanned the prefix without knowing which tokens had been consumed as
// values, so `python -c -m evilmod` reported evilmod -- the argument of -c, read a second
// time as though it were python's own -m. The walk has to be the thing that answers the
// question, not a boundary handed to something that asks it again.
type launcherGrammar struct {
	// subcommandPaths are the subcommand words that may precede the options, longest first
	// and matched only at the start, so a later occurrence is the operand it actually is.
	subcommandPaths [][]string
	// valueFlags take a separate value, consumed whatever it looks like -- including when
	// it begins with a dash, which is what `-c -m` needs.
	valueFlags map[string]struct{}
}

var (
	npxGrammar = launcherGrammar{}
	// No subcommandPaths: uv's top-level shape is parsed by uvSubcommandArgs, which has to
	// tell a subcommand in its own position from the same word among the launched
	// command's arguments. This grammar describes only what follows it.
	uvGrammar = launcherGrammar{
		valueFlags: map[string]struct{}{"--from": {}},
	}
	pipxGrammar = launcherGrammar{
		subcommandPaths: [][]string{{"run"}},
		valueFlags:      map[string]struct{}{"--spec": {}},
	}

	// pythonLongValueFlags are the interpreter's long options that take a separate value.
	// The short options cluster and are read character by character instead; see
	// pythonShortCluster.
	pythonLongValueFlags = map[string]struct{}{"--check-hash-based-pycs": {}}

	npxPackageFlags = map[string]struct{}{"--package": {}, "-p": {}}
	uvFromFlag      = map[string]struct{}{"--from": {}}
	pipxSpecFlag    = map[string]struct{}{"--spec": {}}
)

// launcherOptionValue walks a launcher's own options and returns the value assigned to the
// first option in want, stopping where the launcher's options stop.
//
// Every scanner in this file used to read the whole argument list, so an option belonging to
// the launched server was indistinguishable from one belonging to the launcher: an MCP
// server free to accept --package, --from or --spec had its argument reported as what was
// installed. Three things end the launcher's options, and each was a way through before it
// was handled -- a bare positional, `--`, and a value that happens to look like an option.
func launcherOptionValue(args []string, grammar launcherGrammar, want map[string]struct{}) (string, bool) {
	index := consumeSubcommands(args, grammar.subcommandPaths)
	for index < len(args) {
		argument := args[index]
		switch {
		case argument == "--":
			// Everything after this is an operand by definition.
			return "", false
		case strings.HasPrefix(argument, "-"):
			name, inlineValue, hasInline := strings.Cut(argument, "=")
			if _, wanted := want[name]; wanted {
				if hasInline {
					return inlineValue, true
				}
				if index+1 < len(args) {
					return args[index+1], true
				}
				return "", false
			}
			if hasInline {
				// The inline form carries its own value and consumes nothing.
				index++
				continue
			}
			_, takesValue := grammar.valueFlags[name]
			if !takesValue {
				_, takesValue = runnerValueFlags[name]
			}
			if takesValue {
				index += 2
				continue
			}
			// A credential-named option announces its own arity, so its value is consumed
			// with it. This read `index++`, treating the option as value-less, and the value
			// then reached the default branch below as a bare positional -- which ends the
			// walk, because a positional is where the launched program begins. So any such
			// option *before* the wanted one hid it completely:
			// `npx --auth-token <secret> --package real-pkg` never reached --package, and the
			// operand fallback skipped the real package as a consumed value, so the row came
			// back with no identity at all.
			//
			// Not a leak in either direction, since a value is not an option name and could
			// never have been returned as one -- but a lost identity, and inconsistent with
			// firstOperandAfter, which does skip these values. knownLauncherOption already
			// documents the arity as known from the name; this was the scanner not honouring
			// it.
			if isSecretFlagName(name) {
				index += 2
				continue
			}
			if !knownLauncherOption(name) {
				// An unrecognised separated option. The wanted option may lie past the
				// token it might consume, so the scan cannot be trusted to have reached
				// it -- and an option named like a credential is exactly the case where a
				// wrong answer is a leak. Stop rather than guess.
				return "", false
			}
			index++
		default:
			// A positional that is not a subcommand: the launched program begins here.
			return "", false
		}
	}
	return "", false
}

// consumeSubcommands returns how many leading arguments are subcommand words, matching the
// longest declared path. Only at the start, so a later occurrence of the same word is the
// operand it actually is.
func consumeSubcommands(args []string, paths [][]string) int {
	for _, path := range paths {
		if len(path) > len(args) {
			continue
		}
		matched := true
		for offset, word := range path {
			if args[offset] != word {
				matched = false
				break
			}
		}
		if matched {
			return len(path)
		}
	}
	return 0
}

// CPython's single-dash options cluster, and the cluster decides what the rest of the
// command line means. Verified against python3 3.9.6 rather than read off the grammar:
// `-um this`, `-umthis`, `-OOm this` and `-qIm this` all run the module, and
// `-ucprint(9) -m evilmod` prints 9 -- the -c command ran and `-m evilmod` was its argv.
const (
	// Options taking no argument. A cluster runs through these to whatever follows.
	//
	// -P is deliberately absent although current CPython accepts it: it arrived in 3.11,
	// and this table resolves no interpreter -- the launchers it knows are the
	// version-neutral names `python` and `python3`. On 3.9.6 `python3 -Pm this` exits with
	// "Unknown option: -P" and runs nothing, so accepting the letter asserts a module for
	// an invocation that never executed. Leaving it out costs the identity of a clustered
	// `-Pm` on 3.11 and newer, which is the empty answer this file prefers to a wrong one.
	// Modelling a 3.11 baseline instead would have to be a stated, tested decision.
	pythonBooleanShorts = "bBdEiIOqRsSuvx"
	// Options that print and exit, so nothing is run and nothing is installed.
	pythonTerminatingShorts = "hV?"
	// The four that take an argument -- c, m, W and X -- are named directly in the switch
	// below rather than listed here, because each one does something different with it and
	// a parallel list would be a second copy to keep in agreement for no gain.
)

// pythonClusterOutcome says what a short-option cluster leaves the caller to do.
type pythonClusterOutcome int

const (
	pythonClusterDone       pythonClusterOutcome = iota // booleans only; nothing consumed
	pythonClusterModule                                 // the module was attached to the cluster
	pythonClusterModuleNext                             // an -m ended the cluster: the module is next
	pythonClusterValueNext                              // a -W or -X ended it: its value is next
	pythonClusterStop                                   // no module can follow
)

// pythonShortCluster interprets one single-dash group, left to right, the way CPython's own
// parser does: a boolean letter yields to the next, and the first value-taking letter claims
// the rest of the cluster or the following token.
func pythonShortCluster(group string) (string, pythonClusterOutcome) {
	for position := 0; position < len(group); position++ {
		letter := group[position]
		rest := group[position+1:]
		switch {
		case strings.IndexByte(pythonBooleanShorts, letter) >= 0:
			continue
		case letter == 'm':
			if rest != "" {
				return rest, pythonClusterModule
			}
			return "", pythonClusterModuleNext
		case letter == 'c':
			// python is running a command string. Everything after it, including a later
			// -m, is that command's argv and python never reads it as an option.
			return "", pythonClusterStop
		case letter == 'W' || letter == 'X':
			if rest != "" {
				return "", pythonClusterDone
			}
			return "", pythonClusterValueNext
		case strings.IndexByte(pythonTerminatingShorts, letter) >= 0:
			return "", pythonClusterStop
		default:
			// A letter this does not model. Failing closed is the point: letting the scan
			// continue is how a cluster containing an unrecognised c-like option would let
			// a later -m manufacture an identity out of the command's own arguments.
			return "", pythonClusterStop
		}
	}
	return "", pythonClusterDone
}

// pythonModule returns the module named by -m, which python accepts only among its own
// options: everything after the module or script belongs to that program.
//
// Read here rather than through the generic option walk for two reasons, and the second was
// a false positive rather than a gap. CPython attaches a short option's argument to the
// option itself, so `-mhttp.server` is one token and went unreported. And it clusters them,
// so `-ucprint(9) -m evilmod` hid a -c inside a group this used to skip as a boolean: the
// scan continued and reported evilmod, the argv of the command python actually ran. A
// comment here claimed the parser failed toward an empty answer. For clusters it did not.
func pythonModule(args []string) string {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--" || argument == "-":
			// Both end the interpreter's options: past -- everything is a file name, and a
			// lone - selects stdin.
			return ""
		case !strings.HasPrefix(argument, "-"):
			// The script. Its arguments are its own.
			return ""
		case strings.HasPrefix(argument, "--"):
			// --check-hash-based-pycs is the only long option CPython documents that does
			// not end the run. Everything else prints and exits -- --help, --help-env,
			// --help-xoptions, --help-all, --version -- and an unrecognised one is an
			// error. Verified: `python3 --version -m this` prints the version and does not
			// run the module, and `--definitely-unknown` exits with "unknown option".
			// Treating them as harmless booleans and continuing let a later -m report a
			// module for a command that executed nothing, which is the same false identity
			// the cluster parser exists to prevent.
			name, _, hasInline := strings.Cut(argument, "=")
			if _, takesValue := pythonLongValueFlags[name]; takesValue {
				if !hasInline {
					index++
				}
				continue
			}
			return ""
		}
		module, outcome := pythonShortCluster(argument[1:])
		switch outcome {
		case pythonClusterModule:
			return module
		case pythonClusterModuleNext:
			if index+1 < len(args) {
				return args[index+1]
			}
			return ""
		case pythonClusterValueNext:
			index++
		case pythonClusterStop:
			return ""
		case pythonClusterDone:
		}
	}
	return ""
}

// pinsOneVersion reports whether a version selector names exactly one release.
//
// `pinned_version` is what the configuration pins, so a selector that chooses a *set* does
// not belong in it however concrete it looks. Two shapes were reaching the column:
//
//	npx real-package@latest    reported pinned_version=latest  -- a dist-tag, which npm
//	                           re-points whenever the maintainer publishes
//	uvx real-package==1.*      reported pinned_version=1.*     -- wildcard equality, a range
//
// Both got high confidence too, since confidence is derived from having a name and a version.
// An operator correlating the column against a vulnerability feed reads either as the version
// in use, and neither is.
//
// The rule is that a pin starts with a digit, optionally after a `v`, and contains no
// wildcard. A dist-tag is a name and starts with a letter; `latest`, `next` and `canary` are
// the common ones and npm does not publish a closed list, so matching the shape of a version
// is the only check that does not need one. The selector is still reported verbatim in
// requested_spec, so nothing is lost -- it moves from a column asserting a pin to one
// describing the request.
func pinsOneVersion(ver string) bool {
	if ver == "" {
		return false
	}
	if strings.ContainsAny(ver, "*") {
		return false
	}
	digits := strings.TrimPrefix(ver, "v")
	if digits == "" || digits[0] < '0' || digits[0] > '9' {
		return false
	}
	// A component that is `x` or `X` is npm's other wildcard spelling: 1.x and 1.2.X each
	// select a range while looking like an ordinary version.
	for _, component := range strings.Split(digits, ".") {
		if component == "x" || component == "X" {
			return false
		}
	}
	return true
}

// npmExactVersionRe is a complete semver version: all three components present, with the
// optional prerelease and build metadata semver allows.
//
// npm's X-ranges make a *missing* component a wildcard, so `1` means `1.x.x` and `1.2` means
// `1.2.x` -- ranges that select whatever the maintainer publishes next within them. Sharing
// pinsOneVersion with Python left both reported as exact pins at high confidence, because
// neither contains a wildcard character to notice. The rule has to be npm's own: a pin names
// all three components.
//
// Python is deliberately not held to this. PEP 440 `==1.0` is exact against the release it
// names, so requiring three components there would discard a real pin -- which is why the two
// ecosystems now have separate recognisers rather than one heuristic.
var npmExactVersionRe = regexp.MustCompile(
	`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// pinsOneNPMVersion reports whether an npm selector names exactly one published version.
func pinsOneNPMVersion(ver string) bool {
	return ver != "" && npmExactVersionRe.MatchString(ver)
}

// npmPinnedOrEmpty passes an npm selector through only when it names one version.
func npmPinnedOrEmpty(ver string) string {
	if pinsOneNPMVersion(ver) {
		return ver
	}
	return ""
}

// splitNPMSpec splits e.g. "@scope/pkg@1.0.0" into ("@scope/pkg", "1.0.0").
// Unscoped: "pkg@1" → ("pkg", "1"). No version: returns spec, "".
//
// A selector that is not a single complete version yields the name and an empty version; see
// pinsOneNPMVersion, which applies npm's own rule rather than the shared heuristic.
func splitNPMSpec(spec string) (name, ver string) {
	if spec == "" {
		return "", ""
	}
	if !looksLikePackageSpec(spec) {
		return "", ""
	}
	// Scoped: @scope/name[@ver]
	if strings.HasPrefix(spec, "@") {
		// find the second '@' (the version separator) after the slash
		slash := strings.IndexByte(spec, '/')
		if slash < 0 {
			return spec, ""
		}
		at := strings.IndexByte(spec[slash:], '@')
		if at < 0 {
			return spec, ""
		}
		return spec[:slash+at], npmPinnedOrEmpty(spec[slash+at+1:])
	}
	if at := strings.IndexByte(spec, '@'); at >= 0 {
		return spec[:at], npmPinnedOrEmpty(spec[at+1:])
	}
	return spec, ""
}

// pinnedOrEmpty passes a selector through only when it names one version.
func pinnedOrEmpty(ver string) string {
	if pinsOneVersion(ver) {
		return ver
	}
	return ""
}

// splitPyPISpec splits a PyPI requirement into its name and, only where the requirement
// actually pins one, its version.
//
// `==` is the only comparison that pins. Every other PEP 440 operator states a range or an
// exclusion, and the column is `pinned_version` -- what the configuration pins, which is the
// distinction the rename from `version` existed to draw. Returning the number beside the
// operator made the table assert a version the config never chose, and at *high* confidence,
// because confidence is derived from having both a name and a version:
//
//	pkg>=1.0   reported pinned_version=1.0  -- the floor of a range, not the pin
//	pkg~=1.4   reported pinned_version=1.4  -- a compatible-release range
//	pkg!=1.5   reported pinned_version=1.5  -- an *exclusion*: the one version ruled out
//
// The last is the clearest case for the change. An operator correlating this column against a
// vulnerability feed would read `pinned_version = 1.5` as the version in use, when the
// configuration says specifically not to use it.
//
// So a range yields the name and no version, which leaves confidence at medium: the package
// is known and the version is not. That is the honest reading of a range, and it is what the
// column already means for a requirement with no operator at all.
//
// PEP 440's `===` arbitrary-equality operator is deliberately not handled. It pins exactly,
// so it belongs with `==` on the semantics -- but packageSpecRe requires an alphanumeric
// immediately after the operator, so `pkg===1.2.3` fails looksLikePackageSpec and cannot
// reach this function. A branch for it would be unreachable, and the grammar is the place to
// change if `===` is ever worth admitting.
func splitPyPISpec(spec string) (name, ver string) {
	if spec == "" || !looksLikePackageSpec(spec) {
		return "", ""
	}
	// Checked before the range operators, because `==` contains `=` and a scan for the
	// range set would otherwise cut an exact pin in the wrong place.
	if i := strings.Index(spec, "=="); i > 0 {
		// Exact equality, unless the operand is a wildcard: `==1.*` is equality against a
		// set, which PEP 440 permits and which pins nothing.
		return spec[:i], pinnedOrEmpty(spec[i+2:])
	}
	// Any remaining comparison character starts a range or an exclusion. Matched as a
	// character class rather than as the operator list, so the name is cut at the first one
	// whichever spelling follows -- `>=` and `>` need no separate cases when the version is
	// discarded either way.
	if i := strings.IndexAny(spec, "<>~!="); i > 0 {
		return spec[:i], ""
	}
	// uv and uvx also accept npm-style selection, "tool@version" and "tool@latest". The
	// operator pins when its operand is one version; `@latest` is a moving tag and yields
	// the name with no version, the same as a range.
	if i := strings.IndexByte(spec, '@'); i > 0 {
		return spec[:i], pinnedOrEmpty(spec[i+1:])
	}
	return spec, ""
}

// splitDockerRef separates an image reference into (name, version-or-digest).
// Handles registry-port colons: localhost:5000/repo/img:tag → name=localhost:5000/repo/img, ver=tag.
//
// Both halves are validated after the split, which they were not before. dockerIdentity
// checks the whole reference against dockerRefRe and then hands it here, and the split is
// string surgery on a colon -- so a reference that satisfies the grammar as a whole can still
// produce halves that satisfy nothing. The name and the version are separate columns, and a
// column's value has to satisfy that column's rule rather than inheriting one from a string
// it was cut out of.
func splitDockerRef(ref string) (name, ver string) {
	if ref == "" {
		return "", ""
	}
	defer func() {
		// Checked here so every return path is covered, including the two early ones. A
		// guard at each return was the alternative and is how one gets missed.
		if name != "" && !dockerNameRe.MatchString(name) {
			name, ver = "", ""
			return
		}
		if ver != "" && !pinnedVersionRe.MatchString(ver) {
			// The whole triple goes, not just the version. A name with a version this
			// table refused to publish is a partial identity, and a partial identity reads
			// as a complete one: `package_name = x` with an empty version is what an
			// unpinned package looks like.
			name, ver = "", ""
		}
	}()
	// Digest reference: name@sha256:...
	if i := strings.Index(ref, "@sha256:"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	// Find the last colon that is not part of a host:port. A tag follows the
	// last component of the path, so look for ':' after the last '/'.
	lastSlash := strings.LastIndexByte(ref, '/')
	tail := ref[lastSlash+1:]
	if i := strings.IndexByte(tail, ':'); i >= 0 {
		return ref[:lastSlash+1+i], tail[i+1:]
	}
	return ref, ""
}

// packageSpecRe is the union of the npm and PyPI spec shapes: an optional @scope, a name, and
// an optional version introduced by @ or a PEP 440 comparison operator.
//
// A positive grammar, replacing a list of rejected prefixes. The blacklist accepted anything it
// had not thought of, and what it had not thought of included credentials:
// user:opaque-password@registry/image passed it and was emitted as
// package_name=user:opaque-password. A colon cannot appear in a package name, so a grammar
// rejects every userinfo form without having to enumerate them -- which matters because the
// final redactor only recognises known token shapes and an arbitrary password is not one.
var packageSpecRe = regexp.MustCompile(
	`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*` +
		`((==|>=|<=|~=|!=|[@><])[A-Za-z0-9][A-Za-z0-9.+_~*-]*)?$`)

// dockerRefRe is the distribution reference grammar: an optional host with optional numeric
// port, one or more lowercase path components, an optional tag, and an optional digest.
//
// The port being digits-only is what rejects user:password@host, and requiring lowercase in
// path components is what rejects an option value such as NET_ADMIN being read as an image.
var dockerRefRe = regexp.MustCompile(
	`^([a-z0-9][a-z0-9.-]*(:[0-9]+)?/)?` +
		`[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*` +
		`(:[A-Za-z0-9][A-Za-z0-9._-]*)?(@sha256:[a-f0-9]{64})?$`)

// looksLikePackageSpec reports whether a candidate is shaped like an npm or PyPI spec.
//
// Tarball and archive suffixes are still rejected explicitly: they satisfy the name grammar
// (a filename is name-shaped) but are a local artifact rather than a registry package.
func looksLikePackageSpec(s string) bool {
	if s == "" || len(s) > 214 { // npm's documented maximum name length
		return false
	}
	lo := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lo, ".tar"), strings.HasSuffix(lo, ".tar.gz"),
		strings.HasSuffix(lo, ".tgz"), strings.HasSuffix(lo, ".zip"),
		strings.HasSuffix(lo, ".whl"):
		return false
	}
	return packageSpecRe.MatchString(s)
}
