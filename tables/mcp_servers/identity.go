package mcp_servers

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/redact"
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
	if s.identityArgs != nil {
		argTok = s.identityArgs
	}
	if len(embedded) > 0 {
		// Redacted here because these arguments never passed through materialize, which is
		// where the declared args array gets the same treatment. Without it the two forms
		// of the same configuration behaved differently: `{"args": ["--token", "SECRET",
		// "pkg"]}` had SECRET replaced before inference and reported package_name=pkg,
		// while {"command": "npx --token SECRET pkg"} handed SECRET to the identity scanner
		// as the first package-shaped positional and copied it into package_name and
		// requested_spec. An opaque secret is exactly what the final redactor cannot
		// recognise, so it reached the row intact.
		argTok = secretEach(embedded)
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
		cand, ver, code := npxIdentity(args)
		if code != "" {
			s.noteWarning(warning{Code: code})
		}
		if looksLikePackageSpec(cand) {
			s.RequestedSpec = cand
			s.PackageName, _ = splitNPMSpec(cand)
			s.PinnedVersion = ver
		}
	},
	"bunx": func(s *Server, args []string) {
		s.PackageManager = "bunx"
		candidate, code := bunxIdentity(args)
		assignIfClean(s, candidate, code, splitNPMSpec)
	},
	"uvx": func(s *Server, args []string) {
		s.PackageManager = "uvx"
		candidate, code := uvxIdentity(args)
		assignIfClean(s, candidate, code, splitPyPISpec)
	},
	"uv": func(s *Server, args []string) {
		s.PackageManager = "uv"
		candidate, code := uvRunIdentity(args)
		assignIfClean(s, candidate, code, splitPyPISpec)
	},
	"pipx": func(s *Server, args []string) {
		s.PackageManager = "pipx"
		candidate, code := pipxIdentity(args)
		assignIfClean(s, candidate, code, splitPyPISpec)
	},
	"docker": containerIdentity(dockerGlobalGrammar, dockerRunGrammar),
	"podman": containerIdentity(podmanGlobalGrammar, podmanRunGrammar),
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
// code is threaded in rather than inferred, because the reasons an identity comes out empty are
// indistinguishable from the result: a candidate that is not package-shaped means the launcher
// was not asked to install a registry package, which is ordinary, while an unrecognised option
// or a repeated package option means this table could not tell, which is a finding.
func assignIfClean(s *Server, cand string, code warnCode, splitter func(string) (string, string)) {
	if code != "" {
		s.noteWarning(warning{Code: code})
	}
	if !looksLikePackageSpec(cand) {
		return
	}
	s.RequestedSpec = cand
	name, ver := splitter(cand)
	s.PackageName = name
	s.PinnedVersion = ver
}

// containerIdentity reports a container launcher, docker or podman, as the docker package
// manager, and identifies the image by that launcher's own grammars: before its subcommand, and
// for `run`. Each has its own, because the two disagree about options: podman's --passwd takes
// no value, and read as Docker reads an unlisted credential-named option it took the image as
// its value and published the container's command as the image.
func containerIdentity(global, run launcherGrammar) func(*Server, []string) {
	return func(s *Server, args []string) {
		s.PackageManager = "docker"
		// Validated against the reference grammar before anything is assigned, so a reference
		// such as user:secret@reg/img is not published as requested_spec and package_name.
		ref, unknown := containerRunIdentity(args, global, run)
		if unknown {
			s.noteWarning(warning{Code: warnUnknownLauncherOption})
		}
		if dockerRefRe.MatchString(ref) {
			s.RequestedSpec = ref
			s.PackageName, s.PinnedVersion = splitDockerRef(ref)
		}
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
	// anything else would report `wss://example.test/mcp` as transport=http, a protocol its
	// own config never named; normalizeTransport answers "unknown" for an explicitly
	// declared transport this table does not support, and the same answer is owed when the
	// scheme is the unsupported part.
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

// optionKind is what a launcher does with the token after one of its own options.
type optionKind int

const (
	// optionBoolean takes no value.
	optionBoolean optionKind = iota + 1
	// optionValue takes the next token as its value.
	optionValue
	// optionValueUnlessOption takes the next token as its value unless the token begins with a
	// dash. npx reads every npm setting it does not list as taking a value this way.
	optionValueUnlessOption
	// optionPackage takes the next token as its value, and the value names the package to
	// install, as npx's --package and uvx's --from do.
	optionPackage
	// optionCommand takes the next token as a command to run instead of a package, as npx's
	// --call does, so a launcher given one installs no package unless an optionPackage names one.
	optionCommand
	// optionLocalPath takes no value and makes the operand a local file rather than a package, as
	// pipx run's --path does, so the launcher installs nothing whatever else names a package.
	optionLocalPath
)

// launcherGrammar is how one launcher reads its own options: whether each takes a separate value,
// from the launcher's own source or CLI, so the token a value-taking option consumes is never
// read as the package and a value-less option never swallows it.
//
// Each launcher has its own, because the launchers disagree about the same names: -f is
// --find-links, a value, to uv, --force, which takes none, to npx, and not an option of bunx's;
// -c is uv's --constraint and npx's --call; -p is uvx's --python and npx's --package; podman's
// --passwd takes no value. One table shared between them published a launched server's argument
// as the package whenever two of them disagreed. An option the table does not list ends the scan
// with nothing identified, because whether it takes a value cannot be known.
type launcherGrammar struct {
	options map[string]optionKind
	// dashValues says a value-taking option takes the next token even when it begins with a
	// dash, as Docker's flag parser, npx's own list and bunx do. Otherwise the launcher refuses
	// such a command line, as clap and argparse do, and the scan gives up rather than guess.
	dashValues bool
	// ignoreDashes says options are looked up without their leading dashes, because npx strips
	// any number of them before it looks an option up.
	ignoreDashes bool
	// repeatedPackage is what the launcher does with its package option given more than once.
	repeatedPackage packageRule
	// credentialValues says an option the grammar does not list takes a value when its name
	// announces a credential. Only npx: its own parser reads an option it does not list as
	// taking the next token, so the name settles what the table cannot. The others refuse an
	// option they do not know, or, as bunx does, ignore it and take no value, so reading
	// podman's value-less --passwd as taking a value through Docker's table published the
	// container's command as the image.
	credentialValues bool
}

// packageRule is what a launcher does with its package option given more than once.
type packageRule int

const (
	// packageLast: the last one counts, as bunx's -p and pipx's --spec do.
	packageLast packageRule = iota
	// packageOnce: the launcher refuses the command line, as uv does for a repeated --from.
	packageOnce
	// packageAll: every one is installed, as npx's --package does, so differing ones name no
	// single package.
	packageAll
)

// newGrammar builds a launcherGrammar with settings' parsing rules from one space-separated list
// of option names per kind.
func newGrammar(settings launcherGrammar, lists map[optionKind]string) launcherGrammar {
	grammar := settings
	grammar.options = map[string]optionKind{}
	for kind, list := range lists {
		for _, name := range strings.Fields(list) {
			grammar.options[name] = kind
		}
	}
	return grammar
}

// kindOf returns how grammar reads the option name, and false for one it does not list.
func (grammar launcherGrammar) kindOf(name string) (optionKind, bool) {
	key := name
	if grammar.ignoreDashes {
		key = strings.TrimLeft(name, "-")
	}
	if kind, known := grammar.options[key]; known {
		return kind, true
	}
	if grammar.credentialValues && redact.IsSecretFlagName(name) {
		return optionValue, true
	}
	return 0, false
}

// isOption reports whether argument is an option. A lone dash is an operand: by convention it
// names standard input, and read as an option it took the token after it as its value, so
// `docker run - arg secret` named secret as the image.
func isOption(argument string) bool {
	return len(argument) > 1 && argument[0] == '-'
}

// launcherScan is what a launcher's own options say: the value of the first option naming the
// package, the first operand and where it is, whether an option names a command to run instead
// of a package, and whether the scan could not tell where the options end.
//
// The operand names a package only when it is package-shaped. A script path, a tarball or a URL
// means the launcher was not asked to install a registry package, and everything after it
// belongs to whatever it was asked to run, so packageOperand is empty for one.
type launcherScan struct {
	// packageValues are the values of every option naming the package, in order.
	packageValues []string
	operand       string
	operandIndex  int
	// endOfOptions says the operand came after `--`.
	endOfOptions bool
	command      bool
	// localPath says an option made the operand a local file, so nothing names a package.
	localPath bool
	unknown   bool
}

// scanLauncher walks args from the start by grammar and stops at the first operand, where the
// launched program's own arguments begin. `--` ends the options, so the token after it is the
// operand whatever it looks like. A value-taking option consumes the next token, so
// `--pip-args -i real-pkg secret` names no package from pip's arguments. unknown reports an
// option the grammar does not list, or a value beginning with a dash where the launcher refuses
// one: either way whether the next token is an operand cannot be decided, and an empty identity
// at low confidence is honest where a credential reported as a package name is not.
func scanLauncher(args []string, grammar launcherGrammar) launcherScan {
	var scan launcherScan
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			scan.operandIndex, scan.endOfOptions = index+1, true
			if index+1 < len(args) {
				scan.operand = args[index+1]
			}
			return scan
		}
		if !isOption(argument) {
			scan.operand, scan.operandIndex = argument, index
			return scan
		}
		name, value, hasInline := strings.Cut(argument, "=")
		kind, known := grammar.kindOf(name)
		switch {
		case !known && hasInline:
			// The inline form carries its own value and consumes nothing, so an option this
			// table does not list is harmless here: whatever follows is still an operand.
			continue
		case !known:
			scan.unknown = true
			return scan
		case (kind == optionBoolean || kind == optionLocalPath) && hasInline:
			// A value-less option given a value: uv and pipx refuse the command line, and npx
			// puts the value back as an operand, so `npx -y=./script.js secret` runs the script.
			scan.unknown = true
			return scan
		case kind == optionBoolean:
			continue
		case kind == optionLocalPath:
			scan.localPath = true
			continue
		}
		if !hasInline {
			next := index + 1
			if next >= len(args) {
				scan.operandIndex = len(args)
				return scan
			}
			following := args[next]
			switch {
			case following == "--":
				// The launchers disagree about whether an option takes `--` as its value -- npm's
				// parser never does, and ends the options there -- so neither reading is safe.
				scan.unknown = true
				return scan
			case isOption(following) && redact.IsSecretFlagName(name):
				// A credential option followed by an option: the credential is missing or begins
				// with a dash, and either way the token after it is not the package.
				scan.unknown = true
				return scan
			case isOption(following) && kind == optionValueUnlessOption:
				continue
			case isOption(following) && (!grammar.dashValues || kind == optionPackage):
				// No package name begins with a dash, so a package option's value that does
				// is another option, whatever the launcher would make of it.
				scan.unknown = true
				return scan
			}
			value, index = following, next
		}
		switch kind {
		case optionPackage:
			scan.packageValues = append(scan.packageValues, value)
		case optionCommand:
			scan.command = true
		}
	}
	scan.operandIndex = len(args)
	return scan
}

// packageOperand is the first operand when it is package-shaped, and empty otherwise.
func (scan launcherScan) packageOperand() string {
	if looksLikePackageSpec(scan.operand) {
		return scan.operand
	}
	return ""
}

// identityFrom is the package a scan names, by grammar, and the warning when it cannot name one
// it is sure of: unknown_launcher_option when the scan could not tell where the options end, and
// identity_dropped when the package option was given more than once and the launcher would not
// run exactly one package from it. The package option's value names the package; with none, the
// first operand does, unless an option names a command to run instead.
func identityFrom(scan launcherScan, grammar launcherGrammar) (string, warnCode) {
	values := scan.packageValues
	switch {
	case scan.unknown:
		return "", warnUnknownLauncherOption
	case scan.localPath:
		return "", ""
	case len(values) == 0 && scan.command:
		return "", ""
	case len(values) == 0:
		return scan.packageOperand(), ""
	case len(values) == 1:
		return values[0], ""
	}
	switch grammar.repeatedPackage {
	case packageLast:
		return values[len(values)-1], ""
	case packageAll:
		for _, value := range values[1:] {
			if value != values[0] {
				return "", warnIdentityDropped
			}
		}
		return values[0], ""
	}
	return "", warnIdentityDropped
}

// npxIdentity resolves `npx`. The package is what --package names, or else the first operand;
// with --call and no --package, npx runs a command and installs nothing. A script path or URL
// as the first operand is not package-shaped and names nothing, and everything after the first
// operand belongs to whatever npx was asked to run: `npx real-package --package evil` names
// real-package.
func npxIdentity(args []string) (spec, ver string, code warnCode) {
	spec, code = identityFrom(scanLauncher(args, npxGrammar), npxGrammar)
	_, ver = splitNPMSpec(spec)
	return spec, ver, code
}

// bunxIdentity resolves `bunx`, which reads its options as npx does: --package names the
// package and the first operand is then the binary to run. `bunx -p @scope/pkg cmd` named cmd.
func bunxIdentity(args []string) (string, warnCode) {
	return identityFrom(scanLauncher(args, bunxGrammar), bunxGrammar)
}

// uvxIdentity resolves `uvx`, where --from names the package and the first operand names the
// command inside it. `uvx --from git+https://github.com/acme/mcp-suite.git actual-server` is the
// Git-backed form Astral documents: the package is the Git spec, which is not representable, so
// the identity is empty rather than the command.
func uvxIdentity(args []string) (string, warnCode) {
	return identityFrom(scanLauncher(args, uvToolRunGrammar), uvToolRunGrammar)
}

// uvRunIdentity resolves `uv tool run <pkg>` as uvx, past uv's global options. `uv run` runs a
// command from the project environment and names no package; its options are still read, so one
// this table does not know is reported. uv's `run` takes no --from: uv refuses that command line.
// The subcommand is read only in its own position, so in `uv run actual-command tool run
// fake-package` the pair among the launched command's arguments is not read.
func uvRunIdentity(args []string) (string, warnCode) {
	global := scanLauncher(args, uvGlobalGrammar)
	index := global.operandIndex
	switch {
	case global.unknown:
		return "", warnUnknownLauncherOption
	case global.endOfOptions:
		return "", ""
	case index+1 < len(args) && args[index] == "tool" && args[index+1] == "run":
		return uvxIdentity(args[index+2:])
	case index < len(args) && args[index] == "run" &&
		scanLauncher(args[index+1:], uvRunGrammar).unknown:
		return "", warnUnknownLauncherOption
	}
	return "", ""
}

// pipxIdentity resolves `pipx run`, where --spec names the package and the first operand names
// the app. The subcommand is read only in pipx's own position, after its global options, so the
// same word among another subcommand's arguments or the launched program's is not read as it:
// `pipx install foo run secret` and `pipx --unknown run secret` name nothing.
func pipxIdentity(args []string) (string, warnCode) {
	global := scanLauncher(args, pipxGlobalGrammar)
	index := global.operandIndex
	switch {
	case global.unknown:
		return "", warnUnknownLauncherOption
	case global.endOfOptions || index >= len(args) || args[index] != "run":
		return "", ""
	}
	return identityFrom(scanLauncher(args[index+1:], pipxRunGrammar), pipxRunGrammar)
}

// containerRunIdentity returns the image reference from a `docker run` or `podman run`
// invocation: the first operand after the launcher's own options and run's, when it is
// reference-shaped.
//
// Every option is looked up in the launcher's run grammar, from its own source or help. One it
// does not list
// ends the scan with nothing identified and unknown set, because whether it takes a value cannot
// be known, and guessing either way crosses from the image into the container's command: a
// boolean read as taking a value consumed the image, so `docker run --use-api-socket alpine:3
// opaquesecret123` published the command's argument as the image. Values that satisfy the image
// grammar are why a guess fails silently rather than loudly: `--publish 8080:80` reads as a tagged
// reference, `--memory 512m` and `--dns 1.1.1.1` as one-component ones.
func containerRunIdentity(args []string, global, run launcherGrammar) (ref string, unknown bool) {
	start, isRun, unknown := containerRunArgs(args, global)
	if !isRun {
		return "", unknown
	}
	for i := start; i < len(args); i++ {
		argument := args[i]
		if argument == "--" {
			// Everything after this is the image and the container's command.
			if i+1 < len(args) && dockerRefRe.MatchString(args[i+1]) {
				return args[i+1], false
			}
			return "", false
		}
		if !isOption(argument) {
			// The first operand is the image. One that is not reference-shaped names nothing,
			// and what follows is the container's command.
			if dockerRefRe.MatchString(argument) {
				return argument, false
			}
			return "", false
		}
		name, _, hasInline := strings.Cut(argument, "=")
		kind, known := run.kindOf(name)
		switch {
		case hasInline:
			// The inline form carries its own value and consumes nothing.
		case known && kind == optionBoolean:
		case known:
			// The launchers' flag parser takes the next token as the value whatever it looks
			// like, which --oom-score-adj -100 and --pids-limit -1 need.
			i++
		default:
			// A grouped short-option cluster such as -it, the most common invocation of all.
			consumesNext, recognised := shortCluster(run, argument)
			if !recognised {
				return "", true
			}
			if consumesNext {
				i++
			}
		}
	}
	return "", false
}

// containerRunArgs returns the index just past the run subcommand, `run` or `container run`,
// found in the subcommand's own position: after the launcher's global options, by global. A
// `run` anywhere was accepted, so `docker exec c run secret` published secret as the image.
// isRun is false when that position holds anything else; unknown also reports a global option
// the table does not list, since it may consume the next token.
func containerRunArgs(args []string, grammar launcherGrammar) (index int, isRun, unknown bool) {
	global := scanLauncher(args, grammar)
	index = global.operandIndex
	switch {
	case global.unknown:
		return 0, false, true
	case global.endOfOptions:
		return 0, false, false
	case index < len(args) && args[index] == "run":
		return index + 1, true, false
	case index+1 < len(args) && args[index] == "container" && args[index+1] == "run":
		return index + 2, true, false
	}
	return 0, false, false
}

// shortCluster interprets a single-dash short-option group such as -it or -itv by grammar's
// one-letter options.
//
// The container launchers' flag parser (pflag) walks a cluster left to right: a value-less
// shorthand yields to the next character, while the first value-taking one takes the rest of
// the cluster as its value (-p8080:80) or, when it ends the cluster, the next token
// (-p 8080:80).
//
// recognised is false when the group holds a character the grammar does not list, and the
// caller then identifies nothing.
func shortCluster(grammar launcherGrammar, argument string) (consumesNext, recognised bool) {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false, false
	}
	group := argument[1:]
	for index := 0; index < len(group); index++ {
		switch grammar.options["-"+group[index:index+1]] {
		case optionBoolean:
			continue
		case optionValue:
			return index == len(group)-1, true
		default:
			return false, false
		}
	}
	return false, true
}

// The launchers' grammars, each from the launcher's own source or CLI: npm 12.2.1's
// bin/npx-cli.js and config definitions, uv 0.13.3's clap definitions in crates/uv-cli, pipx
// 1.18.4's argparse definitions in src/pipx/main.py, bun 1.4.3's src/runtime/cli/bunx_command.rs,
// Docker 29.8.2's `docker --help` and `docker run --help`, and podman 6.1.4's flag definitions in
// cmd/podman/root.go, cmd/podman/containers/run.go and cmd/podman/common. A launcher adding a
// value-less option after these versions costs that option's rows their identity, with
// unknown_launcher_option saying so, and adding the option here repairs it.
var (
	// npx, from npm 12.2.1: bin/npx-cli.js decides which options take a value, from npm's config
	// definitions and shorthands, before npm exec reads the command line.
	npxGrammar = newGrammar(launcherGrammar{dashValues: true, ignoreDashes: true,
		credentialValues: true, repeatedPackage: packageAll}, map[optionKind]string{
		optionBoolean: `
		? B D E H O P S a all allow-same-version allow-scripts-pending allow-scripts-pin
		allow-unused-patches always-spawn audit bin-links browser bypass-2fa color commit-hooks
		d dangerously-allow-all-scripts dd ddd desc description dev diff-ignore-all-space
		diff-name-only diff-no-prefix diff-text dry-run engine-strict expect-results f force
		foreground-scripts format-package-lock fund g git-tag-version global global-style h
		help if-present ignore-existing ignore-extension ignore-patch-failures ignore-scripts
		include-attestations include-staged include-workspace-root init-private install-links
		iwr json keep-edit-dir l legacy-bundling legacy-peer-deps link local long no no-install
		offline omit-lockfile-registry-resolved optional package-lock package-lock-only
		packages-all parseable porcelain prefer-dedupe prefer-offline prefer-online production
		progress provenance q quiet read-only readonly rebuild-bundle s save save-bundle
		save-dev save-exact save-optional save-peer save-prod shell-auto-fallback
		sign-git-commit sign-git-tag silent strict-allow-scripts strict-npmrc strict-peer-deps
		strict-ssl timing unicode update-notifier usage v verbose version versions workspaces
		workspaces-update ws y yes`,
		optionValue: `
		cache n node-arg npm shell userconfig`,
		optionValueUnlessOption: `
		C L _auth access allow-directory allow-file allow-git allow-remote allow-scripts also
		audit-level auth-type before ca cache-max cache-min cafile cert cidr cpu depth diff
		diff-dst-prefix diff-src-prefix diff-unified edit-dir editor enjoy-by
		expect-result-count expires extension-file fetch-retries fetch-retry-factor
		fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout git global-ignore-file
		globalconfig heading https-proxy include init-author-email init-author-name
		init-author-url init-license init-module init-type init-version install-strategy key
		libc local-address location lockfile-version loglevel logs-dir logs-max m maxsockets
		message min-release-age min-release-age-exclude name node-gyp node-options noproxy omit
		only orgs orgs-permission os otp pack-destination packages
		packages-and-scopes-permission password patches-dir prefix preid provenance-file proxy
		reg registry replace-registry-host save-prefix sbom-format sbom-type scope scopes
		script-shell searchexclude searchlimit searchopts searchstaleness tag
		tag-version-prefix to token-description umask user-agent viewer w which workspace`,
		optionPackage: `
		p package`,
		optionCommand: `
		c call`,
	})
	// uvx, and `uv tool run` after its subcommand.
	uvToolRunGrammar = newGrammar(launcherGrammar{repeatedPackage: packageOnce},
		map[optionKind]string{
			optionBoolean: `
		--allow-python-downloads --binary --build --build-isolation --compile
		--compile-bytecode --force-reinstall --help --isolated --lfs --managed-python
		--native-tls --no-binary --no-build --no-build-isolation --no-cache --no-cache-dir
		--no-color --no-compile --no-compile-bytecode --no-config --no-env-file --no-index
		--no-installer-metadata --no-managed-python --no-native-tls --no-offline --no-preview
		--no-progress --no-python-downloads --no-refresh --no-reinstall
		--no-require-build-hashes --no-sources --no-system-certs --no-upgrade --offline --pre
		--preview --quiet --refresh --reinstall --require-build-hashes --show-resolution
		--show-settings --system-certs --upgrade --verbose --version -U -V -h -n -q -v`,
			optionValue: `
		--allow-insecure-host --build-constraint --build-constraints --cache-dir --color
		--config-file --config-setting --config-settings --config-settings-package --constraint
		--constraints --default-index --directory --env-file --exclude-newer
		--exclude-newer-package --extra-index-url --find-links --fork-strategy
		--generate-shell-completion --index --index-strategy --index-url --keyring-provider
		--link-mode --no-binary-package --no-build-isolation-package --no-build-package
		--no-sources-package --override --overrides --prerelease --prerelease-package
		--preview-feature --preview-features --project --python --python-fetch
		--python-platform --python-preference --refresh-package --reinstall-package
		--resolution --torch-backend --trusted-host --upgrade-group --upgrade-package --with
		--with-editable --with-requirements -C -P -b -c -f -i -p -w`,
			optionPackage: `
		--from`,
		})
	// `uv run`, after its subcommand.
	uvRunGrammar = newGrammar(launcherGrammar{}, map[optionKind]string{
		optionBoolean: `
		--active --all-extras --all-packages --allow-python-downloads --binary --build
		--build-isolation --compile --compile-bytecode --editable --exact --force-reinstall
		--frozen --gui-script --help --inexact --isolated --locked --managed-python --module
		--native-tls --no-active --no-all-extras --no-binary --no-build --no-build-isolation
		--no-cache --no-cache-dir --no-color --no-compile --no-compile-bytecode --no-config
		--no-editable --no-env-file --no-exact --no-frozen --no-index --no-installer-metadata
		--no-locked --no-managed-python --no-native-tls --no-offline --no-preview --no-progress
		--no-project --no-python-downloads --no-refresh --no-reinstall
		--no-require-build-hashes --no-sources --no-sync --no-system-certs --no-upgrade
		--no_workspace --offline --pre --preview --quiet --refresh --reinstall
		--require-build-hashes --script --show-resolution --show-settings --system-certs
		--upgrade --verbose --version -U -V -h -m -n -q -s -v`,
		optionValue: `
		--allow-insecure-host --cache-dir --color --config-file --config-setting
		--config-settings --config-settings-package --default-index --directory --env-file
		--exclude-newer --exclude-newer-package --extra --extra-index-url --find-links
		--fork-strategy --index --index-strategy --index-url --keyring-provider --link-mode
		--max-recursion-depth --no-binary-package --no-build-isolation-package
		--no-build-package --no-editable-package --no-extra --no-sources-package --package
		--prerelease --prerelease-package --preview-feature --preview-features --project
		--python --python-fetch --python-platform --python-preference --refresh-package
		--reinstall-package --resolution --trusted-host --upgrade-group --upgrade-package
		--with --with-editable --with-requirements -C -P -f -i -p -w`,
	})
	// uv before its subcommand.
	uvGlobalGrammar = newGrammar(launcherGrammar{}, map[optionKind]string{
		optionBoolean: `
		--allow-python-downloads --help --isolated --managed-python --native-tls --no-cache
		--no-cache-dir --no-color --no-config --no-installer-metadata --no-managed-python
		--no-native-tls --no-offline --no-preview --no-progress --no-python-downloads
		--no-system-certs --offline --preview --quiet --show-settings --system-certs --verbose
		--version -V -h -n -q -v`,
		optionValue: `
		--allow-insecure-host --cache-dir --color --config-file --directory --preview-feature
		--preview-features --project --python-fetch --python-preference --trusted-host`,
	})
	// `docker run`, after its subcommand, with four hidden aliases Docker still accepts:
	// --disable-content-trust, --net, --net-alias, --dns-opt and --kernel-memory.
	dockerRunGrammar = newGrammar(launcherGrammar{dashValues: true}, map[optionKind]string{
		optionBoolean: `
		--detach --disable-content-trust --help --init --interactive --no-healthcheck
		--oom-kill-disable --privileged --publish-all --quiet --read-only --rm --sig-proxy
		--tty --use-api-socket -P -d -i -q -t`,
		optionValue: `
		--add-host --annotation --attach --blkio-weight --blkio-weight-device --cap-add
		--cap-drop --cgroup-parent --cgroupns --cidfile --cpu-count --cpu-percent --cpu-period
		--cpu-quota --cpu-rt-period --cpu-rt-runtime --cpu-shares --cpus --cpuset-cpus
		--cpuset-mems --detach-keys --device --device-cgroup-rule --device-read-bps
		--device-read-iops --device-write-bps --device-write-iops --dns --dns-opt --dns-option
		--dns-search --domainname --entrypoint --env --env-file --expose --gpus --group-add
		--health-cmd --health-interval --health-retries --health-start-interval
		--health-start-period --health-timeout --hostname --io-maxbandwidth --io-maxiops --ip
		--ip6 --ipc --isolation --kernel-memory --label --label-file --link --link-local-ip
		--log-driver --log-opt --mac-address --memory --memory-reservation --memory-swap
		--memory-swappiness --mount --name --net --net-alias --network --network-alias
		--oom-score-adj --pid --pids-limit --platform --publish --pull --restart --runtime
		--security-opt --shm-size --stop-signal --stop-timeout --storage-opt --sysctl --tmpfs
		--ulimit --umask --user --userns --uts --volume --volume-driver --volumes-from
		--workdir -a -c -e -h -l -m -p -u -v -w`,
	})
	// docker before its subcommand.
	dockerGlobalGrammar = newGrammar(launcherGrammar{}, map[optionKind]string{
		optionBoolean: `
		--debug --tls --tlsverify --version -D -v`,
		optionValue: `
		--config --context --host --log-level --tlscacert --tlscert --tlskey -H -c -l`,
	})
	// podman before its subcommand: the root command's own flags and its persistent ones.
	podmanGlobalGrammar = newGrammar(launcherGrammar{dashValues: true}, map[optionKind]string{
		optionBoolean: `
		--debug --help --noout --remote --syslog --trace --transient-store -D -r`,
		optionValue: `
		--cdi-spec-dir --cgroup-manager --config --conmon --connection --context --cpu-profile
		--default-mounts-file --events-backend --hooks-dir --host --identity --imagestore
		--log-level --max-workers --memory-profile --module --namespace --network-backend
		--network-config-dir --out --pull-option --registries-conf --root --runroot --runtime
		--runtime-flag --ssh --storage-driver --storage-opt --tls-ca --tls-cert --tls-details
		--tls-key --tmpdir --url --volumepath -H -c`,
	})
	// `podman run`, after its subcommand: run's, create's and the network flags, the persistent
	// ones, and the aliases podman's AliasFlags maps onto them.
	podmanRunGrammar = newGrammar(launcherGrammar{dashValues: true}, map[optionKind]string{
		optionBoolean: `
		--detach --disable-content-trust --env-host --help --http-proxy --init --interactive
		--no-healthcheck --no-hostname --no-hosts --oom-kill-disable --passwd --privileged
		--publish-all --quiet --read-only --read-only-tmpfs --replace --rm --rmi --rootfs
		--sig-proxy --syslog --trace --transient-store --tty --unsetenv-all -P -d -i -q -t`,
		optionValue: `
		--add-host --annotation --arch --attach --authfile --blkio-weight --blkio-weight-device
		--cap-add --cap-drop --cdi-spec-dir --cert-dir --cgroup-conf --cgroup-manager
		--cgroup-parent --cgroupns --cgroups --chrootdirs --cidfile --conmon --conmon-pidfile
		--cpu-period --cpu-profile --cpu-quota --cpu-rt-period --cpu-rt-runtime --cpu-shares
		--cpus --cpuset-cpus --cpuset-mems --creds --decryption-key --default-mounts-file
		--detach-keys --device --device-cgroup-rule --device-read-bps --device-read-iops
		--device-write-bps --device-write-iops --dns --dns-opt --dns-option --dns-search
		--entrypoint --env --env-file --env-merge --events-backend --expose --gidmap --gpus
		--group-add --group-entry --health-cmd --health-interval --health-log-destination
		--health-max-log-count --health-max-log-size --health-on-failure --health-retries
		--health-start-period --health-startup-cmd --health-startup-interval
		--health-startup-retries --health-startup-success --health-startup-timeout
		--health-timeout --healthcheck-command --healthcheck-interval --healthcheck-retries
		--healthcheck-start-period --healthcheck-timeout --hooks-dir --hostname --hosts-file
		--hostuser --image-volume --imagestore --init-path --ip --ip6 --ipc --kernel-memory
		--label --label-file --log-driver --log-level --log-opt --mac-address --max-workers
		--memory --memory-profile --memory-reservation --memory-swap --memory-swappiness
		--mount --name --namespace --net --network --network-alias --network-backend
		--network-config-dir --oom-score-adj --os --override-arch --override-os
		--override-variant --passwd-entry --personality --pid --pidfile --pids-limit --platform
		--pod --pod-id-file --preserve-fds --publish --pull --pull-option --rdt-class
		--registries-conf --requires --restart --retry --retry-delay --root --runroot --runtime
		--runtime-flag --sdnotify --seccomp-policy --secret --security-opt --shm-size
		--shm-size-systemd --signature-policy --stop-signal --stop-timeout --storage-driver
		--storage-opt --subgidname --subuidname --sysctl --systemd --timeout --tmpdir --tmpfs
		--tz --uidmap --ulimit --umask --unsetenv --user --userns --uts --variant --volume
		--volumepath --volumes-from --workdir -a -c -e -h -l -m -p -u -v -w`,
	})
	// pipx before its subcommand.
	pipxGlobalGrammar = newGrammar(launcherGrammar{}, map[optionKind]string{
		optionBoolean: `
		--global --help --quiet --skip-maintenance --verbose --version -h -q -v`,
	})
	// `pipx run`, after its subcommand.
	pipxRunGrammar = newGrammar(launcherGrammar{}, map[optionKind]string{
		optionBoolean: `
		--editable --fetch-missing-python --global --help --no-cache --no-path-check
		--pypackages --quiet --refresh --skip-maintenance --system-site-packages --verbose
		--version -e -h -q -v`,
		optionValue: `
		--backend --cooldown --fetch-python --index-url --pip-args --python --python-args
		--with -i`,
		optionPackage: `
		--spec`,
		optionLocalPath: `
		--path`,
	})
	// bunx. bunx itself ignores an option it does not know, so failing closed on one is
	// stricter than bunx is.
	bunxGrammar = newGrammar(launcherGrammar{dashValues: true}, map[optionKind]string{
		optionBoolean: `
		--bun --no-install --revision --silent --verbose --version -b -v`,
		optionPackage: `
		--package -p`,
	})
)

// pythonLongValueFlags are the interpreter's long options that take a separate value. The short
// options cluster and are read character by character instead; see pythonShortCluster.
var pythonLongValueFlags = map[string]struct{}{"--check-hash-based-pycs": {}}

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
// Read here rather than through the generic option walk, for two reasons. CPython attaches a
// short option's argument to the option itself, so `-mhttp.server` is one token. And it
// clusters them, so `-ucprint(9) -m evilmod` holds a -c inside a group: skipping the group as
// a boolean would report evilmod, while python runs the -c program.
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
