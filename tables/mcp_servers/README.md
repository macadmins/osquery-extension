# `mcp_servers`

[Model Context Protocol](https://modelcontextprotocol.io/specification/latest) servers configured per user and client, read from each client's own configuration files.

One row per declared server, plus diagnostic rows describing anything that was not listed. No table in this repository had a README before this one; the pattern is a short description and a `Notes` pointer in the root `README.md`, with the detail here.

## Sources

Every path is relative to a user's home directory. The application-support root resolves per platform — `~/Library/Application Support` on macOS, `%APPDATA%` (`~/AppData/Roaming`) on Windows, `~/.config` on Linux — and is reconstructed from each home rather than read from the environment, because the environment belongs to the daemon's account and not to the account being scanned.

### Fixed paths, probed once per account

| Client | Path | Format | Vendor documentation |
|---|---|---|---|
| `claude_code` | `.claude.json` | JSON | [Claude Code MCP](https://docs.claude.com/en/docs/claude-code/mcp) |
| `claude_desktop` | `<appsupport>/Claude/claude_desktop_config.json` | JSONC | [MCP quickstart](https://modelcontextprotocol.io/quickstart/user) |
| `cursor` | `.cursor/mcp.json` | JSONC | [Cursor MCP](https://docs.cursor.com/context/mcp) |
| `windsurf` | `.codeium/windsurf/mcp_config.json` | JSONC | [Windsurf Cascade MCP](https://docs.windsurf.com/windsurf/cascade/mcp) |
| `gemini` | `.gemini/settings.json` | JSONC | [Gemini CLI MCP](https://google-gemini.github.io/gemini-cli/docs/tools/mcp-server.html) |
| `copilot` | `.copilot/mcp-config.json` | JSONC | [GitHub Copilot MCP](https://docs.github.com/en/copilot/concepts/about-mcp) |
| `codex` | `.codex/config.toml` | TOML | [Codex MCP](https://developers.openai.com/codex/mcp) |
| `codex` | `.codex/mcp.json`, `.codex/.mcp.json` | JSONC (older builds) | [Codex MCP](https://developers.openai.com/codex/mcp) |
| `vscode`, `cursor`, `windsurf` | `<appsupport>/<fork>/User/mcp.json` | JSONC | [VS Code MCP servers](https://code.visualstudio.com/docs/copilot/chat/mcp-servers) |
| `cline` | `<appsupport>/<fork>/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | JSONC | [Cline MCP](https://docs.cline.bot/mcp/configuring-mcp-servers) |

Each link is the vendor's own documentation for the file this table reads, so a reader can check a path against its source rather than against this table's reading of it. All resolved in October 2026; a vendor reorganising its docs will break them, which is the ordinary cost of citing a URL instead of restating the claim.

VS Code family forks are `Code`, `Code - Insiders`, `Cursor`, `Windsurf` and `VSCodium`. Insiders and VSCodium report as `client = 'vscode'`, because they are the same editor and an operator filtering for it means all of them.

On Linux a snap or flatpak install redirects the configuration directory out of `~/.config`, so the forks with an official sandboxed channel are also looked for under `~/snap/<name>/current/.config` and `~/.var/app/<app-id>/config`. The snap name and the flatpak application id are tabulated per fork because they follow no derivable rule.

### Generated directory names, read with one bounded listing

Two locations put a name the application generates between a fixed path and the configuration file, so no fixed path can reach them. Each is one `ReadDir`, no recursion, capped, with symlinks refused at every component:

- `<appsupport>/<fork>/User/profiles/<generated-id>/mcp.json` — a user with a work profile and a personal profile keeps a different server list in each, and neither is the user-scope file above.
- `~/.codex/<profile>.config.toml` — Codex named profiles. The `.codex` parent is required rather than matching `config.toml` anywhere, because that basename is among the most common on a developer machine.

### Claude Code plugins

A [plugin](https://docs.claude.com/en/docs/claude-code/plugins) can ship its own `.mcp.json`, and those servers are live. Installed plugins sit at:

```
~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.mcp.json
```

All three directory names are chosen by the marketplace rather than derivable, so this is three bounded listings, capped per level and against a total probe budget.

**Every installed plugin is probed, and enablement is reported rather than filtered.** [`~/.claude/settings.json`](https://code.claude.com/docs/en/settings) carries `enabledPlugins` as an object of `"<plugin>@<marketplace>": bool`, which gives three distinct states, and `approval_state` has a value for each:

| In `enabledPlugins` | `approval_state` |
|---|---|
| `true` | `enabled` |
| `false` | `disabled` — turned off deliberately |
| absent | `not_approved` — installed, never enabled |

A plugin someone installed and forgot is a thing a security inventory should show, which is why these are listed rather than dropped. Settings that exist and cannot be read give `unknown` rather than `not_approved`; settings that are *absent* give `not_approved`, because a user who never enabled a plugin genuinely has no such file.

**`~/.claude/settings.local.json` is deliberately not read.** Claude Code's documented precedence places it at *project* scope — managed, then command line, then project-local `settings.local.json`, then shared project `settings.json`, then user `settings.json` — and there is no user-scope version of it. The file appears in a home whenever that home has been opened as a project, which is common, so reading it applied one project's overrides to every plugin row for the account.

**A cached version is not evidence that the client would load it.** `installed_plugins.json` is the record Claude Code itself loads from, keyed `<entry>@<marketplace>` and holding each install's scope, installPath and version. It is read, because the cache keeps old versions: on update or uninstall Claude writes an `.orphaned_at` marker into the previous version's directory and deletes it in a background sweep fourteen days later, so a session that already loaded it keeps working. A cached directory that the records do not point at, or that carries the marker, reports `approval_state = 'unknown'` with `plugin_version_superseded` rather than inheriting the plugin's enabled state — for two weeks after any update, a server deleted in the new release was otherwise still reported as `enabled`. The row is kept rather than dropped, because a running session may still hold that server; what is withdrawn is the claim that it is enabled.

Where selection simply could not be established — an orphan marker that could not be read, records that could not be read, a record carrying no `installPath` — the row reports `plugin_selection_unknown` instead. Only one of those three is a records-read failure, and that one is reported in its own right at account level, so the row names what it does not know rather than guessing at a cause.

**Selection is established from `installPath`, not from the version string.** A version names a *release* and more than one directory can carry the same label — a relative-path plugin loaded in place, a relocated cache, a leftover copy — so matching on it treated any directory labelled `1.0.0` as selected even when the record pointed elsewhere. `installPath` names the filesystem copy the client resolved, which is the question being asked. Paths are compared as written rather than case-folded, and a record carrying no `installPath` establishes nothing: both read as `unknown` rather than as selected, since the cost of that is a qualified row and the cost of the other direction is a false `enabled`.

**Servers declared in the plugin manifest are read as well as `.mcp.json`.** `.claude-plugin/plugin.json` may carry `mcpServers` as an inline map, a `./*.json` path, or an array mixing them, and Claude loads `.mcp.json` first and then each declared shape in order, with a later server name replacing an earlier one. All three forms are read and that precedence is preserved, so a manifest that renames or redefines a server reports what the client would actually run. Two documented forms are refused and reported with `plugin_manifest_unsupported`: a `.mcpb` or `.dxt` bundle would have to be unpacked, and a bundle URL fetched, before either could say what it declares — one is an archive extraction driven by a file the user controls, the other a network request to a host named in it, and neither belongs in a scheduled query. Declared paths are re-checked for containment here rather than trusted, and a path containing a backslash is refused outright because the documentation makes such a path load on Windows only. A file the manifest *names* and that cannot be read is reported with `plugin_manifest_missing_source`, which is the opposite policy from the root `.mcp.json`: most plugins ship no root config, so its absence is the common case and silent, while a declared path is documented to have to exist and its absence is a broken reference.

**A declaration that cannot be read qualifies the definition it would have replaced.** Precedence is by declared name, but the merge can only key on names it decoded, so a manifest declaring `"srv": {"command": 123}` produced a parse diagnostic and left the root `.mcp.json`'s `srv` standing as a clean, complete, enabled row — reporting a definition a higher-precedence declaration had overridden with something unreadable. Rows from lower-precedence sources are marked incomplete and carry `plugin_declaration_shadowed` when a later source in the same plugin fails at source scope. The qualification is applied *before* that source's own declarations are merged, so a name it successfully redefines overwrites the qualified row and carries nothing from it — only a name the failed source did not replace stays qualified. The code is source-scoped rather than home-scoped, because it describes one file's authority and not the account's: home scope made one stale plugin definition set `scan_complete = 0` on every row for the account, an unrelated client's healthy configuration included. They are qualified rather than dropped, and rather than resolved: this table cannot tell whether the client rejected the bad entry and kept the old one or replaced it, so the honest row is the old definition marked as possibly stale. The scope is coarse by name and exact by precedence — the extractor reports a failed envelope without naming the entries inside it, so which names were shadowed is not recoverable, while which rows are lower precedence is.

**A manifest element of the wrong type is reported, not skipped.** `mcpServers` accepts a path, a map, or an array of either; an element that is a number, a boolean or a nested array is a malformed value in a field this table reads, and `claude plugin validate` treats such a type mismatch as a load-time failure. It reports `plugin_manifest_invalid_declaration` and the sibling elements that did parse are still listed. A JSON `null` or an empty map stays silent, because declaring nothing is not the same as being malformed.

**Manifest declarations are bounded separately from the plugin probe cap.** That cap counts cached version directories, and a manifest adds reads underneath one of them, so without a second bound a single manifest could name thousands of independently capped files and the accepted byte and row totals were unbounded while every individual read looked compliant. The deadline does not substitute, because it bounds elapsed cooperative work rather than bytes accumulated before it expires. Eight declared sources per version and sixty-four across the pass; exceeding either reports `plugin_manifest_truncated`, so coverage lost to a cap is visible. A path declared twice is read once, but still counts at its last position, because a repeated declaration decides which definition of a name survives and dropping it would change precedence rather than save work.

**`~/.claude/plugins/marketplaces/` is deliberately not read.** That is the marketplace's own checkout; it holds the plugin source, so reading it would both reintroduce installable-catalog rows and double-count every installed plugin. An earlier version of this table excluded the whole `plugins/` tree by path substring, with a measured justification — 39 of 51 rows from one client were catalog entries nobody had enabled. That was right about the catalog and too broad about the installed copy, which is configuration the client acts on. Probing only `plugins/cache/` makes the noise impossible by construction rather than excluded by a list of substrings maintained by noticing each new cache directory.

Not read: plugin enablement set per project rather than per user. Only `~/.claude/settings.json` is consulted, which is the one user-scope file -- an earlier version of this sentence said two, and `~/.claude/settings.local.json` is the other one it meant, which is project-scope and deliberately not read for the reason given above.

### Project-local configuration, from each client's project list

Project-local files are found by reading the list of projects a client already maintains and probing known filenames inside each entry. Three lists are read:

| Origin | Source | What is read |
|---|---|---|
| `claude_json` | `.claude.json` → `projects` | the key, `enabledMcpjsonServers`, `disabledMcpjsonServers` |
| `codex_toml` | `.codex/config.toml` → `[projects."…"]` | the key and `trust_level` |
| `vscode_workspace` | `<appsupport>/<fork>/User/workspaceStorage/*/workspace.json` | the `folder` field |

Four things are read from a Claude project entry — the key, the two server-name arrays, and `hasTrustDialogAccepted`, which decides whether a repository-provided `.claude/settings.json` in that project is eligible to approve anything. The count is stated because it is a hard rule rather than a minimisation: the same object carries `lastSessionFirstPrompt`, the literal text of the last thing the user typed at the client. The code decodes into a struct naming only those two arrays, which cannot reach it, and a test asserts the property from the outside.

Codex's `trust_level` is read from its project table for the same reason and under the same rule: it is a closed enum rather than free text, it decides whether that project's `.codex/config.toml` is consulted at all, and nothing else in the table is decoded.

Inside a contained project, **only the files belonging to the clients that recorded it** are probed:

| Recorded by | Files probed |
|---|---|
| `~/.claude.json` → `projects` | `.mcp.json` |
| `workspaceStorage` → `folder` | `.vscode/mcp.json`, `.cursor/mcp.json` |
| `~/.codex/config.toml` → `[projects."…"]` | `.codex/config.toml`, and only when the project is trusted |

That mapping is the point, not an optimisation. Probing all four files in every project used one client's evidence that a directory is a project to justify reporting a *different* client's configuration in it — so a directory known only to Codex produced a `vscode` row because a dormant `.vscode/mcp.json` happened to sit there, with nothing establishing that VS Code had ever opened the directory. Deduplication keeps the full set of discovering clients, so a project in two histories is probed for both.

The consequence worth knowing: **a home that is itself a recorded Claude project no longer activates other clients' project files.** `~/.vscode/mcp.json` is found only if a VS Code fork recorded the home as a workspace. That is the evidence-based answer and it is narrower than before.

**Codex trust gates its project config.** Codex skips every project-scoped `.codex/` layer for a project marked untrusted, so a `.codex/config.toml` there declares servers Codex will not load. Trust comes from `trust_level` in the `[projects."…"]` table and is matched positively against `trusted`: an unrecognised value, or an absent one, fails closed and is reported rather than assumed, since Codex's own default is to ask.

**This replaced a filesystem walk, and the trade is worth understanding.** The walk covered about 22 directories per home to depth 6 under a time budget shared across every account. It worked and it was wrong in four ways. Results changed between runs, because the first account's source tree could exhaust the shared budget and decide what the second account's rows were. It downloaded files: `~/Documents` and `~/Desktop` are iCloud-backed under "Optimise Mac Storage", and reading a dehydrated file is a synchronous network fetch, so an inventory query pulled a user's documents down from the network. It blocked: one dead mount, offline network home or Windows oplock stalled the walk and everything osquery had scheduled behind it. And a walk finds *files* rather than *configuration* — on one workstation 39 of 51 rows from one client came from a plugin marketplace cache, installable catalog entries nobody had enabled, excluded afterwards by a list of path substrings maintained by noticing each new cache directory after it polluted the table.

What it costs: **a project the user has never opened in a participating client is invisible to this table.** So is a project recorded only by a client there is no lister for. The exclusions are gone too, and nothing replaces them, because a marketplace cache is not a project anyone opened.

One behaviour deliberately changed direction. A project recorded under `node_modules` *is* probed now, where the walk pruned it. A client does not record `node_modules` unless the user genuinely opened an editor there, and if they did, that project's MCP configuration is a real thing the editor will act on.

### Known omissions

**Some are covered elsewhere.** Fleet's orbit has an `ai_tools` table that reads Zed, Continue and Roo from the list below, plus Jan, so a Fleet user already has a form of what this table delivers for that software. (Parity is not currently our goal: in a field this volatile, all of this tooling may change or vendors themselves may abandon products over time.)

Each of these is a client the table does **not** read. They are recorded with their paths so adding one is mechanical, and marked with how the path was established, because a documented path that is wrong is worse than an acknowledged gap.

**Verified present on a development machine and still unread.** Both were found by running the table and comparing its output against a live session, and both would be two probes plus a thin extractor:

| Client | Path (all platforms) | Key | Note |
|---|---|---|---|
| [Amp](https://ampcode.com/manual) (Sourcegraph) | `~/.config/amp/settings.json` | `amp.mcpServers` | A literal dotted key at the top level, not a nested object, so the existing envelope extractor finds nothing. Uses `~/.config` on every OS rather than the per-platform application-support root. |
| [Zed](https://zed.dev/docs/ai/mcp) | `~/.config/zed/settings.json` | `context_servers` | Zed's own name for MCP servers. JSONC. Its sibling `agent_servers` is **ACP**, a different protocol for driving coding agents, and is deliberately out of scope — reporting it would make `client` and `transport` describe two protocols. |

**Documented by the vendor, not verified against an install.** Paths are from vendor documentation; none has been confirmed on a machine with the client installed, which is why none is implemented:

| Client | User-scope path | Project-scope path | Key |
|---|---|---|---|
| [Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/) | `~/.qwen/settings.json` | `.qwen/settings.json` | `mcpServers` |
| [Amazon Q Developer CLI](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/qdev-mcp.html) | `~/.aws/amazonq/mcp.json` | `.amazonq/mcp.json` | `mcpServers` |
| [JetBrains Junie](https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html) | `~/.junie/mcp/mcp.json` | `.junie/mcp/mcp.json` | `mcpServers` |
| [LM Studio](https://lmstudio.ai/docs/app/plugins/mcp) | `~/.lmstudio/mcp.json` | — | `mcpServers` (Cursor's notation) |
| [Roo Code](https://docs.roocode.com/features/mcp/using-mcp-in-roo) | `<appsupport>/<fork>/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `.roo/mcp.json` | `mcpServers` |
| [Kilo Code](https://kilocode.ai/docs/features/mcp/using-mcp-in-kilo-code) | `<appsupport>/<fork>/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | — | `mcpServers` |
| [Warp](https://docs.warp.dev/agent-platform/capabilities/mcp/) | `~/.warp/.mcp.json` | `.warp/.mcp.json` | `mcpServers` |
| [Warp Agent CLI](https://docs.warp.dev/agents/cli/configuration/) | `~/.warp_cli/.mcp.json` | — | `mcpServers` |
| [Continue](https://docs.continue.dev/customize/deep-dives/mcp) | `~/.continue/config.yaml` | `.continue/mcpServers/*.yaml` | `mcpServers` — **YAML**, which this table has no parser for |
| [opencode](https://opencode.ai/docs/en/mcp-servers/) | `~/.config/opencode/opencode.json` (or `.jsonc`) | `opencode.json` / `opencode.jsonc` at the project root | `mcp` — see the note below, the entry shape differs from every other client here |

Roo Code and Kilo Code are Cline forks and sit in VS Code extension storage, so they are the same shape as the `cline` probe already present — the cheapest of these to add. Continue is the most expensive: it needs a YAML reader, and an earlier version of this README claimed the path was `~/.continue/mcpServers/*.yaml`, which is the *project* scope; the user-scope file is `~/.continue/config.yaml`.

[opencode](https://opencode.ai/docs/en/config/) is worth four separate notes, because almost nothing about its entries matches the shape the rest of this table assumes. Its key is `mcp`, not `mcpServers`. `command` is a single **array** combining the executable and its arguments, where every other client here splits them into `command` and `args` — so `command_basename` and `args_count` would both have to be derived from one field. Environment variables are under `environment` rather than `env`. And it spells the state `enabled` rather than `disabled`, the same inversion Codex uses and which this table already reads correctly for that client: a config carrying `enabled = false` must not be reported as an enabled server.

Its project-scope file is also unusual in being at the project **root** rather than inside a dotdir — `opencode.json`, beside `go.mod` and `package.json` — which means a project probe for it cannot rely on the dotdir convention the other four project probes share.

One thing about opencode sits outside this table's model entirely. It reads a machine-wide config as well as a per-user one: `/Library/Application Support/opencode/` on macOS, `/etc/opencode/` on Linux, `%ProgramData%\opencode` on Windows. Every source this table reads is inside a user's home, because the table's unit is an account and its containment guarantee is anchored to a home directory. A system-managed MCP server would belong to no account, so supporting it is a schema question — which `user` would such a row carry? — and not a path question. Both `OPENCODE_CONFIG` and `OPENCODE_CONFIG_DIR` can relocate the per-user config too, which is the same limitation already recorded for `XDG_CONFIG_HOME`: the environment belongs to the daemon's account, not to the account being scanned.

**Popular and structurally unreadable: [Crush](https://github.com/charmbracelet/crush).** Charm's terminal coding agent is widely used — 28.5k GitHub stars as of October 2026 — and it is the one client on this list that could not be supported by adding a probe, because it has no declarative configuration file to read. Its config is `crushrc`, which is *Bash* with Crush-specific builtins, and MCP servers are registered imperatively:

```bash
mcp add github \
  --type http \
  --url "https://api.github.com/mcp/" \
  --header Authorization "Bearer $(op read 'op://my-secret-key')"
```

Read in priority order from `./.crushrc`, `./crushrc`, then `~/.config/crush/crushrc` (XDG-respecting, and overridable entirely by `CRUSH_GLOBAL_CONFIG`). There is a JSON form keyed on `mcp` under the `https://charm.land/crush.json` schema, but the documented search path names only `crushrc`.

Recovering the server list would mean either executing the script — which is out of the question, since it runs arbitrary shell as the user, and the vendor's own example shells out to 1Password for a bearer token — or implementing enough of a Bash interpreter to evaluate it statically. Neither is a probe.

Two things are worth taking from this rather than just recording it. First, `~/.local/share/crush/crush.json` exists and looks like a config file, and is not one: Crush's documentation calls it ephemeral state that "should not be edited by hand, nor should it be considered configuration", and notes that `$(...)` inside it also runs at load time. Reading it would report state as configuration. Second, that `$(op read ...)` example is a concise argument for why this table reduces rather than reports: a client can legitimately hold a credential as a *command to run*, so a field that looks inert can be a secret one shell expansion away, and the only safe thing to publish is the shape of the value and not the value.

Crush is not installed on the machine this was developed against, so none of the above is verified against a real `crushrc`.

Two caveats worth carrying. LM Studio's documentation says `~/.lmstudio/mcp.json`, but its own bug tracker records the file appearing at `~/.cache/lm-studio/` on some macOS versions, so that one needs checking on a real install rather than trusting either path. And one more activation route is unaccounted for entirely: a client can be handed a config on the command line — Claude Code's `--mcp-config` is the example — and a server configured that way exists in no file this table could find.

**Other limits of what is read:**

- **A multi-root `.code-workspace`** records `workspace` rather than `folder`. Only `folder` is read.
- **`~/.claude/**/mcp.json`** had no documented path and was speculative.
- **`XDG_CONFIG_HOME` on Linux** is assumed to be its default. The variable can name any absolute directory and Electron resolves a VS Code fork's userData under it, so an account that sets it keeps its configuration somewhere this never looks. Reading the variable is not available: the environment belongs to the daemon's account.
- **Codex's literal `http_headers`** has no reader, deliberately. Its values are credentials by design.
- **Per-project plugin enablement.** Only the user-scope `~/.claude/settings.json` is read, so a plugin enabled or disabled in a project's own `.claude/settings.json` or `.claude/settings.local.json` is reported at its user-scope state.

## Containment

Every path recorded in a configuration file is a path a user controls, so containment is established rather than inherited. In order:

1. **Origin.** A `file://` URL is accepted only for `workspace.json`'s `folder` field, and only when the scheme is exactly `file`, there is no opaque body, and the host is empty or `localhost`. `file://server/share` is a UNC path, and opening it would make this host authenticate to a server named in a file the scanned user controls — a recorded project path becoming an outbound credential. `vscode-remote://`, `ssh-remote://`, `wsl+…`, `docker://` and `http(s)://` all name a filesystem that is not this one.
2. **Decoding.** Only a `file://` origin is decoded, and `url.Parse` does it: it percent-decodes into `URL.Path`, which is the form used from there on, so there is no second decoding pass. A bare recorded path — the common case, since `.claude.json` and Codex record plain paths — is taken literally, because a directory named `100%` is ordinary and decoding it would invent a different one. The ordering still matters and is why the refusals below run afterwards: `%2e%2e%2f` arrives as `../`, so the `..` check has to see the decoded form.
3. **Shape.** Empty, NUL, any ASCII control character, and any non-absolute path are refused.
4. **Traversal.** Any `..` component is refused, inspected *before* `Clean`, because `Clean` collapses `/home/alice/../bob` into a path that looks ordinary afterwards. Trailing separators are tolerated; recorded paths carry them.
5. **Relativity.** The path is reduced to a form relative to the home, refusing anything that resolves above it. `.` is allowed: a home is frequently itself a recorded project, and `~/.mcp.json` is a real configuration file.
6. **The read.** The absolute path is never opened. Every read re-walks the relative form from the home down, opening each component with symlinks refused, which is what makes step 5 a guarantee about the bytes rather than a string comparison that happened earlier — a project directory that was inside the home when it was checked and is a symlink by the time it is opened fails the open.
7. **Cloud placeholders.** Two rules, because they fail differently. A **prefix** rule refuses the directories a sync provider conventionally owns, as a string comparison before anything is opened: `Library/Mobile Documents` and `Library/CloudStorage` on macOS, and `OneDrive` (including the `OneDrive - <Tenant>` business form), `Dropbox`, `Google Drive` and `iCloudDrive` on Windows. These are per-platform conventions and are applied only on their own platform. An **attribute** rule then refuses a file the platform marks non-local — `SF_DATALESS` on macOS, `RECALL_ON_DATA_ACCESS` / `OFFLINE` / `RECALL_ON_OPEN` on Windows — read from the open descriptor rather than by path, so an intermediate symlink cannot redirect the lookup.

   Reading a placeholder is not a read; it is a download of unbounded duration, charged to a scheduled query, that leaves the machine different from how it was found.

   **Linux answers a different question, because it cannot answer this one.** The two services the rules above were asked to handle have no Linux client — iCloud Drive has none, OneDrive none official — and Dropbox's Linux client syncs fully or selectively rather than leaving placeholders, so an unsynced file there is simply missing and reads as expected absence. What does exist is FUSE on demand: `rclone mount`, `google-drive-ocamlfuse` and `onedriver` fetch content when a read arrives. A FUSE filesystem carries no attribute saying in advance whether a given file's content is local, so the attribute rule has nothing to read, and a Linux directory named `Google Drive` is an ordinary directory, so the prefix rule would over-refuse without evidence.

   So the question asked instead is which filesystem the descriptor is on. `fileOnUserspaceFilesystem` runs `fstatfs` on the open handle before any read — from the descriptor, not the path, for the same reason every other check here does — and refuses `FUSE_SUPER_MAGIC` with `ErrUserspaceFilesystem`. That classifies as `ClassUserspaceFilesystem` and reports `project_userspace_filesystem`, which **degrades completeness**: the project was in scope and was not read. Nothing bounds a read already in progress, which is what makes a pre-read check the only workable point — the query deadline is consulted between operations rather than inside a syscall, and closing the descriptor from another goroutine cannot interrupt a blocked read on a regular file.

   This over-refuses, in the same way and for the same reason the prefix rules do. FUSE is not only cloud storage: sshfs, gocryptfs and AppImage mounts are all FUSE, and a project on one of those is refused even though its content is local. That is acceptable only because the refusal is reported — the row names the filesystem and marks the scan incomplete — so an operator sees the coverage they lost rather than reading an empty result as an absence of servers. Network filesystems are deliberately **not** included, though the NFS and SMB magics are equally reachable: an NFS-mounted home is the ordinary arrangement in a managed fleet, so refusing on it would inventory nothing at all for those accounts, and what makes a dead NFS mount dangerous is that a read can block rather than that it can download. That is a separate problem with a separate remedy.

   The prefix rule over-refuses deliberately: a project inside one of those directories is refused even when its files are fully hydrated, which "Always keep on this device" makes common. It is reported rather than dropped, and it buys the one thing the attribute rule cannot. `FILE_ATTRIBUTE_RECALL_ON_OPEN` is by definition set on files whose provider begins fetching at `CreateFile`, and `os.Root` exposes no `FILE_FLAG_OPEN_NO_RECALL` — so a descriptor-based check learns that attribute only after causing the download it exists to prevent. The string rule runs first. What remains uncovered is a `RECALL_ON_OPEN` placeholder somewhere no provider conventionally owns; closing that needs a metadata lookup anchored to the parent directory's handle, which would be new unexercised code on the platform with no CI.

Reads also refuse a file with more than one hard link. **This can drop rows on a benign host** — dotfile managers link configs into place, and pnpm and Homebrew link package contents — which is why the refusal is reported rather than silent: `project_read_refused` with a reason, never swallowed as absence.

### How refusals are reported

| Outcome | Reported as |
|---|---|
| Project directory deleted, or has no MCP config | **Silent.** The common case by a wide margin — three of thirty recorded projects on the development machine no longer exist, because a project list is a history of what was opened and nobody prunes it. One row each would be most of this table's output. |
| Project outside the home | Counted, **with no path.** A path inside a user's home is not publishable, so a diagnostic naming the directory would reintroduce the disclosure the columns are narrowed to prevent. |
| Project on another host | Counted, no path. |
| Cloud placeholder | Counted. A configuration exists and this scan declined to download it. |
| Hard link or owner refusal | **Never silent.** That one is a finding rather than an absence. |

## Columns

Twenty columns.

| Column | Meaning | Format enforced |
|---|---|---|
| `user` | Account name, from osquery's `users` table | none — it is the join key |
| `user_id` | uid on POSIX, SID on Windows | `^(S-1-[0-9-]+\|[0-9]+)$` |
| `source_path` | Absolute path of the file the row came from | structural only (see below) |
| `source_context` | Where in the file the server was declared | closed token set, or `projects[P].mcpServers` with `P` contained |
| `client` | Which client owns the configuration | closed set |
| `server_name` | The name the configuration gives the server | redaction, with a placeholder fallback |
| `transport` | `stdio` \| `http` \| `sse` \| `unknown` | closed set |
| `command_basename` | Executable name only — no directories, no arguments | `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, ≤ 64 bytes |
| `args_count` | Length of the `args` array as written | integer |
| `url_endpoint` | Scheme and host only | scheme in `{http,https,ws,wss}`, host hostname-shaped or bracketed IPv6 |
| `env_keys` | JSON array of variable **names**; values are never read | each `^[A-Za-z_][A-Za-z0-9_]*$` |
| `package_manager` | `npx`, `uvx`, `docker`, `mcp-remote`, … | closed set |
| `package_name` | The package the launcher installs | npm/PyPI or Docker name grammar |
| `requested_spec` | The spec as written, including any pin | package spec, Docker ref, or a validated endpoint |
| `pinned_version` | The version **the configuration pins** | `^[A-Za-z0-9][A-Za-z0-9.+_~*-]*$` or `sha256:<64 hex>` |
| `confidence` | `low` \| `medium` \| `high` | closed set |
| `disabled` | `1` when the configuration file says disabled | integer |
| `approval_state` | `enabled` \| `not_approved` \| `disabled` \| `unknown` \| `not_applicable` | closed set |
| `scan_complete` | `1` when this row's source was listed in full by an enumeration that finished | integer |
| `warning` | What was not listed, and why | built from a closed catalogue |

`pinned_version` was called `version`, which invited the wrong reading. It is what the file pins, never what is installed: `npx` resolves `@1.2.3` itself and may resolve it elsewhere, and an absent pin means unpinned rather than unknown. It is text and compares as text, so `'1.10.0' < '1.9.0'` — compare exact values and sort in whatever consumes the rows.

`approval_state` has a fifth value, `unknown`, and the distinction from `not_approved` is load-bearing. `not_approved` is a positive finding: the client recorded its decisions and this server was not among them. `unknown` means the evidence does not support a positive finding either way, so the server may well be live. Collapsing the two reported "not approved" about a server nobody had declined, which fails in the direction an inventory must not: it invites ignoring a server that is running.

Three situations produce `unknown`. The first is a record that could not be read — malformed settings, an undecodable project entry. The second is a record that read cleanly from a source whose *eligibility* is uncertain: `.claude/settings.local.json` is honoured only for a trusted project, and trust lives in git state this table does not consult. Where such a file contradicts a lower-precedence one, both readings are live — if the file counts its value wins, and if it does not the account-wide value does — so neither may be published as fact. Resolution therefore runs twice, once with the uncertain source and once without, and reports `unknown` only when the two disagree. An uncertain source that agrees with the certain evidence, or says nothing about this server, changes nothing; a rejection anywhere is decisive, since nothing promotes a server the user declined. The third is a plugin version that is cached but is not the installation the client would load: Claude keeps the previous version's directory for fourteen days after an update so a session that already loaded it keeps running, so such a server may genuinely still be live in somebody's open session while no new session would load it. Each case carries its own warning code, so `unknown` is never the whole answer a row gives.

`approval_state` is separate from `disabled` on purpose. Claude Code treats a server declared in a project's `.mcp.json` as inert until the user approves it, so `disabled = 0` on an unapproved server was a false positive in a security inventory. `disabled` means "the configuration file said disabled", which is a fact about the file; approval is a fact about the client's state, and a user who has neither approved nor rejected a server is in neither of that column's two values. Folding them together would make one column mean different things depending on the client.

### `scan_complete`, and what `warning` is for

`scan_complete = 1` means: every server declared in this row's `source_path` was listed, **and** the enumeration that found that source ran to completion.

It is `0` at two scopes. A *source*-level loss — entries that would not decode, a file over its size cap, a malformed sibling — marks the rows of that file only. A *home*-level loss — an exhausted budget, a cancelled query, an unreadable home, an undetermined AppData location, an unreadable or over-cap project list, a cloud placeholder, a refused file — marks every row for that account, including rows from files that were read perfectly well, because the question is not "was this file parsed" but "is this list of servers the whole list". Diagnostic rows are always `0`.

A *descriptive* finding does not degrade it either. A dropped environment key or a literal TOML header value means one optional column is empty and the warning explains why; every server the file declared is still listed, so the row is a complete listing of its source. The computation follows the warning's classification rather than the mere presence of a warning.

What does **not** make a row incomplete is the table's own scope boundary. A recorded project outside the home, on another host, or at a path that is not a usable absolute path is reported and counted, but the rows are still complete: those are the definition of what is searched rather than a scan cut short, the same way a project the user never opened is silent. Opening a project outside your home is ordinary — `/tmp`, `/Volumes`, a shared checkout — and once you have, the client's project list records it permanently, so treating it as a loss would pin `scan_complete` to `0` for that account forever and make the predicate useless.

`WHERE scan_complete = 1` is therefore the completeness predicate, and `warning` is purely descriptive. That closes a real gap: `warning = ''` selects the healthy servers and discards the diagnostic that said the list was short, so before this column a truncated scan and a host with nothing on it gave the same answer.

### The warning catalogue

`warning` is assembled only from a fixed sentence chosen by code, decimal integers, closed-enum spellings, and — in one case — a configuration key that has passed `^[A-Za-z_][A-Za-z0-9_.-]*$`. There is no fifth source.

That is not fastidiousness. Four columns were built by concatenating an error message, and both parsers quote the input they failed on: BurntSushi's `ParseError.Message` carries `found "…"`, so an `env = { TOKEN = abc123 }` put the token in the column verbatim, and `encoding/json` names the offending value. What is read instead is position — a line number from TOML, a byte offset from JSON — because those are integers, they are what an operator needs to go and look, and neither can carry a secret. TOML's `LastKey` is also user bytes, since the format permits quoted keys, so it passes the identifier grammar before being reported.

Codes group as: roster and per-account omissions; one home's enumeration (budget, cancellation, unreadable home, AppData, profile and project lists); one source file (unreadable, over cap, parse failure, entries skipped); and one column of one row dropped by its allowlist. Only the last group leaves `scan_complete` at `1`, because a dropped column means one field of a listed server is empty rather than a server being missing.

### The redaction contract, and what it does not cover

Credentials are removed from the places they are *routinely* found, and the limit is stated rather than implied.

- **`args` is never emitted** — only counted. Arguments routinely carry opaque tokens no pattern detects.
- **`command` is never emitted** — only its basename, which drops every directory component and any whitespace-embedded arguments. `/opt/--dd-key=<secret>/bin/tool` arrives as `tool`.
- **`url_endpoint`** keeps scheme and host; path, query, fragment and userinfo are dropped, then the remainder must match a host grammar.
- **`env_keys`** carries names; values are never extracted.
- Known token shapes are replaced with `[REDACTED]`, as is the value of any flag-style assignment whose option name announces a credential (`--token=`, `--api-key=`, `--dd-key=`) wherever in a field it appears.
- Every free-text column has a **positive grammar**, and what does not match is dropped with a code saying so.

`server_name` has a grammar too, and was the last column to get one: it was checked only negatively — empty, the redaction marker alone, a control character, too long — so a configuration whose server *key* was `API_KEY=opaqueValue` or `Authorization: Bearer opaqueValue` published it verbatim with no warning. It now takes the same shape as `command_basename`, and a name that fails it gets the positional placeholder rather than being emptied. A name redaction has already cleaned keeps its marker: `release-[REDACTED]` publishes, while `API_KEY=[REDACTED]` still does not, because only the marker is forgiven and not the text around it.

**Residual risk.** Redaction recognises *known* shapes, so an opaque secret with no structure passes through it. Two columns have no grammar available:

- **`source_path`** is a filesystem path whose directory names the user chooses, and an allowlist of directory names cannot exist. It keeps redaction plus a structural assertion — absolute, already clean, under the home. **A user who names a directory after an opaque secret puts it in this column.**
- **`user`** is the join key. Constraining it would break `WHERE user = '<name>'`.

An earlier version of this table argued that narrowing the free-text columns was unsound applied to one while others kept the property, and that applied to all of them it would remove the table's purpose — citing `terraform-mcp-server` and `computer-use-client-launcher` as basenames no allowlist would contain. The first half was right, and is why all of them were narrowed together. The second half confused an allowlist of *names* with an allowlist of the *format* a name has: both of those pass unchanged, while `API_KEY=xyz npx -y pkg` does not, because a filename cannot contain an equals sign.

Two losses that follow from that, stated rather than buried. A **non-ASCII basename is dropped**, because admitting Unicode letters reopens homoglyph confusion — `nрx` with a Cyrillic er reads as `npx` in any console. And an **unrecognised launcher option empties the identity triple** for that row at `confidence = low`: an unlisted option may or may not consume the token after it, and `npx -y --pat <secret> pkg` otherwise reported the secret as the package name. A legitimate unlisted boolean now costs its row the package columns, which is a missing answer where the alternative is a confidently wrong one.

### When `server_name` cannot be published

If redaction empties the name, leaves only the marker, or the name carries a control character or exceeds 256 bytes, the column reports `[redacted:<source path relative to the home>]`, with `#2`, `#3` appended only when one file yields more than one such name, ordered by raw name so it is stable across runs.

Positional, not hashed. A server name is short and drawn from a small vocabulary, so a truncated digest is brute-forceable offline — the oracle this must not be. The trade: this traces to "which file, go and look", and deliberately does not answer "is this the same server as last week". Durable fleet-wide correlation needs a stable pseudonym, and a stable pseudonym is the attackable thing.

## Query budget

`MACADMINS_EXTENSION_WALK_TIMEOUT` accepts a Go duration and bounds the whole query, shared across every account rather than granted per account — sized against osquery's watchdog on the assumption that one query costs one budget. Giving each home its own turns that into homes × budget, and a shared Mac with a handful of accounts then gets the whole extension killed, dropping every other table's rows.

An account the budget never reached says so under its own name rather than stopping quietly, because a user who was never scanned and a user with no MCP configuration are otherwise the same empty answer.

The name is now a misnomer: nothing walks. It is kept because it is a documented environment variable an operator may already have set.

## Size caps

Sources are read with a 1 MiB cap, except `~/.claude.json`, which gets 4 MiB.

That one exception matters because the file is both a source of servers and the project list, so an oversized one costs the account every project-local configuration and the whole approval state, not just its `claude_code` rows — and the size is driven by something no operator can reason about. Measured on the development machine: 94,827 bytes, of which 43% is `cachedGrowthBookFeatures`, the client's own feature-flag cache. 4 MiB is roughly forty times the real file. The cost is real: `json.Unmarshal` of a 4 MiB document allocates several times that, per account, per query. Exceeding either cap is reported with the actual size and the limit, and an unreadable project list degrades the whole home.

## Platform notes

**The account roster comes from osquery's own `users` table**, not from enumerating a directory, so it is the same list an operator joins against: OpenDirectory on macOS, the local account database on Windows, `/etc/passwd` on Linux. There is no filesystem fallback — the socket is how this extension returns rows at all, so if it cannot be reached osquery is not receiving results either.

**Linux: local accounts only.** osquery's `users` table hides an `include_remote` column defaulting to 0, so accounts served by LDAP, SSSD or another directory are absent. Their homes are often the ones carrying the configuration this table looks for. Setting `include_remote` would enumerate an entire directory on every scheduled query, which osquery itself warns can be extremely expensive, so the local roster is used and **this limit is documented here rather than emitted as a row**. An earlier version raised a warning on every Linux run, which made `warning` non-empty on every Linux host whether or not anything was wrong — so the one predicate an operator would write to find real problems matched every host in the fleet. A condition true of every run is a property of the table, and this is where a property of the table belongs. Per-account reporting is unaffected: a name the roster never mentioned still gets a row saying so.

**Linux: refused by filesystem type, not by placeholder attribute.** The prefix and attribute rules above are macOS and Windows only, because neither has a Linux counterpart. A project on a FUSE mount is refused by an `fstatfs` check instead and reported as `project_userspace_filesystem`, which over-refuses sshfs and gocryptfs deliberately and says so. Network filesystems are not refused. See the cloud-placeholder step above.

**Windows is untested.** There is no Windows CI job, so `go vet` and cross-compilation are the only automated checks that see the Windows code. What has been exercised on a real host: bounded reads under a user profile, root enumeration, a junction planted at a probed path being refused, and Roaming AppData resolution for a logged-on account. What has not: `NumberOfLinks`, the `RECALL_ON_*` placeholder check, and `file:///C:/` decoding. Platform-specific decisions are parameterised by GOOS so both branches run from any host, leaving only the syscall at the boundary.

Two Windows behaviours are deliberate rather than incomplete. **Only a mounted registry hive is read** — a logged-off account's `NTUSER.DAT` is not loaded, because an inventory query should not mount a registry hive, and the API for it creates the file when absent, so a read could write. An account whose hive is not mounted falls to the existing "location could not be determined" diagnostic. And **owner verification is not implemented**: a read asked to verify an owner on Windows is *refused* rather than passed, so a caller cannot believe a check ran that did not. This table does not ask for it and relies on the hard-link refusal instead.

## Completeness query

```sql
-- Servers an operator can trust
SELECT user, client, server_name, command_basename, package_name, pinned_version
FROM mcp_servers
WHERE scan_complete = 1 AND server_name != '';

-- Everything that was not listed, and why
SELECT user, client, source_path, warning
FROM mcp_servers
WHERE warning != '';
```

## Narrowing by user

A `user` constraint reaches the generator and narrows the scan under osquery's default `--extensions_default_index=true`, which promotes extension columns to `INDEX`. Equality only, and all of it or none: `user = 'alice' OR user LIKE 'b%'` scans every home and filters afterwards, because `QueryContext` does not carry enough of the original boolean structure to prove the equality subset is sufficient. Scanning more than asked costs time; returning fewer rows than the query matches is a wrong answer.

The filter is applied to the roster *before* any filesystem call. Narrowing afterwards still stat'd every home on the host, so one dead automount belonging to an account nobody asked about could consume the budget of a query scoped to a single local user.

Diagnostics are attributed to the narrowest account they apply to, so a constrained query still receives the ones that concern it. A roster-level failure is repeated under every name the query asked about, rather than emitted once with an empty `user` that the constraint would discard.
