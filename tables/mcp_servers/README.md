# `mcp_servers`

[Model Context Protocol](https://modelcontextprotocol.io/specification/latest) servers configured per user and client, read from each client's own configuration files.

One row per declared server, plus diagnostic rows describing anything that was not listed. The root `README.md` has a short description and a `Notes` pointer, with the detail here.

## Sources

Every path is relative to a user's home directory. The application-support root resolves per platform — `~/Library/Application Support` on macOS, `%APPDATA%` (`~/AppData/Roaming`) on Windows, `~/.config` on Linux — and is reconstructed from each home rather than read from the environment, because the environment belongs to the daemon's account and not to the account being scanned.

### Fixed paths, probed once per account

| Client | Path | Format | Vendor documentation |
| --- | --- | --- | --- |
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

Two locations put a name the application generates between a fixed path and the configuration file, so no fixed path can reach them. Each is one `ReadDir`, no recursion, capped, with symlinks refused at every component. An absent directory, or one with a regular file partway down its path, is silent; one reached through a symlink is a `profile_directory_unreadable` row with `reason=refused_path`:

- `<appsupport>/<fork>/User/profiles/<generated-id>/mcp.json` — a user with a work profile and a personal profile keeps a different server list in each, and neither is the user-scope file above.
- `~/.codex/<profile>.config.toml` — Codex named profiles. The `.codex` parent is required rather than matching `config.toml` anywhere, because that basename is among the most common on a developer machine.

### Claude Code plugins

A [plugin](https://docs.claude.com/en/docs/claude-code/plugins) can ship its own `.mcp.json`, and those servers are live. Installed plugins sit at:

```text
~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.mcp.json
```

All three directory names are chosen by the marketplace rather than derivable, so this is three bounded listings, capped per level and against a total probe budget. Only directories count: each listing reads at most 500 entries and keeps the directories among them, so a `.DS_Store` or any other file at a level is neither a plugin nor a version and spends no cap. On Windows that includes a file a storage provider placed as a reparse point, such as a Cloud Files or WOF-compressed file, which is not counted as a link. A level that is a symbolic link is not listed through and is a `plugin_list_unreadable` row with `reason=refused_path`, as the refusal table below says.

**Every installed plugin is probed, and enablement is reported rather than filtered.** [`~/.claude/settings.json`](https://code.claude.com/docs/en/settings) carries `enabledPlugins` as an object of `"<plugin>@<marketplace>": bool`, which gives three distinct states, and `approval_state` has a value for each:

| In `enabledPlugins` | `approval_state` |
| --- | --- |
| `true` | `enabled` |
| `false` | `disabled` — turned off deliberately |
| absent | `not_approved` — installed, never enabled |

A plugin someone installed and forgot is a thing a security inventory should show, which is why these are listed rather than dropped. Settings that exist and cannot be read give `unknown` rather than `not_approved`; settings that are *absent* give `not_approved`, because a user who never enabled a plugin genuinely has no such file.

**`~/.claude/settings.local.json` is deliberately not read.** Claude Code's documented precedence places it at *project* scope — managed, then command line, then project-local `settings.local.json`, then shared project `settings.json`, then user `settings.json` — and there is no user-scope version of it. The file appears in a home whenever that home has been opened as a project, which is common, so reading it applied one project's overrides to every plugin row for the account.

**The enablement settings and installation records are read only when a plugin is installed.** `~/.claude/settings.json` and `installed_plugins.json` describe plugins, so they are read once the cache holds at least one version directory, and an account with no plugins gets no `plugin_settings_unreadable` or `plugin_records_unreadable` row for a malformed copy.

**A cached version is not evidence that the client would load it.** `installed_plugins.json` is the record Claude Code itself loads from, keyed `<entry>@<marketplace>` and holding each install's scope, installPath and version. It is read, because the cache keeps old versions: on update or uninstall Claude writes an `.orphaned_at` marker into the previous version's directory and deletes it in a background sweep fourteen days later, so a session that already loaded it keeps working. A cached directory that the records do not point at, or that carries the marker, reports `approval_state = 'unknown'` with `plugin_version_superseded` rather than inheriting the plugin's enabled state — for two weeks after any update, a server deleted in the new release was otherwise still reported as `enabled`. The row is kept rather than dropped, because a running session may still hold that server; what is withdrawn is the claim that it is enabled.

Where selection simply could not be established — an orphan marker that could not be read, records that could not be read, a record carrying no `installPath` — the row reports `plugin_selection_unknown` instead. Only one of those three is a records-read failure, and that one is reported in its own right at account level, so the row names what it does not know rather than guessing at a cause.

**Selection is established from `installPath`, not from the version string.** A version names a *release* and more than one directory can carry the same label — a relative-path plugin loaded in place, a relocated cache, a leftover copy — so matching on it treated any directory labelled `1.0.0` as selected even when the record pointed elsewhere. `installPath` names the filesystem copy the client resolved, which is the question being asked. Paths are compared as written rather than case-folded, and a record carrying no `installPath` establishes nothing: both read as `unknown` rather than as selected, since the cost of that is a qualified row and the cost of the other direction is a false `enabled`.

**Servers declared in the plugin manifest are read as well as `.mcp.json`.** `.claude-plugin/plugin.json` may carry `mcpServers` as an inline map, a `./*.json` path, or an array mixing them, and Claude loads `.mcp.json` first and then each declared shape in order, with a later server name replacing an earlier one. All three forms are read and that precedence is preserved, so a manifest that renames or redefines a server reports what the client would actually run. Two documented forms are refused and reported with `plugin_manifest_unsupported`: a `.mcpb` or `.dxt` bundle would have to be unpacked, and a bundle URL fetched, before either could say what it declares — one is an archive extraction driven by a file the user controls, the other a network request to a host named in it, and neither belongs in a scheduled query. Declared paths are re-checked for containment here rather than trusted, and a path containing a backslash is refused outright because the documentation makes such a path load on Windows only. A declared path whose absolute form is longer than 1,024 bytes, the bound a recorded project's path has, is not read and is counted in a `plugin_manifest_path_too_long` row on the manifest, so a 1 MiB manifest cannot put most of a megabyte into `source_path`. A file the manifest *names* and that cannot be read is reported with `plugin_manifest_missing_source`, which is the opposite policy from the root `.mcp.json`: most plugins ship no root config, so its absence is the common case and silent, while a declared path is documented to have to exist and its absence is a broken reference. A root `.mcp.json` that exists and cannot be read is reported as any configuration file is, `source_unreadable` with the reason or `source_too_large`, naming that file. Each manifest finding is plugin scope: that plugin version's server rows read `scan_complete = 0`, because the client may load a definition this scan did not read, and no other plugin's rows change.

**A declaration that cannot be read qualifies the definition it would have replaced.** Precedence is by declared name, but the merge can only key on names it decoded, so a manifest declaring `"srv": {"command": 123}` would otherwise leave the root `.mcp.json`'s `srv` standing as a clean, enabled row, a definition a higher-precedence declaration overrode with something unreadable. When a later source in the same plugin fails at source scope, the rows from earlier sources read `scan_complete = 0` and carry `plugin_declaration_shadowed`. The qualification is applied *before* that source's own declarations are merged, so a name it successfully redefines overwrites the qualified row and carries nothing from it — only a name the failed source did not replace stays qualified. The code is source scope, because it describes one file's authority, so another client's rows are unaffected. The rows are qualified rather than dropped, and rather than resolved: this table cannot tell whether the client rejected the bad entry and kept the old one or replaced it, so the honest row is the old definition marked as possibly stale. The scope is coarse by name and exact by precedence — the extractor reports a failed envelope without naming the entries inside it, so which names were shadowed is not recoverable, while which rows are lower precedence is.

**A manifest element of the wrong type is reported, not skipped.** `mcpServers` accepts a path, a map, or an array of either; an element that is a number, a boolean or a nested array is a malformed value in a field this table reads, and `claude plugin validate` treats such a type mismatch as a load-time failure. It reports `plugin_manifest_invalid_declaration` and the sibling elements that did parse are still listed. A JSON `null` or an empty map stays silent, because declaring nothing is not the same as being malformed.

**Manifest declarations are bounded separately from the plugin probe cap.** That cap counts cached version directories, and a manifest adds reads underneath one of them, so without a second bound a single manifest could name thousands of independently capped files and the accepted byte and row totals were unbounded while every individual read looked compliant. The deadline does not substitute, because it bounds elapsed cooperative work rather than bytes accumulated before it expires. Eight declared sources per version and sixty-four across the pass. A manifest that declares more than eight usable sources reports `plugin_manifest_truncated`, with that count; a `null`, an invalid element and an unsupported one keep their own reporting and do not count toward the eight; reaching sixty-four declared file reads across the account's plugins reports `plugin_manifest_reads_exhausted` once on each manifest with a declared file left unread, which can be a manifest within its own cap, and that manifest's inline declarations and files already read are still taken, in its order. Inline declarations are not reads and do not count. Either way, coverage lost to a cap is visible. A path declared twice, on Windows also in two cases, is read once and counts against the sixty-four once, whether or not the read succeeded; a row about the file, such as `plugin_manifest_missing_source` or `parse_failed`, is reported once however many times it is declared; a manifest that declares the root `./.mcp.json` gets a read of its own, as a declared source, so a link there is followed for the root file and not for the declaration, but still counts at its last position, because a repeated declaration decides which definition of a name survives and dropping it would change precedence rather than save work.

**`~/.claude/plugins/marketplaces/` is deliberately not read.** That is the marketplace's own checkout; it holds the plugin source, so reading it would both reintroduce installable-catalog rows and double-count every installed plugin. On one workstation 39 of 51 rows from one client would have been catalog entries nobody had enabled. Probing only `plugins/cache/`, which holds the installed copies the client acts on, keeps the catalog out by construction rather than by a list of path substrings.

Not read: plugin enablement set per project rather than per user. Only `~/.claude/settings.json`, the one user-scope file, is consulted; `~/.claude/settings.local.json` is project-scope and not read, for the reason given above.

### Project-local configuration, from each client's project list

Project-local files are found by reading the list of projects a client already maintains and probing known filenames inside each entry. Three lists are read:

| Origin | Source | What is read |
| --- | --- | --- |
| `claude_json` | `.claude.json` → `projects` | the key, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `hasTrustDialogAccepted` |
| `codex_toml` | `.codex/config.toml` → `[projects."…"]` | the key and `trust_level` |
| `vscode_workspace` | `<appsupport>/<fork>/User/workspaceStorage/*/workspace.json`, for the 500 most recently used records per fork | the `folder` field, or for a multi-root workspace the `workspace` field and the `folders` of the `.code-workspace` file it names |

A fork keeps one `workspaceStorage` record for every workspace ever opened and never removes one. The editor writes a record's `state.vscdb` while its workspace is open, which updates the record directory's modification time, so the 500 most recently modified records per fork are read, newest first, and the older ones are counted in a descriptive `workspace_records_older` row. Only directories are ranked: a file or any other entry beside the records that is not a directory is skipped before the 500 are chosen, so newer entries cannot push a record out, and a record directory that is a symbolic link, or on Windows a junction, is not followed and is counted in `workspace_record_unreadable`. A `workspace.json` whose content a cloud provider holds is counted there too, not as a project stored with a provider: the record is in the editor's settings, so the project it names may be on this disk, and its configuration is missing from the rows. The choice is made fresh on every query. At most 5,000 entries are listed per fork before the 500 are chosen; a fork with more is a `workspace_list_truncated` row.

A multi-root workspace's record names a `.code-workspace` file instead of a folder. That file is read when it is inside the home, once however many records name it, and on Windows whatever case each record spells it in, through the same component-wise open as every other read, and its folders count for each editor whose records name it, so a folder that VS Code and Cursor both reach through it has both editors' files probed; and up to 100 of its `folders` are taken, and at most 1,000 from every workspace file in one account's scan; its `settings` are not decoded. A workspace file stored with a cloud provider, in a directory a provider holds, or in a directory on a network or userspace filesystem the home is not on, is counted as one recorded project in `project_cloud_placeholder`, `project_on_network_filesystem` or `project_userspace_filesystem`, and not read. One that is a symbolic link is not followed, and is counted in `workspace_record_unreadable`. A folder given as a `uri` is contained like `folder`, an absolute `path` like a path from `~/.claude.json`, and a relative `path` is resolved from the file's directory with a leading `..` allowed only within the home and a `..` after a named directory refused. On Windows a `path` rooted without a drive (`\repo`) or with a drive and no separator (`C:repo`) is relative to a current drive or directory the scan does not have, and is counted as an unusable path. A workspace file outside the home is counted in `project_outside_home`, a missing one is silent, and one that cannot be read or parsed, including one that is `null` or whose `folders` is missing or `null`, is counted in `workspace_record_unreadable` or `workspace_record_malformed`. More than 100 folders in one file is a `workspace_list_truncated` row with `limit=100` once all 100 are taken for an editor, and more than 1,000 across the scan one with `limit=1000`, which is the only row for a file the total cut short; once 1,000 are taken, no further workspace file is opened.

Four things are read from a Claude project entry — the key, the two server-name arrays, and `hasTrustDialogAccepted`, which decides whether a repository-provided `.claude/settings.json` in that project is eligible to approve anything. The count is stated because it is a hard rule rather than a minimization: the same object carries `lastSessionFirstPrompt`, the literal text of the last thing the user typed at the client. The code decodes into a struct naming only the two arrays and `hasTrustDialogAccepted`, which cannot reach it, and a test asserts the property from the outside.

Codex's `trust_level` is read from its project table for the same reason and under the same rule: it is a closed enum rather than free text, it decides whether that project's `.codex/config.toml` is consulted at all, and nothing else in the table is decoded.

Inside a contained project, **only the files belonging to the clients that recorded it** are probed:

| Recorded by | Files probed |
| --- | --- |
| `~/.claude.json` → `projects` | `.mcp.json` |
| `workspaceStorage` → `folder` | `.vscode/mcp.json`, `.cursor/mcp.json` |
| `~/.codex/config.toml` → `[projects."…"]` | `.codex/config.toml`, and only when the project is trusted |

That mapping is the point, not an optimisation. Probing all four files in every project used one client's evidence that a directory is a project to justify reporting a *different* client's configuration in it — so a directory known only to Codex produced a `vscode` row because a dormant `.vscode/mcp.json` happened to sit there, with nothing establishing that VS Code had ever opened the directory. Deduplication keeps the full set of discovering clients, so a project in two histories is probed for both.

The consequence worth knowing: **a home that is itself a recorded Claude project does not activate other clients' project files.** `~/.vscode/mcp.json` is found only if a VS Code fork recorded the home as a workspace.

**A Claude project's approval settings are read only for its servers.** Its `.claude/settings.json` and `.claude/settings.local.json` are read once, and only after its `.mcp.json` was read and declares a server, because they decide nothing else. The account-wide `~/.claude/settings.json` is read the same way, once per home, the first time any recorded project declares a server. A project with no `.mcp.json`, or one whose files are stored somewhere other than this machine's disk, costs no settings read and gets no `approval_settings_unreadable` row, and neither does a home whose projects declare none.

**Codex trust gates its project config.** Codex skips every project-scoped `.codex/` layer for a project marked untrusted, so a `.codex/config.toml` there declares servers Codex will not load. Trust comes from `trust_level` in the `[projects."…"]` table and is matched positively against `trusted`: an unrecognised value, or an absent one, fails closed and is reported rather than assumed, since Codex's own default is to ask. Two keys that name one project, such as one with a trailing separator, leave it trusted only when both say `trusted`.

**Nothing walks the filesystem, and the trade is worth understanding.** A walk of the directories under each home would be wrong in four ways. Its results would change between runs, because the first account's source tree could exhaust a shared budget and decide what the second account's rows were. It would download files: `~/Documents` and `~/Desktop` are iCloud-backed under "Optimize Mac Storage", and reading a dehydrated file is a synchronous network fetch. It would block: one dead mount, offline network home or Windows oplock stalls a walk and everything osquery has scheduled behind it. And a walk finds *files* rather than *configuration*, such as a plugin marketplace's catalog of entries nobody enabled.

What it costs: **a project the user has never opened in a participating client is invisible to this table.** So is a project recorded only by a client there is no lister for.

A project recorded under `node_modules` is probed. A client does not record `node_modules` unless the user opened an editor there, and if they did, that project's MCP configuration is a real thing the editor will act on.

### Known omissions

**Some are covered elsewhere.** Fleet's orbit has an `ai_tools` table that reads Zed, Continue and Roo from the list below, plus Jan, so a Fleet user already has a form of what this table delivers for that software. (Parity is not currently our goal: in a field this volatile, all of this tooling may change or vendors themselves may abandon products over time.)

Each of these is a client the table does **not** read. They are recorded with their paths so adding one is mechanical, and marked with how the path was established, because a documented path that is wrong is worse than an acknowledged gap.

**Verified present on a development machine and still unread.** Both were found by running the table and comparing its output against a live session, and both would be two probes plus a thin extractor:

| Client | Path (all platforms) | Key | Note |
| --- | --- | --- | --- |
| [Amp](https://ampcode.com/manual) (Sourcegraph) | `~/.config/amp/settings.json` | `amp.mcpServers` | A literal dotted key at the top level, not a nested object, so the existing envelope extractor finds nothing. Uses `~/.config` on every OS rather than the per-platform application-support root. |
| [Zed](https://zed.dev/docs/ai/mcp) | `~/.config/zed/settings.json` | `context_servers` | Zed's own name for MCP servers. JSONC. Its sibling `agent_servers` is **ACP**, a different protocol for driving coding agents, and is deliberately out of scope — reporting it would make `client` and `transport` describe two protocols. |

**Documented by the vendor, not verified against an install.** Paths are from vendor documentation; none has been confirmed on a machine with the client installed, which is why none is implemented:

| Client | User-scope path | Project-scope path | Key |
| --- | --- | --- | --- |
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

Roo Code and Kilo Code are Cline forks and sit in VS Code extension storage, so they are the same shape as the `cline` probe already present — the cheapest of these to add. Continue is the most expensive: it needs a YAML reader, and its user-scope file is `~/.continue/config.yaml`; `~/.continue/mcpServers/*.yaml` is the *project* scope.

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

- **`~/.claude/**/mcp.json`** had no documented path and was speculative.
- **`XDG_CONFIG_HOME` on Linux** is assumed to be its default. The variable can name any absolute directory and Electron resolves a VS Code fork's userData under it, so an account that sets it keeps its configuration somewhere this never looks. The daemon's own environment is the wrong source, because it belongs to the daemon's account. Core osquery's `process_envs` table reports each running process's environment, which an extension can query, so the variable is visible only while one of the account's processes is running, and each process can carry a different value; this table does not read it yet.
- **Codex's literal `http_headers`** has no reader, deliberately. Its values are credentials by design.
- **Per-project plugin enablement.** Only the user-scope `~/.claude/settings.json` is read, so a plugin enabled or disabled in a project's own `.claude/settings.json` or `.claude/settings.local.json` is reported at its user-scope state.

## Containment

Every path recorded in a configuration file is a path a user controls, so containment is established rather than inherited. In order:

1. **Origin.** A `file://` URL is accepted only for `workspace.json`'s `folder` field, and only when the scheme is exactly `file`, there is no opaque body, the host is empty or `localhost`, and there is no userinfo, query or fragment. Those name no path bytes and VS Code never writes them, so they are refused rather than discarded, and one path cannot be accepted in one spelling and refused in another. `file://server/share` is a UNC path, and opening it would make this host authenticate to a server named in a file the scanned user controls — a recorded project path becoming an outbound credential. `vscode-remote://`, `ssh-remote://`, `wsl+…`, `docker://` and `http(s)://` all name a filesystem that is not this one.
2. **Decoding.** Only a `file://` origin is decoded, and `url.Parse` does it: it percent-decodes into `URL.Path`, which is the form used from there on, so there is no second decoding pass. A bare recorded path — the common case, since `.claude.json` and Codex record plain paths — is taken literally, because a directory named `100%` is ordinary and decoding it would invent a different one. The ordering still matters and is why the refusals below run afterwards: `%2e%2e%2f` arrives as `../`, so the `..` check has to see the decoded form.
3. **Shape.** Empty, NUL, any ASCII control character, any non-absolute path, and a path whose absolute form is longer than 1,024 bytes, macOS's `PATH_MAX`, are refused. The length bound keeps a path of any length written into a project list from reaching `source_path` and `source_context` on every row about that project.
4. **Traversal.** Any `..` component is refused, inspected *before* `Clean`, because `Clean` collapses `/home/alice/../bob` into a path that looks ordinary afterwards. Trailing separators are tolerated; recorded paths carry them.
5. **Relativity.** The path is reduced to a form relative to the home, refusing anything that resolves above it. The comparison folds case on macOS and Windows, whose default filesystems are case-insensitive, so `/users/alice/code` is a project under the home `/Users/alice`; on a case-sensitive APFS volume such a path is read through the home's spelling, still inside the home. On Windows, two recorded spellings of one directory that differ only in case are one project, probed once under the spelling read first, because Codex records every project key in lowercase there, so a project Codex and another client both record arrives in two spellings. On macOS they stay two projects, because a case-sensitive APFS volume can hold both as separate directories, so on the default case-insensitive volume a project recorded in two cases is probed twice, and its servers are listed under both spellings. On Windows a UNC path, `\\server\share` or `//server/share`, names another host and is counted as remote, as `file://server/share` is. An extended-length or device-namespace path to a drive, `\\?\C:\…` or `\\.\C:\…`, is local and is contained as `C:\…`, because Codex records project keys in the extended form. After either prefix, `UNC\server\share` still names another host, and anything other than a drive letter and `:\` is malformed. `.` is allowed: a home is frequently itself a recorded project, and `~/.mcp.json` is a real configuration file.
6. **The read.** The absolute path is never opened. Every read re-walks the relative form from the home down, opening each component with symlinks refused, which is what makes step 5 a guarantee about the bytes rather than a string comparison that happened earlier — a project directory that was inside the home when it was checked and is a symlink by the time it is opened fails the open.
7. **Cloud placeholders.** Two rules, and a third on Windows, because they fail differently. A **prefix** rule refuses the directories a sync provider conventionally owns, as a string comparison before anything is opened: `Library/Mobile Documents` and `Library/CloudStorage` on macOS, and `OneDrive` (including the `OneDrive - <Tenant>` business form), `Dropbox`, `Google Drive` and `iCloudDrive` on Windows. These are per-platform conventions and are applied only on their own platform. An **attribute** rule then refuses a file the platform marks non-local — `SF_DATALESS` on macOS, `RECALL_ON_DATA_ACCESS` / `OFFLINE` / `RECALL_ON_OPEN` on Windows — read from the open descriptor rather than by path, so an intermediate symlink cannot redirect the lookup. On Windows a **reparse-point** rule comes first, at every path component: a reparse point a storage provider placed, as every Cloud Files provider does for its placeholders and synced files, and as ProjFS, an HSM and WOF compression also do, is refused from the attributes `os.Root.Lstat` reports for it against its parent directory's handle, before it is opened, and counted as stored with a cloud provider wherever it sits, including the folders of providers the prefix rule does not name, such as Box Drive or Nextcloud. A junction or symbolic link is refused as a link, silently. The attribute rule applies to every file this table reads: a project file, a configuration file or project list at a fixed path in the home, and a followed link's target, which can sit in an evicted `~/Documents` that no prefix covers. A followed link to such a target is not followed, and is reported as the refused link it is.

   Reading a placeholder is not a read; it is a download of unbounded duration, charged to a scheduled query, that leaves the machine different from how it was found.

   **Linux answers a different question, because it cannot answer this one.** The two services the rules above were asked to handle have no Linux client — iCloud Drive has none, OneDrive none official — and Dropbox's Linux client syncs fully or selectively rather than leaving placeholders, so an unsynced file there is simply missing and reads as expected absence. What does exist is FUSE on demand: `rclone mount`, `google-drive-ocamlfuse` and `onedriver` fetch content when a read arrives. A FUSE filesystem carries no attribute saying in advance whether a given file's content is local, so the attribute rule has nothing to read, and a Linux directory named `Google Drive` is an ordinary directory, so the prefix rule would over-refuse without evidence.

   So the question asked instead is which filesystem the descriptor is on. `fileOnUserspaceFilesystem` runs `fstatfs` on the open handle before any read — from the descriptor, not the path, for the same reason every other check here does — and refuses `FUSE_SUPER_MAGIC` with `ErrUserspaceFilesystem`. That classifies as `ClassUserspaceFilesystem` and is counted in `project_userspace_filesystem`, a descriptive row: like a project in a cloud provider's folder, its content is stored somewhere other than this machine's disk and is inventoried there. Nothing bounds a read already in progress, which is what makes a pre-read check the only workable point — the query deadline is consulted between operations rather than inside a syscall, and closing the descriptor from another goroutine cannot interrupt a blocked read on a regular file.

   This over-refuses, in the same way and for the same reason the prefix rules do. FUSE is not only cloud storage: sshfs, gocryptfs and AppImage mounts are all FUSE, and a project on one of those is refused even though its content is local. That is acceptable only because the refusal is reported — the row names the filesystem — so an operator sees the coverage they lost rather than reading an empty result as an absence of servers. Network filesystems are deliberately **not** included, though the NFS and SMB magics are equally reachable: an NFS-mounted home is the ordinary arrangement in a managed fleet, so refusing on it would inventory nothing at all for those accounts, and what makes a dead NFS mount dangerous is that a read can block rather than that it can download. That is a separate problem with a separate remedy.

   The prefix rule over-refuses deliberately: a project inside one of those directories is refused even when its files are fully hydrated, which "Always keep on this device" makes common. It is reported rather than dropped, and it buys the one thing the attribute rule cannot. `FILE_ATTRIBUTE_RECALL_ON_OPEN` is by definition set on files whose provider begins fetching at `CreateFile`, and `os.Root` exposes no `FILE_FLAG_OPEN_NO_RECALL` — so a descriptor-based check learns that attribute only after causing the download it exists to prevent. The string rule runs first, and the reparse-point rule refuses every Cloud Files placeholder before it is opened, because each is a reparse point. What remains uncovered is a file that carries `RECALL_ON_OPEN` without being a reparse point.

**A configuration file that is a symbolic link** is followed one hop on macOS and Linux when the file it names is in the same home, because dotfile managers such as chezmoi, stow and yadm link `~/.claude.json`, `~/.cursor/mcp.json` and the like into place. That covers every file read at a fixed path, in a generated profile directory or in a recorded project, a plugin's root `.mcp.json`, and so the two project lists. The rules are `go_modules`', in `fsscan.FollowLink`: the link is read relative to its directory, which was opened with symlinks refused; the target must be inside the home, must not climb above it or have a `..` after a named directory, must not be in a cloud storage provider's folder, and must sit in a directory that is local or stored the same way as the home; and the target is then opened from the home down with symlinks refused, so it cannot be another link, and every check in this section applies to it. `source_path` names the link, which is where the client reads the file. A link that is not followed is silent for a configuration file, as any refused file is, and a `project_list_unreadable` row for a project list. `~/.claude/settings.json`, `installed_plugins.json`, a plugin's `plugin.json`, a source a plugin manifest declares, the approval settings files, `workspace.json` and a `.code-workspace` file are not followed. On Windows no link is followed.

Reads also refuse a file with more than one hard link. **This can drop rows on a benign host** — dotfile managers link configs into place, and pnpm and Homebrew link package contents — which is why the refusal is reported rather than silent: `project_read_refused` with a reason, never swallowed as absence.

### How refusals are reported

| Outcome | Reported as |
| --- | --- |
| Project directory deleted, or has no MCP config | **Silent.** The common case by a wide margin — three of thirty recorded projects on the development machine no longer exist, because a project list is a history of what was opened and nobody prunes it. One row each would be most of this table's output. |
| Project outside the home | Counted, **with no path.** A path inside a user's home is not publishable, so a diagnostic naming the directory would reintroduce the disclosure the columns are narrowed to prevent. |
| Project on another host | Counted, no path. |
| Project in a cloud provider's folder, or with a file the provider holds or on a userspace filesystem | Counted once per project, in a descriptive row. Its content is stored somewhere other than this machine's disk, and reading it could download it. A project in a provider's folder is decided from its path, so nothing in it is opened, its settings files included. |
| Hard link or owner refusal | **Never silent.** That one is a finding rather than an absence. |
| `~/.claude.json` or `~/.codex/config.toml` is a symlink this table does not follow, or `~/.codex` is a symlink | `project_list_unreadable`. The refusal stays in force, and the projects that list records are reported as missing rather than treated as never recorded. The servers `~/.claude.json` itself declares stay silent, as any refused config file is. A symlinked `~/.codex` is also a `profile_directory_unreadable` row, because Codex's named profiles in it are lost too. |
| A directory this table lists reached through a symlink: a VS Code fork's `workspaceStorage` or `profiles`, `~/.codex`, or a level of the plugin cache | Its listing is reported, with `reason=refused_path`: `workspace_list_unreadable`, `profile_directory_unreadable` or `plugin_list_unreadable`. The directory exists, so the configuration in it is missing rather than absent. An absent directory, or one with a regular file partway down its path, is silent. |

## Columns

Twenty-one columns, in the order a query writer needs them: the server, what it runs, whether it is live, the file and user it was found for, and whether the listing is complete. Core osquery's package tables lead with the item the same way (`npm_packages` and `vscode_extensions` start with `name`), and `SELECT *`, `.mode line` and fleet consoles show columns in declared order, so `package_name` and `url_endpoint`, the values a hunt filters on, come before the file and user columns. `go_modules` follows the same order.

| Column | Meaning | Format enforced |
| --- | --- | --- |
| `server_name` | The name the configuration gives the server | redaction, with a placeholder fallback |
| `client` | Which client owns the configuration | closed set |
| `transport` | `stdio` \| `http` \| `sse` \| `unknown` | closed set |
| `package_manager` | `npx`, `uvx`, `docker`, `mcp-remote`, … | closed set |
| `package_name` | The package the launcher installs | npm/PyPI or Docker name grammar |
| `requested_spec` | The spec as written, including any pin | package spec, Docker ref, or a validated endpoint |
| `pinned_version` | The version **the configuration pins** | `^[A-Za-z0-9][A-Za-z0-9.+_~*-]*$` or `sha256:<64 hex>` |
| `confidence` | `low` \| `medium` \| `high` | closed set |
| `command_basename` | Executable name only — no directories, no arguments | `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, ≤ 64 bytes |
| `args_count` | Length of the `args` array as written | integer |
| `url_endpoint` | Scheme and host only | scheme in `{http,https,ws,wss}`, host hostname-shaped or bracketed IPv6 |
| `env_keys` | JSON array of variable **names**; values are never read | each `^[A-Za-z_][A-Za-z0-9_]*$` |
| `disabled` | `1` when the configuration file says disabled | integer |
| `approval_state` | `enabled` \| `not_approved` \| `disabled` \| `unknown` \| `not_applicable` | closed set |
| `source_path` | Absolute path of the file the row came from | structural only (see below) |
| `source_context` | Where in the file the server was declared | closed token set, or `projects[P].mcpServers` with `P` an absolute path contained in the home, or a probe's `[P]` with `P` a relative path contained without its `..` being cleaned away |
| `user` | Account name, from osquery's `users` table | none — it is the join key |
| `uid` | The `uid` column of osquery's `users` table, as core osquery's per-user tables publish it, so the table joins with `users` (see "Joining with `users`" for the form to use); on Windows osquery fills it with the last component of the SID, which two accounts can share, so `user_id` stays the identity to correlate on | integer |
| `user_id` | uid on POSIX, SID on Windows | `^(S-1-[0-9-]+\|-?[0-9]+)$` |
| `scan_complete` | `1` when every server this row's source declares was listed and, for a plugin's server, every source its plugin version's manifest declares was read | integer |
| `warning` | What was not listed, and why | built from a closed catalogue |

`pinned_version` is what the file pins, never what is installed: `npx` resolves `@1.2.3` itself and may resolve it elsewhere, and an absent pin means unpinned rather than unknown. It is text and compares as text, so `'1.10.0' < '1.9.0'` — compare exact values and sort in whatever consumes the rows.

`approval_state` has a fifth value, `unknown`, and the distinction from `not_approved` is load-bearing. `not_approved` is a positive finding: the client recorded its decisions and this server was not among them. `unknown` means the evidence does not support a positive finding either way, so the server may well be live. Collapsing the two reported "not approved" about a server nobody had declined, which fails in the direction an inventory must not: it invites ignoring a server that is running.

Three situations produce `unknown`. The first is a record that could not be read — malformed settings, a settings file that is JSON `null`, an undecodable project entry, or a project entry that is JSON `null`, which records nothing. The second is a record that read cleanly from a source whose *eligibility* is uncertain: `.claude/settings.local.json` is honoured only for a trusted project, and trust lives in git state this table does not consult. Where such a file contradicts a lower-precedence one, both readings are live — if the file counts its value wins, and if it does not the account-wide value does — so neither may be published as fact. Resolution therefore runs twice, once with the uncertain source and once without, and reports `unknown` only when the two disagree. An uncertain source that agrees with the certain evidence, or says nothing about this server, changes nothing; a rejection anywhere is decisive, since nothing promotes a server the user declined. The third is a plugin version that is cached but is not the installation the client would load: Claude keeps the previous version's directory for fourteen days after an update so a session that already loaded it keeps running, so such a server may genuinely still be live in somebody's open session while no new session would load it. Each case carries its own warning code, so `unknown` is never the whole answer a row gives.

`approval_state` is separate from `disabled` on purpose. Claude Code treats a server declared in a project's `.mcp.json` as inert until the user approves it, so `disabled = 0` on an unapproved server was a false positive in a security inventory. `disabled` means "the configuration file said disabled", which is a fact about the file; approval is a fact about the client's state, and a user who has neither approved nor rejected a server is in neither of that column's two values. Folding them together would make one column mean different things depending on the client.

### `scan_complete`, and what `warning` is for

`scan_complete`, like every yes-or-no column in this table and in core osquery, is an INTEGER: `1` means yes and `0` means no. On a server row, `scan_complete = 1` means every server declared in that row's `source_path` was listed and, for a server a Claude Code plugin declares, every source that plugin version's manifest declares was read. Every diagnostic row reads `0`.

A finding changes the server rows it is about, and no others:

- **Its file.** A finding about one source file marks only that file's rows. A `~/.cursor/mcp.json` with three servers and one entry that will not decode gets an `entries_skipped` row naming the file, and its three servers read `scan_complete = 0`, while the servers in `~/.claude.json` keep `1`.
- **Its plugin's manifest.** A finding about a plugin's manifest marks only that plugin version's server rows. A manifest that names `./servers.json`, which does not exist, gets a `plugin_manifest_missing_source` row, and the servers in that plugin version's `.mcp.json` read `0`, because the client may load a definition this scan did not read. Another plugin's servers keep `1`. A budget that runs out between one plugin version's sources marks that version's rows the same way.
- **Not user-level findings.** A problem finding the user's configuration is a row of its own, and no server row changes. An unreadable `~/.codex/config.toml` gets a `source_unreadable` row for the file, whose own servers are not listed, and a `project_list_unreadable` row, because the projects Codex records are not found; the servers in every file that was read keep `1`. A budget that runs out between two files is a `budget_exhausted_during_home` row, and the servers in the files read before it keep `1`. An unreadable `~/.claude/settings.json` is a `plugin_settings_unreadable` row, and the plugin servers read `approval_state = 'unknown'` and keep `1`, because their own files were read in full.

A descriptive finding changes nothing either: a column left empty on a server that is still listed, such as `env_key_dropped`, or a recorded project this table does not read, because it is outside the home, on another host, at an unusable path, untrusted, stored with a cloud storage provider or on a userspace filesystem. Opening a project outside your home is ordinary — `/tmp`, `/Volumes`, a shared checkout — and the client's project list keeps it permanently, so treating it as a loss would mark the account incomplete on every run.

So a row's `scan_complete` depends only on its own source and, for a plugin, its own manifest. A passing problem elsewhere, such as Claude Code rewriting `~/.claude.json` partway through a read, does not set every row the user has to `0` and back on the next run, which osquery's differential logging would record as each row removed and added again.

- `WHERE scan_complete = 1` keeps the servers whose sources were read in full.
- A user's inventory is complete when that user has no warning rows other than the descriptive ones. Every descriptive warning that is a row of its own starts with "recorded project", and no other warning does. A descriptive warning on a server row, such as a dropped column, sits on a row that reads `1` unless its file was cut short. So the users with an incomplete inventory are:

```sql
SELECT DISTINCT user FROM mcp_servers
WHERE scan_complete = 0 AND warning NOT LIKE 'recorded project%';
```

That selects every diagnostic row except the descriptive ones, and every server row whose source or manifest was not read in full. Before this column, a truncated scan and a host with nothing on it gave the same answer to `warning = ''`.

### The warning catalogue

`warning` is assembled only from a fixed sentence chosen by code, decimal integers, closed-enum spellings, and — in one case — a configuration key that has passed `^[A-Za-z_][A-Za-z0-9_.-]*$`. There is no fifth source.

That is not fastidiousness. Four columns were built by concatenating an error message, and both parsers quote the input they failed on: BurntSushi's `ParseError.Message` carries `found "…"`, so an `env = { TOKEN = abc123 }` put the token in the column verbatim, and `encoding/json` names the offending value. What is read instead is position — a line number from TOML, a byte offset from JSON — because those are integers, they are what an operator needs to go and look, and neither can carry a secret. TOML's `LastKey` is also user bytes, since the format permits quoted keys, so it passes the identifier grammar before being reported.

### Warning codes

Every `warning` value is one sentence from `warnSentences` in `warnings.go`, followed by details in brackets, such as `[count=4]` or `[reason=denied]`. The code names below are the identifiers this documentation and the source use; the column publishes the sentence, so a query selects a kind of warning with `LIKE` on the sentence's opening words. A warning either sits on a server row, about that row, or is a diagnostic row of its own, which always reads `scan_complete = 0`. A server row carries at most one warning, and a finding that rows are missing takes precedence over a dropped column. Each code's effect on `scan_complete` is its scope, set in `scope()` in `warnings.go`, and a code with no scope is treated as source scope.

| Detail | What it holds |
| --- | --- |
| `count=` | how many entries, projects, plugins or keys the warning is about |
| `limit=` | the cap a count or size was measured against |
| `line=` | a line number from the TOML parser |
| `offset=` | a byte offset from the JSON parser |
| `reason=` | the failure type, from `pkg/fsscan`'s closed set, such as `denied` or `hard_link` |
| `source=` | which client's list of projects, from `pkg/devclients`' closed set: `claude_json`, `codex_toml`, `vscode_workspace`, `cursor_workspace` or `windsurf_workspace` |
| `shape=` | what defeated the parser: `unterminated_block_comment`, `top_level_is_not_an_object` for a document that is `null`, `envelope_present_but_undecodable` for a JSON envelope or a Codex `mcp_servers` table none of whose entries decode, `value_has_the_wrong_type` or `unrecognised` |
| `value=` | a JSON value kind: `string`, `number`, `bool`, `array`, `object` or `null` |
| `key=` | a configuration key that passed `^[A-Za-z_][A-Za-z0-9_.-]*$` and is at most 64 characters |

**User scope: rows for the user, and no server row changes.** `source_path` names the home, or the roster's default directory when the finding has no home. A directory the roster declares for an account it skipped is published only when it is absolute and clean, so an `account_home_not_absolute` row has an empty `source_path` when the directory is relative or has a `..`.

A user that was not scanned. These come from the roster or from the first checks on a home. The user has no server rows, so the row is the whole answer for that user.

| Code | Sentence | Details |
| --- | --- | --- |
| `roster_unreachable` | osquery could not be reached to list user accounts, so no account's configuration was inspected | none |
| `roster_query_failed` | the osquery users table could not be read, so no account could be confirmed or ruled out | none |
| `roster_account_unnamed` | the roster returned an account with no username, so it could not be attributed or inspected and this account may be it | none |
| `account_not_in_roster` | no account of this name is in the roster osquery returned, so nothing was scanned for it: the name may be misspelled, the account may have been removed, or it may be one the roster does not enumerate | `count=1` when the roster also returned an account with no username, a `roster_account_unnamed` row, so the name may be that account; none otherwise |
| `account_non_login` | this account cannot log in, so it was not inspected and keeps no editor or agent configuration | none |
| `account_no_home_declared` | this account declares no home directory, so there was nowhere to look | none |
| `account_home_missing` | the home directory this account declares does not exist, which may mean it is offline rather than absent, so its configuration is not listed | none |
| `account_home_unstattable` | this account's home directory could not be inspected, so its configuration is not listed | none |
| `account_home_redirected` | this account's home directory is a symlink or reparse point, which is not followed, so its configuration is not listed | none |
| `account_home_not_directory` | the home directory this account declares is not a directory, so its configuration is not listed | none |
| `account_home_not_absolute` | the home directory this account declares is not an absolute path free of '..', so it was not resolved and its configuration is not listed | none |
| `accounts_home_unusable` | accounts with no usable home directory were not inspected; query a specific user to see which | `count=` |
| `home_unreadable` | this account's home directory could not be opened, so none of its configuration is listed | `reason=` |
| `budget_exhausted_before_home` | the query budget was exhausted before this account was scanned, so none of its configuration is listed | none |
| `cancelled_before_home` | the query was cancelled before this account was scanned, so none of its configuration is listed | none |
| `budget_exhausted_opening_home` | the query budget was exhausted opening this account's home directory, so none of its configuration is listed | none |

A user whose scan fell short. Some of the user's configuration is not listed, and the servers that are listed keep their own `scan_complete`.

| Code | Sentence | Details |
| --- | --- | --- |
| `budget_exhausted_during_home` | the query budget was exhausted part way through this account, so some of its configuration may not be listed | none |
| `cancelled_during_home` | the query was cancelled part way through this account, so some of its configuration may not be listed | none |
| `appdata_undetermined` | the roaming application data location could not be determined for this account, so its editor and agent configuration may not be listed; the conventional location was inspected instead | none |
| `appdata_redirected_outside_profile` | roaming application data for this account is redirected outside the profile, which is not inspected, so its editor and agent configuration is not listed | none |
| `profile_directory_unreadable` | a per-profile configuration directory could not be listed, so any profile-scoped servers in it are not listed | `reason=`, or `count=` and `limit=` when the directory holds more than this scan lists |
| `project_list_unreadable` | the list of projects this client records could not be read, so no project-local configuration was found for it | `source=`, `claude_json` or `codex_toml`, one row per list; with `reason=` when the file could not be read, and nothing more when it could not be parsed or is `null` |
| `project_list_truncated` | the list of projects this client records was longer than this scan will follow, so projects past the limit were not inspected | `count=`, `limit=`; `source=` naming the list whose entry first found its 1,000-project cap reached, and no source when the cap across every client was reached |
| `project_read_refused` | a project configuration file was refused by a safety check rather than being absent, so it exists and was deliberately not read | `reason=` |
| `project_trust_unknown` | the trust state of recorded projects could not be read, and project-scoped configuration is only loaded for trusted projects, so any servers they declare are not listed | `count=` |
| `workspace_list_unreadable` | an editor's workspace list could not be read, so the projects it records and any configuration in them are not listed | `reason=`, `source=`: `vscode_workspace`, `cursor_workspace` or `windsurf_workspace`; one row per editor and reason, so two of an editor's storage roots that failed differently are two rows |
| `workspace_list_truncated` | an editor's workspace list held more entries than this scan reads, so projects past the limit are not inspected | `count=`, `limit=`, `source=`: `limit=5000` for a `workspaceStorage` directory, `limit=100` for one `.code-workspace` file's folders, `limit=1000` for every workspace file's folders together |
| `workspace_record_unreadable` | workspace records exist and could not be read, so the projects they name and any configuration in them are not listed | `count=` |
| `workspace_record_malformed` | workspace records could not be parsed, so the projects they name and any configuration in them are not listed | `count=` |
| `plugin_list_unreadable` | the installed plugin directory could not be listed, so any servers declared by plugins are not listed | `reason=` |
| `plugin_list_truncated` | more installed plugins were found than this scan will probe, so servers declared by plugins past the limit are not listed | `limit=`, the limit reached: `20` marketplaces, `50` plugins in a marketplace, `10` versions of a plugin, `500` entries read from one cache directory, or `200` versions across the scan; `count=`, how many were taken under it. One row per limit the scan reached: a level's cap is not reported when the probe budget or the deadline stopped the scan before that level took every name it kept |
| `plugin_settings_unreadable` | the settings recording which plugins are enabled could not be read, so plugin-declared servers are listed with an unknown approval state | `reason=` when the file could not be read; none when it could not be parsed or is `null` |
| `plugin_records_unreadable` | the plugin installation records could not be read, so it is not known which installed version the client would load | `reason=` when the file could not be read; none when it could not be parsed or is `null` |

**Plugin scope: that plugin version's server rows read `scan_complete = 0`.** `source_path` names the manifest, `.claude-plugin/plugin.json` in the plugin version's directory, except for `plugin_manifest_missing_source`, where it names the file the manifest declares. A plugin version's server rows also read `0` when the budget runs out between its sources, which a `budget_exhausted_during_home` or `cancelled_during_home` row reports.

| Code | Sentence | Details |
| --- | --- | --- |
| `plugin_manifest_unreadable` | a plugin manifest exists and could not be read, so any MCP servers it declares are not listed | `reason=` when the file could not be read; none when it could not be parsed or is `null` |
| `plugin_manifest_unsupported` | a plugin manifest declares MCP servers in a bundle or at a URL, which this table does not unpack or fetch, so they are not listed | `count=` |
| `plugin_manifest_truncated` | a plugin manifest declares more MCP configuration sources than this table will read, so some of its servers are not listed | `count=`, the usable sources the manifest declares; `limit=8` |
| `plugin_manifest_reads_exhausted` | the plugins' manifests together declare more MCP configuration sources than this table reads in one scan, so some of this manifest's servers are not listed | `limit=64` |
| `plugin_manifest_missing_source` | a plugin manifest names an MCP configuration file that could not be read, so any servers it declares are not listed | `reason=` |
| `plugin_manifest_invalid_declaration` | a plugin manifest declares MCP servers with a value of a type the field does not accept, so that declaration was not read | `count=` |
| `plugin_manifest_path_too_long` | a plugin manifest names an MCP configuration file whose path is longer than this table reads, so any servers it declares are not listed | `count=`, the declarations; `limit=1024` |

**About one source file: that file's rows read `scan_complete = 0`.** Source scope. `source_path` names the file. `plugin_declaration_shadowed` sits on the server rows it qualifies; the others are diagnostic rows.

| Code | Sentence | Details |
| --- | --- | --- |
| `source_unreadable` | this configuration file could not be read, so any servers it declares are not listed | `reason=` |
| `source_too_large` | this configuration file is larger than the limit this scan reads, so the servers it declares are not listed | `limit=` |
| `parse_failed` | this configuration file could not be parsed, so the servers it declares are not listed | TOML: `line=` and `key=`; JSON: `offset=`, with `shape=value_has_the_wrong_type`, `key=` and `value=` for a value of the wrong type; otherwise `shape=` |
| `entries_skipped` | server entries in this file could not be decoded and are not listed | `count=` |
| `plugin_declaration_shadowed` | a higher-precedence declaration for this server could not be read, so this definition may not be the one the client loads | none |

**Descriptive: `scan_complete` is unchanged.** These describe what the table reads, or a field left empty on a server that is still listed. The column drops, `env_*`, `identity_dropped`, `unknown_launcher_option` and the two plugin-selection codes sit on the server row they describe. The recorded-project codes are rows of their own, and their sentences start with "recorded project".

| Code | Sentence | Details |
| --- | --- | --- |
| `project_outside_home` | recorded projects lie outside this account's home and were not inspected | `count=` |
| `project_remote_origin` | recorded projects are on another host rather than this filesystem and were not inspected | `count=` |
| `project_path_malformed` | recorded project locations were not usable absolute paths and were not inspected | `count=` |
| `project_cloud_placeholder` | recorded projects are stored with a cloud storage provider rather than on this machine's disk and were not read, so nothing was downloaded | `count=`, the projects |
| `project_userspace_filesystem` | recorded projects are on a filesystem implemented in userspace, where a read may fetch their contents on demand, and were not read | `count=`, the projects |
| `project_on_network_filesystem` | recorded projects are on a network filesystem, unlike this account's home, and were not read, so nothing was read over the network | `count=`, the `.code-workspace` files: this table reads a project on a network filesystem, and counts only a workspace file on one |
| `workspace_records_older` | recorded project records older than the most recently used ones this scan reads were not inspected | `count=`, the records not read, summed across the directories one editor has; `limit=500`; `source=` |
| `project_untrusted` | recorded projects are marked untrusted by their client, which does not load project-scoped configuration for them, so any servers they declare are not listed | `count=` |
| `approval_settings_unreadable` | recorded project servers that a settings file governs are reported with an unknown approval state rather than a guessed one, because the settings file exists and could not be used | `key=` naming the settings file, with `reason=` when it could not be read or the parse details when it could not be parsed or is `null` |
| `plugin_version_superseded` | a plugin version is present in the cache but is not the installation the client would load, so its servers may be from a superseded release | `count=` |
| `plugin_selection_unknown` | it could not be established whether this cached plugin version is the installation the client would load | none |
| `command_basename_dropped` | the command name in this entry did not match the format this column records and was dropped | none |
| `server_name_unrepresentable` | this server's name could not be published safely and has been replaced with a placeholder naming the file it came from | none |
| `source_context_path_dropped` | the project path in this entry's location could not be published and was dropped, leaving the section name | none |
| `url_endpoint_dropped` | the endpoint in this entry did not match the format this column records and was dropped | none |
| `env_key_dropped` | environment variable names in this entry did not match the format this column records and were dropped | `count=` |
| `env_header_literal_value` | this entry supplies an HTTP header value literally rather than naming an environment variable, so the configuration file itself holds the credential | `count=` |
| `identity_dropped` | the package this entry launches could not be identified unambiguously, so the package columns are empty rather than guessed | none |
| `user_id_dropped` | the account identity the roster supplied was not in a recognised form and was dropped | none |
| `unknown_launcher_option` | this entry passes an option this table does not recognise to its launcher, so the package columns are empty rather than guessed: an unrecognised option may or may not consume the value after it | none |

### The redaction contract, and what it does not cover

Credentials are removed from the places they are *routinely* found, and the limit is stated rather than implied.

- **`args` is never emitted** — only counted. Arguments routinely carry opaque tokens no pattern detects. `package_name` and `requested_spec` are read from them only within the launcher's own options, and each launcher's options are read by its own table of which take a separate value, from the launcher's own source or CLI: npm 12.2.1 for npx, bun 1.4.3 for bunx, uv 0.13.3 for uvx and `uv`, pipx 1.18.4, Docker 29.8.2 and podman 6.1.4. The launchers disagree about the same names — `-f` takes a value for uv and none for npx, `-c` is npx's `--call`, `-p` names the package for npx and bunx — so one shared table published a launched server's argument whenever two disagreed. The scan stops at the launcher's first operand; `--` makes the token after it the only candidate, and a lone `-` is an operand; an option the launcher's table does not list identifies nothing, with `unknown_launcher_option`, because whether it takes a value cannot be known, and a credential-named one is no exception except for npx, whose own parser reads an option it does not list as taking the next token; and `run` counts only in the subcommand's own position, so `pipx install foo run <secret>` and `docker exec c run <secret>` publish nothing. `npx --call` runs a command and names no package unless `--package` does, and `uv run` takes no `--from`, which uv refuses, so it names no package either. Identity is read from the arguments as parsed, each redacted for its own content, so the scan sees whether the argument after an option is another option or `--`: a credential-named option followed by either, `--` after any option that takes a value, and a value given inline to an option that takes none all identify nothing, and podman's value-less `--passwd` leaves `podman run --passwd alpine:3 <secret>` naming `alpine:3`. A package option given more than once names the last for bunx and pipx, which use the last, and nothing, with `identity_dropped`, for uvx, which refuses a repeated `--from`, and for npx when the packages differ, since npx installs every one.
- **`command` is never emitted** — only its basename, which drops every directory component and any whitespace-embedded arguments. `/opt/--dd-key=<secret>/bin/tool` arrives as `tool`.
- **`url_endpoint`** keeps scheme and host; path, query, fragment and userinfo are dropped, then the remainder must match a host grammar.
- **`env_keys`** carries names; values are never extracted.
- Known token shapes are replaced with `[REDACTED]`, as is the value of any flag-style assignment whose option name announces a credential (`--token=`, `--api-key=`, `--dd-key=`) wherever in a field it appears.
- Every free-text column has a **positive grammar**, and what does not match is dropped with a code saying so.

`server_name` has a grammar too, the same as `command_basename`'s. Checks that only refuse bad values — empty, the redaction marker alone, a control character, too long — would publish a server *key* such as `API_KEY=opaqueValue` or `Authorization: Bearer opaqueValue` verbatim. A name that fails the grammar gets the positional placeholder rather than being emptied. A name redaction has already cleaned keeps its marker: `release-[REDACTED]` publishes, while `API_KEY=[REDACTED]` still does not, because only the marker is forgiven and not the text around it.

**Residual risk.** Redaction recognises *known* shapes, so an opaque secret with no structure passes through it. Two columns have no grammar available:

- **`source_path`** is a filesystem path whose directory names the user chooses, and an allowlist of directory names cannot exist. It keeps redaction plus a structural assertion — absolute, already clean, under the home, or for a row about the roster, which has no home, absolute and already clean. **A user who names a directory after an opaque secret puts it in this column.**
- **`user`** is the join key. Constraining it would break `WHERE user = '<name>'`.

Narrowing one free-text column while others keep the property would be unsound, which is why all of them are narrowed together. A grammar constrains the format of a name, not a list of names: `terraform-mcp-server` and `computer-use-client-launcher` pass unchanged, while `API_KEY=xyz npx -y pkg` does not, because a filename cannot contain an equals sign.

Two losses that follow from that, stated rather than buried. A **non-ASCII basename is dropped**, because admitting Unicode letters reopens homoglyph confusion — `nрx` with a Cyrillic er reads as `npx` in any console. And an **unrecognised launcher option empties the identity triple** for that row at `confidence = low`: an unlisted option may or may not consume the token after it, and `npx -y --pat <secret> pkg` otherwise reported the secret as the package name. A legitimate unlisted boolean now costs its row the package columns, which is a missing answer where the alternative is a confidently wrong one.

### When `server_name` cannot be published

If redaction empties the name, leaves only the marker, or the name carries a control character or exceeds 256 bytes, the column reports `[redacted:<source path relative to the home>]`, with `#2`, `#3` and onward appended only when one file yields more than one such name, ordered by raw name so it is stable across runs. The number has no upper bound, so two such names from one file never publish the same value; the file's size cap bounds how many there can be.

Positional, not hashed. A server name is short and drawn from a small vocabulary, so a truncated digest is brute-forceable offline — the oracle this must not be. The trade: this traces to "which file, go and look", and deliberately does not answer "is this the same server as last week". Durable fleet-wide correlation needs a stable pseudonym, and a stable pseudonym is the attackable thing.

## Query budget

`MACADMINS_EXTENSION_WALK_TIMEOUT` accepts a Go duration and bounds the whole query, shared across every account rather than granted per account — sized against osquery's watchdog on the assumption that one query costs one budget. Giving each home its own turns that into homes × budget, and a shared Mac with a handful of accounts then gets the whole extension killed, dropping every other table's rows.

An account the budget never reached says so under its own name rather than stopping quietly, because a user who was never scanned and a user with no MCP configuration are otherwise the same empty answer.

The name is now a misnomer: nothing walks. It is kept because it is a documented environment variable an operator may already have set.

## Size caps

Sources are read with a 1 MiB cap, except `~/.claude.json`, which gets 4 MiB. The same 1 MiB cap applies to each `workspace.json` and `.code-workspace` file, and the folders taken from `.code-workspace` files stop at 100 per file and 1,000 per account's scan.

That one exception matters because the file is both a source of servers and the project list, so an oversized one costs the account every project-local configuration and the whole approval state, not just its `claude_code` rows — and the size is driven by something no operator can reason about. Measured on the development machine: 94,827 bytes, of which 43% is `cachedGrowthBookFeatures`, the client's own feature-flag cache. 4 MiB is roughly forty times the real file. The cost is real: `json.Unmarshal` of a 4 MiB document allocates several times that, per account, per query. Exceeding either cap is reported with the limit, in a `source_too_large` row for the file, and an oversized project list also gets a `project_list_unreadable` row for the user.

## Scan time and output size

Up to 1,000 recorded projects per user are followed, a cap `go_modules` shares (`devclients.MaxProjects`); exceeding it is reported as `project_list_truncated`. Rows follow the servers declared, not the projects followed: a project with no MCP configuration costs one to three failed opens and produces nothing. `BenchmarkDiscoverRecordedProjects` in `bench_test.go` measures one user with 200 and with 1,000 projects recorded in `~/.claude.json`, one in ten declaring two servers and one in ten deleted. On an Apple M4 Pro with a warm file cache, a scan took about 40 ms and 215 ms, and produced 40 and 200 rows, about 24 KB and 120 KB of JSON.

The table has no row cap of its own, so its output is bounded by the project cap and the per-file size caps rather than by a row count: a host where users declare thousands of servers returns thousands of rows. A scheduled query in osquery's default differential mode logs only the rows added or removed since its last run, so after the first run the volume follows change rather than the size of the inventory.

## Platform notes

**The account roster comes from osquery's own `users` table**, not from enumerating a directory, so it is the same list an operator joins against: OpenDirectory on macOS, the local account database on Windows, `/etc/passwd` on Linux. There is no filesystem fallback — the socket is how this extension returns rows at all, so if it cannot be reached osquery is not receiving results either.

**Linux: local accounts only.** osquery's `users` table hides an `include_remote` column defaulting to 0, so accounts served by LDAP, SSSD or another directory are absent. Their homes are often the ones carrying the configuration this table looks for. Setting `include_remote` would enumerate an entire directory on every scheduled query, which osquery itself warns can be extremely expensive, so the local roster is used and **this limit is documented here rather than emitted as a row**. A warning on every Linux run would make `warning` non-empty on every Linux host whether or not anything was wrong, so the one predicate an operator writes to find real problems would match every host in the fleet. A condition true of every run is a property of the table, and this is where a property of the table belongs. Per-account reporting is unaffected: a name the roster never mentioned still gets a row saying so.

**Linux: refused by filesystem type, not by placeholder attribute.** The prefix and attribute rules above are macOS and Windows only, because neither has a Linux counterpart. A project on a FUSE mount is refused by an `fstatfs` check instead and reported as `project_userspace_filesystem`, which over-refuses sshfs and gocryptfs deliberately and says so. Network filesystems are not refused. See the cloud-placeholder step above.

**Windows is partly tested.** `native-tests.yml` runs this table's tests and `pkg/fsscan`'s on `windows-latest`, without the race detector; their first run is on the pull request that adds the workflow. On Windows they cover a junction at an intermediate or final component and a junctioned profile, a directory symlink when the account may create one, an NTFS hard link refused through `NumberOfLinks`, a junctioned project directory, the registry lookup of Roaming AppData for the running account, and `file:///C:/` workspace URLs. What has also been exercised on a real host: bounded reads under a user profile, root enumeration, and a junction planted at a probed path being refused. What is still untested: the `RECALL_ON_*` placeholder check, beyond an ordinary file not being mistaken for a placeholder, because a real placeholder needs a sync provider; Roaming AppData for an account other than the one running the tests; and an unreadable profile, which needs an ACL that denies the test account. Platform-specific decisions are parameterised by GOOS so both branches run from any host, leaving only the system calls themselves to their own platform's job.

Two Windows behaviours are deliberate rather than incomplete. **Only a mounted registry hive is read** — a logged-off account's `NTUSER.DAT` is not loaded, because an inventory query should not mount a registry hive, and the API for it creates the file when absent, so a read could write. An account whose hive is not mounted falls to the existing "location could not be determined" diagnostic, as does a hive whose AppData value uses any variable other than `%USERPROFILE%` at its start, is not an absolute path, or contains `..`. And **owner verification is not implemented**: a read asked to verify an owner on Windows is *refused* rather than passed, so a caller cannot believe a check ran that did not. This table does not ask for it and relies on the hard-link refusal instead.

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

-- Users whose inventory is incomplete
SELECT DISTINCT user FROM mcp_servers
WHERE scan_complete = 0 AND warning NOT LIKE 'recorded project%';
```

## Narrowing by user

A `user` constraint reaches the generator and narrows the scan under osquery's default `--extensions_default_index=true`, which promotes extension columns to `INDEX`. Equality only, and all of it or none: `user = 'alice' OR user LIKE 'b%'` scans every home and filters afterwards, because `QueryContext` does not carry enough of the original boolean structure to prove the equality subset is sufficient. Scanning more than asked costs time; returning fewer rows than the query matches is a wrong answer. `user = ''` selects the rows that belong to no account, such as `accounts_home_unusable`, so it scans every home.

The filter is applied to the roster *before* any filesystem call. Narrowing afterwards still stat'd every home on the host, so one dead automount belonging to an account nobody asked about could consume the budget of a query scoped to a single local user.

Diagnostics are attributed to the narrowest account they apply to, so a constrained query still receives the ones that concern it. A roster-level failure is repeated under every name the query asked about, rather than emitted once with an empty `user` that the constraint would discard.

## Joining with `users`

Put this table first and join with `LEFT JOIN`. SQLite keeps the left side of a `LEFT JOIN` as the outer loop, so the table is scanned once, and every row of the table is kept, including the diagnostic rows about no single account, such as `accounts_home_unusable`, which have no `uid`:

```sql
SELECT u.username, u.description, t.*
FROM mcp_servers t LEFT JOIN users u USING (uid);
```

On Windows, `uid` is the last component of the SID, which two accounts can share, so join on the whole SID, which `user_id` holds and osquery's `users` table reports as `uuid`:

```sql
SELECT u.username, u.description, t.*
FROM mcp_servers t LEFT JOIN users u ON u.uuid = t.user_id;
```

With a plain `JOIN`, SQLite may put this table on the inner side and run the whole scan once for each `users` row, because `uid` is not pushed down to the read. `go_modules` works the same way, and there `FROM users JOIN go_modules USING (uid)` ran 133 scans in about 42 seconds on a development Mac with 133 rows in `users`, measured with osqueryi 5.23.1, against one scan in under a second for the `LEFT JOIN` form. Joining on `user` costs the same and adds rows: each scan is constrained to one name, so every service account the join reaches gets a row saying it was not inspected. A `CROSS JOIN` with the table first also scans once, but as an inner join it drops the rows that have no `uid`.
