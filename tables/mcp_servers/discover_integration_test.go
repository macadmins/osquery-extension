package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// serversOnly drops the diagnostic rows, so a test asserting on the servers found does not
// also have to account for every note the fixture happens to raise.
//
// More useful than it was: discovery now reads project lists, so a fixture home carries a
// ~/.claude.json whose own servers and whose project refusals both produce rows. A test about
// which project-local configs were probed should not have to enumerate those.
func serversOnly(rows []Server) []Server {
	out := make([]Server, 0, len(rows))
	for _, row := range rows {
		if row.Warning.empty() && row.ServerName != "" {
			out = append(out, row)
		}
	}
	return out
}

// discoverForTest supplies the context and the walk budget that DiscoverAll threads through in
// production, so the per-home tests below can keep naming just the user and the home.
// The standing-notes filter is applied here rather than at each call site: a fixture account
// has no registry hive, so on Windows every one of these tests would otherwise carry an extra
// roaming-application-data row and fail a count or a no-warning assertion for a reason that
// has nothing to do with discovery. See withoutStandingNotes.
func discoverForTest(user, home string) []Server {
	rows := discoverForHome(context.Background(), fsscan.UserHome{Name: user, Path: home},
		time.Now().Add(fsscan.WalkTimeout()))
	return withoutStandingNotes(rows)
}

// buildFakeHome materializes a minimal user home with the given files.
// files is a map of relative path -> contents. Returns the home dir.
// buildFakeHomeWithProjects is buildFakeHome plus the project list that makes the
// project-local files discoverable.
//
// Needed because discovery no longer walks: a project-local config is found by reading the
// list of projects a client records and probing inside each entry, so a fixture that only
// creates files on disk creates files nothing looks at. That is the behaviour change these
// tests exist to pin, and making the fixture state it explicitly is the point -- a reader of
// the test can see that the recorded list is what drives discovery.
func buildFakeHomeWithProjects(t *testing.T, files map[string]string, projectRels ...string) string {
	t.Helper()
	home := buildFakeHome(t, files)
	projects := make(map[string]any, len(projectRels))
	for _, rel := range projectRels {
		projects[filepath.Join(home, rel)] = map[string]any{}
	}
	recorded, err := json.Marshal(map[string]any{"projects": projects})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

// recordVSCodeWorkspace records a project the way a VS Code fork does, which is the only
// evidence that licenses probing `.vscode/mcp.json` or `.cursor/mcp.json` inside it.
//
// Claude's project list no longer stands in for this. Using it did, and that was the
// cross-product defect: one client's record that a directory is a project was being used to
// justify reporting a different client's configuration there.
func recordVSCodeWorkspace(t *testing.T, home, fork, projectRel string) {
	t.Helper()
	// The directory name under workspaceStorage is a generated hash; any stable string
	// serves, since it is reached by listing rather than by a fixed path.
	id := "ws-" + strings.ReplaceAll(projectRel, string(filepath.Separator), "-")
	record := `{"folder":"file://` +
		filepath.ToSlash(filepath.Join(home, projectRel)) + `"}`
	writeTestFile(t, filepath.Join(home,
		appSupport(fork, "User", "workspaceStorage", id, "workspace.json")), record)
}

// recordCodexProject records a project the way Codex does, including the trust state that
// decides whether Codex would load its project-scoped config at all.
func recordCodexProject(t *testing.T, home, projectRel, trustLevel string) {
	t.Helper()
	path := filepath.Join(home, ".codex", "config.toml")
	existing, _ := os.ReadFile(path)
	entry := "[projects.\"" + filepath.Join(home, projectRel) + "\"]\n"
	if trustLevel != "" {
		entry += "trust_level = \"" + trustLevel + "\"\n"
	}
	writeTestFile(t, path, string(existing)+entry)
}

func buildFakeHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return home
}

func TestDiscoverForHome_AllKnownClientsViaDirectPaths(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		appSupport("Claude", "claude_desktop_config.json"): `{
			// JSONC: top-of-file comment
			"mcpServers": {"desktop-srv": {"command": "npx", "args": ["-y", "desktop-mcp@1.0.0"]}}
		}`,
		".claude.json": `{
			"mcpServers": {"global-claude": {"type": "http", "url": "https://global.example.com/mcp"}},
			"projects": {
				"/repo/foo": {"mcpServers": {"foo-local": {"command": "node", "args": ["foo.js"]}}},
				"/repo/bar": {"mcpServers": {"bar-local": {"command": "uvx", "args": ["bar-mcp"]}}}
			}
		}`,
		".cursor/mcp.json":                  `{"mcpServers": {"cursor-srv": {"command": "uvx", "args": ["cursor-mcp@2.0.0"]}}}`,
		".codeium/windsurf/mcp_config.json": `{"mcpServers": {"wind-srv": {"command": "docker", "args": ["run", "--rm", "myimg:tag"]}}}`,
		".gemini/settings.json":             `{"mcpServers": {"gemini-srv": {"command": "npx", "args": ["-y", "gemini-mcp"]}}, "unrelated": "ignored"}`,
		".codex/mcp.json":                   `{"servers": {"codex-srv": {"command": "node", "args": ["s.js"]}}}`,
		appSupport("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"): `{"mcpServers": {"cline-srv": {"command": "npx", "args": ["cline-mcp"]}}}`,
	})

	rows := discoverForTest("alice", home)

	wantClient := map[string]string{
		"desktop-srv":   "claude_desktop",
		"global-claude": "claude_code",
		"foo-local":     "claude_code",
		"bar-local":     "claude_code",
		"cursor-srv":    "cursor",
		"wind-srv":      "windsurf",
		"gemini-srv":    "gemini",
		"codex-srv":     "codex",
		"cline-srv":     "cline",
	}
	gotClient := map[string]string{}
	for _, r := range rows {
		if !r.Warning.empty() {
			// The ~/.claude.json fixture records /repo/foo and /repo/bar as projects, which
			// are absolute paths outside this temporary home. Reporting that is correct and
			// is new: the inline servers those entries declare are still listed -- they are
			// read out of the file, not probed -- but the directories themselves are not
			// inspected, and the row set says so with a count and no path.
			if r.Warning.Code == warnProjectOutsideHome {
				if r.Warning.Count != 2 {
					t.Errorf("outside-home count = %d, want 2", r.Warning.Count)
				}
				continue
			}
			t.Errorf("unexpected warning on %s: %s", r.SourcePath, r.Warning.render())
			continue
		}
		gotClient[r.ServerName] = r.Client
	}
	if len(gotClient) != len(wantClient) {
		t.Errorf("server count: got %d want %d\ngot=%v", len(gotClient), len(wantClient), gotClient)
	}
	for name, want := range wantClient {
		if got := gotClient[name]; got != want {
			t.Errorf("%s: got client %q want %q", name, got, want)
		}
	}
}

// A project recorded in a client's own list is probed, and one that is not recorded is not.
//
// This is the whole of the discovery change in one test. The old version created
// ~/code/myrepo/.mcp.json and relied on a depth-6 walk of ~/code to find it, which worked and
// was nondeterministic: the budget was shared across every home, so whether this file was
// reached depended on how large the previous account's source tree was.
//
// Now the project list is the input. The file is found because ~/.claude.json records
// ~/code/myrepo as a project, and the second fixture -- an identical file in a directory
// nobody recorded -- is the cost of the change, asserted rather than left implicit.
func TestDiscoverForHome_ProbesRecordedProjects(t *testing.T) {
	home := buildFakeHomeWithProjects(t, map[string]string{
		"code/myrepo/.mcp.json": `{"mcpServers": {"repo-mcp": {"command": "npx", "args": ["repo-mcp@1.0.0"]}}}`,
		// Same file, in a directory no client records. Not discovered, by design: a project
		// the user has never opened in a participating client is invisible to this table,
		// which the README states.
		"code/unopened/.mcp.json": `{"mcpServers": {"never-opened": {"command": "npx", "args": ["x"]}}}`,
	}, "code/myrepo")

	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "repo-mcp" {
		t.Errorf("server name: %q", rows[0].ServerName)
	}
	if rows[0].Client != "claude_code" {
		t.Errorf(".mcp.json should be attributed to claude_code; got %q", rows[0].Client)
	}
	// Declared in a project .mcp.json and not in the approved list, so Claude Code will not
	// run it. Reported as enabled before approval_state existed.
	if rows[0].Approval != approvalNotApproved {
		t.Errorf("approval = %q, want %q", rows[0].Approval, approvalNotApproved)
	}
}

func TestDiscoverForHome_ProbesCursorInRecordedProject(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"dev/foo/.cursor/mcp.json": `{"mcpServers": {"ws-cursor": {"command": "uvx", "args": ["x"]}}}`,
	})
	recordVSCodeWorkspace(t, home, "Cursor", filepath.Join("dev", "foo"))
	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("rows: %d (%+v)", len(rows), rows)
	}
	if rows[0].Client != "cursor" {
		t.Errorf("a project .cursor/mcp.json should be attributed to cursor; got %q", rows[0].Client)
	}
	// Cursor has no approval step, so the question does not arise and `disabled` is the
	// whole answer. Borrowing Claude's state here would say something the client does not.
	if rows[0].Approval != approvalNotApplicable {
		t.Errorf("approval = %q, want %q", rows[0].Approval, approvalNotApplicable)
	}
}

func TestDiscoverForHome_ProbesVSCodeInRecordedProject(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"projects/foo/.vscode/mcp.json": `{"mcpServers": {"ws-vscode": {"command": "npx", "args": ["x"]}}}`,
	})
	recordVSCodeWorkspace(t, home, "Code", filepath.Join("projects", "foo"))
	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("rows: %d (%+v)", len(rows), rows)
	}
	if rows[0].Client != "vscode" {
		t.Errorf("a project .vscode/mcp.json should be attributed to vscode; got %q", rows[0].Client)
	}
}

// The plugin-catalog exclusions are gone, and so are the tests for them.
//
// Claude Code and Codex both cache installable plugin definitions as .mcp.json files --
// catalog entries, not configured servers. Measured on one workstation, 39 of 51 Codex rows
// came from three such directories. The fix was a list of path substrings, maintained by
// noticing each new cache location after it polluted the table.
//
// Nothing reaches them now. A marketplace cache is not a project any client records, so it is
// not probed, and the exclusion list became unreachable code with two tests asserting
// behaviour that could no longer occur. Deleted rather than kept green against a path that
// does not exist: a test that cannot fail is worse than no test, because it reads as coverage.
//
// A behaviour change, asserted rather than hidden: a project recorded under node_modules IS
// probed now.
//
// The walk pruned node_modules, .git and vendor, because descending them found vendored and
// hook-local configs that nothing was configured to run -- noise indistinguishable from real
// rows. The prune list is still in fsscan and still correct for a walk.
//
// It no longer applies here, because nothing walks. A directory is probed because a client
// recorded it as a project the user opened, and a client does not record node_modules unless
// the user genuinely opened an editor there. If they did, that project's MCP configuration is
// a real thing the editor will act on, and the old behaviour of silently pruning it was the
// wrong answer for that case.
//
// So the noise this prevented is prevented by a different and better mechanism -- nobody
// records a vendored directory as a project -- and the one case that changes is the one where
// the user really did open it. Stated here because a test that quietly stopped covering the
// prune would leave the next reader thinking it still applied.
func TestDiscoverForHome_ProbesRecordedProjectEvenUnderNodeModules(t *testing.T) {
	home := buildFakeHomeWithProjects(t, map[string]string{
		"code/foo/.mcp.json":                  `{"mcpServers": {"good": {"command": "npx", "args": ["x"]}}}`,
		"code/foo/node_modules/dep/.mcp.json": `{"mcpServers": {"vendored": {"command": "npx", "args": ["y"]}}}`,
		// Not recorded as a project, so still not found -- which is what actually keeps the
		// vendored noise out, rather than a prune list.
		"code/foo/vendor/other/.cursor/mcp.json": `{"mcpServers": {"unrecorded": {"command": "evil"}}}`,
	}, "code/foo", "code/foo/node_modules/dep")

	var found []string
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		found = append(found, row.ServerName)
	}
	sort.Strings(found)
	if !reflect.DeepEqual(found, []string{"good", "vendored"}) {
		t.Errorf("found %v; a recorded project is probed wherever it sits, and an "+
			"unrecorded one is not probed at all", found)
	}
}

// Dedup between the home-rooted and project-rooted probe lists.
//
// The real case, and it is not contrived: a user's home is frequently itself a recorded
// project -- it is on the machine this was developed on -- and ~/.cursor/mcp.json is then
// reachable both as a fixed path relative to the home and as `.cursor/mcp.json` inside the
// project whose path is the home. Containment allows that deliberately, because `~/.mcp.json`
// is a legitimate configuration file.
//
// So the two lists overlap for exactly one project, and the dedup that used to sit between
// the direct pass and the walker has to sit between these two instead.
func TestDiscoverForHome_DedupsBetweenHomeAndProjectProbes(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers": {"single": {"command": "npx", "args": ["x"]}}}`,
	})
	// The home records itself as a project, which is what makes the overlap reachable.
	recorded, err := json.Marshal(map[string]any{"projects": map[string]any{home: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after dedup, got %d: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "single" {
		t.Errorf("server name: %q", rows[0].ServerName)
	}
}

func TestDiscoverForHome_AllRowsHaveUserAndPath(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers": {"a": {"command": "npx", "args": ["x"]}}}`,
	})
	rows := discoverForTest("bob", home)
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].User != "bob" {
		t.Errorf("user: %q", rows[0].User)
	}
	if !strings.HasSuffix(rows[0].SourcePath, filepath.Join(".cursor", "mcp.json")) {
		t.Errorf("source path: %q", rows[0].SourcePath)
	}
}

func TestDiscoverForHome_MalformedJSON_EmitsWarning(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{not even close to JSON`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 {
		t.Fatalf("expected 1 warning row, got %d", len(rows))
	}
	if rows[0].Warning.empty() {
		t.Errorf("expected warning, got none")
	}
	if rows[0].ServerName != "" {
		t.Errorf("warning row should not have server name, got %q", rows[0].ServerName)
	}
	if rows[0].User != "alice" {
		t.Errorf("user: %q", rows[0].User)
	}
}

func TestDiscoverForHome_MissingFiles_SilentlySkipped(t *testing.T) {
	home := t.TempDir()
	rows := discoverForTest("alice", home)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d: %v", len(rows), rows)
	}
}

func TestDiscoverForHome_JSONCWithComments(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{
			// top-of-file comment
			"mcpServers": {
				/* a block comment */
				"x": {"command": "npx", "args": ["pkg"]} // trailing
			}
		}`,
	})
	rows := discoverForTest("alice", home)
	if len(rows) != 1 || rows[0].Warning.empty() == false {
		t.Fatalf("expected 1 clean row, got %#v", rows)
	}
	if rows[0].ServerName != "x" {
		t.Errorf("server name: %q", rows[0].ServerName)
	}
}

func TestDiscoverAll_UserFilter(t *testing.T) {
	root := t.TempDir()
	for _, u := range []string{"alice", "bob"} {
		dir := filepath.Join(root, u, ".cursor")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mcp.json"),
			[]byte(`{"mcpServers":{"`+u+`-srv":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	all := withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), nil))
	if len(all) != 2 {
		t.Errorf("no filter: got %d rows, want 2: %v", len(all), all)
	}
	just := withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{"alice": {}}))
	if len(just) != 1 || just[0].User != "alice" {
		t.Errorf("filter alice: got %#v", just)
	}
}

// fsscan.WalkTimeout is sized against osquery's watchdog on the assumption that one query
// costs one budget. Granting it per home instead makes the cost homes x budget, so a shared
// Mac with several accounts walks for minutes and gets the extension killed, taking every
// other table's rows with it.
//
// Asserted as a ratio rather than a wall-clock ceiling. Both measurements run on the same
// fixture on the same machine, so machine speed cancels out: a shared budget puts the N-home
// walk at roughly the cost of the one-home walk, while a per-home budget puts it at N times
// that. Measured here at 0.97-1.00 shared, against 4.0 for the additive version. An absolute
// ceiling cannot do this, because the only honest one is a small multiple of a 20ms budget and
// CI machines are not quiet enough for that.
func TestDiscoverAllSharesOneWalkBudgetAcrossHomes(t *testing.T) {
	root := t.TempDir()
	const homes = 4
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		user := fmt.Sprintf("user%d", homeIndex)
		// Wide enough under a recognised dev subdir that one walk cannot finish inside the
		// budget below. If a machine is fast enough to finish anyway, the test skips rather
		// than failing: with no walk truncated there is no budget behaviour to compare.
		for project := 0; project < 400; project++ {
			dir := filepath.Join(root, user, "code", fmt.Sprintf("p%d", project), "a", "b")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv(fsscan.WalkTimeoutEnv, "20ms")

	measure := func(filter map[string]struct{}) (time.Duration, bool) {
		start := time.Now()
		rows := withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), filter))
		elapsed := time.Since(start)
		for _, row := range rows {
			if row.Warning.empty() == false {
				return elapsed, true
			}
		}
		return elapsed, false
	}

	oneHome, budgetWasBinding := measure(map[string]struct{}{"user0": {}})
	if !budgetWasBinding {
		t.Skipf("one home walked %v without exhausting a 20ms budget; nothing to compare",
			oneHome)
	}
	allHomes, _ := measure(nil)

	if ratio := float64(allHomes) / float64(oneHome); ratio > 2 {
		t.Errorf("%d homes cost %v against one home's %v (ratio %.2f): budget looks additive "+
			"rather than shared", homes, allHomes, oneHome, ratio)
	}
}

// The other half of a shared budget: a user the budget never reached has to say so. Reporting
// nothing makes an unscanned user indistinguishable from a user with no MCP configuration,
// which is the confusion the truncation contract exists to prevent, and it is what a `break`
// here instead of a `continue` would silently reintroduce.
//
// An already-exhausted budget is used so no walk can start at all. That needs no large fixture
// and leaves nothing to machine speed.
func TestDiscoverAllReportsUsersTheBudgetNeverReached(t *testing.T) {
	root := t.TempDir()
	const homes = 5
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		dir := filepath.Join(root, fmt.Sprintf("user%d", homeIndex), "code")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(fsscan.WalkTimeoutEnv, "1ns")

	reported := make(map[string]warnCode, homes)
	for _, row := range DiscoverAll(context.Background(), rosterOf(t, root), nil) {
		if row.Warning.empty() {
			t.Errorf("user %q: an unscanned user must carry a warning", row.User)
		}
		reported[row.User] = row.Warning.Code
	}
	for homeIndex := 0; homeIndex < homes; homeIndex++ {
		user := fmt.Sprintf("user%d", homeIndex)
		if _, ok := reported[user]; !ok {
			t.Errorf("user %q was skipped silently; reported: %v", user, reported)
		}
	}
}

// A cancelled query must stop the walk. Generate is handed osquery's context and used to
// discard it, so this guards the threading rather than fsscan's own behaviour.
func TestDiscoverAllHonoursCallerCancellation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alice", ".cursor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mcp.json"),
		[]byte(`{"mcpServers":{"s":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The assertion is about how the stop is reported: a cancelled query must not be
	// described as a budget outcome, which means something different to an operator -- the
	// first says the query went away, the second says this host is too slow for the
	// schedule it is on.
	//
	// Equality on a code rather than a substring match on the sentence. The old version
	// searched for "timeout", which passed for every wording that did not happen to contain
	// that word, including a budget message that said "exhausted" instead.
	budgetCodes := map[warnCode]struct{}{
		warnBudgetExhaustedPreHome: {}, warnBudgetExhaustedOpening: {},
		warnBudgetExhaustedInHome: {},
	}
	for _, row := range DiscoverAll(ctx, rosterOf(t, root), nil) {
		if row.Warning.empty() {
			continue
		}
		if _, isBudget := budgetCodes[row.Warning.Code]; isBudget {
			t.Errorf("cancellation was reported as a budget failure: %q", row.Warning.Code)
		}
	}
}

func TestDiscoverForHome_VSCodeUserScopeProfilesAndCopilot(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		appSupport("Code", "User", "mcp.json"): `{
			// JSONC is accepted here too
			"servers": {"vscode-user": {"command": "npx", "args": ["-y", "vs-mcp@1.0.0"]}}
		}`,
		appSupport("Code", "User", "profiles", "abc123", "mcp.json"): `{"servers":{"vscode-profile":{"command":"node","args":["p.js"]}}}`,
		appSupport("Cursor", "User", "mcp.json"):                     `{"servers":{"cursor-user":{"command":"uvx","args":["c-mcp"]}}}`,
		".copilot/mcp-config.json":                                   `{"mcpServers":{"copilot-srv":{"type":"http","url":"https://example.test/mcp"}}}`,
	})
	rows := discoverForTest("alice", home)
	got := map[string]string{}
	for _, row := range rows {
		if row.Warning.empty() == false {
			t.Errorf("unexpected warning on %s: %s", row.SourcePath, row.Warning.render())
			continue
		}
		got[row.ServerName] = row.Client
	}
	for name, wantClient := range map[string]string{
		"vscode-user":    "vscode",
		"vscode-profile": "vscode",
		"cursor-user":    "cursor",
		"copilot-srv":    "copilot",
	} {
		if got[name] != wantClient {
			t.Errorf("%s: client = %q, want %q (rows=%v)", name, got[name], wantClient, got)
		}
	}
}

// Codex supports project-scoped configuration in <repo>/.codex/config.toml and named profiles
// in ~/.codex/<profile>.config.toml. Only the user-scope file had a direct path, so both of
// these were false negatives for a client the table names as supported.
//
// The .codex parent is still required rather than matching config.toml anywhere, and the
// reason is unchanged: that basename is among the most common on a developer machine. What
// changed is which mechanism enforces it. The project-scoped file is now found because the
// project is recorded and `.codex/config.toml` is a probe path inside it, so an unrelated
// `config.toml` at a project root is never opened rather than being opened and rejected. The
// named-profile file still needs isCodexTOMLPath, because that one is reached by listing
// ~/.codex and the names in it are generated.
func TestDiscoverForHome_CodexProjectAndProfileTOML(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		"code/myrepo/.codex/config.toml": "[mcp_servers.project_scoped]\ncommand = \"node\"\n",
		".codex/work.config.toml":        "[mcp_servers.profile_scoped]\ncommand = \"uvx\"\n",
		".codex/config.toml":             "[mcp_servers.user_scoped]\ncommand = \"npx\"\n",
		// Must NOT be picked up: a config.toml that is not Codex's. Both sit inside a
		// recorded project, so they are reachable in principle and excluded by the probe
		// path naming `.codex/config.toml` specifically.
		"code/myrepo/config.toml":          "[build]\ntarget = \"wasm\"\n",
		"code/rustproj/.cargo/config.toml": "[net]\ngit-fetch-with-cli = true\n",
	})
	// Recorded by Codex itself and trusted, which is what licenses reading a project's
	// `.codex/config.toml`: Codex skips project-scoped layers for an untrusted project.
	recordCodexProject(t, home, "code/myrepo", "trusted")
	recordCodexProject(t, home, "code/rustproj", "trusted")
	rows := serversOnly(discoverForTest("alice", home))
	found := map[string]bool{}
	for _, row := range rows {
		found[row.ServerName] = true
		if row.Client != "codex" {
			t.Errorf("%s: client = %q, want codex", row.ServerName, row.Client)
		}
	}
	for _, want := range []string{"project_scoped", "profile_scoped", "user_scoped"} {
		if !found[want] {
			t.Errorf("missing %q; found %v", want, found)
		}
	}
	if len(found) != 3 {
		t.Errorf("an unrelated config.toml was picked up: %v", found)
	}
}

// The budget running out mid-home has to be reported, by either route.
//
// Two paths reach it and only one was covered. Pass 1 breaking early was handled. Pass 1
// *completing* while the deadline passed during its final read was not: the range just ended,
// no break fired, and the Pass 2 guard then skipped the walk silently. A home whose last
// direct read was slow -- the network-backed case the budget exists for -- returned partial
// rows that looked complete. One diagnostic after Pass 1 now covers both.
func TestDiscoverForHomeReportsAnExhaustedBudget(t *testing.T) {
	home := buildFakeHome(t, map[string]string{
		".cursor/mcp.json": `{"mcpServers":{"maybe-read":{"command":"npx","args":["x"]}}}`,
	})
	for _, testCase := range []struct {
		name   string
		budget time.Duration
	}{
		// Breaks on the first iteration of Pass 1.
		{"already exhausted", -1 * time.Second},
		// Positive on entry, gone by the time Pass 2 is considered. Whether this breaks
		// mid-loop or completes and fails the guard depends on how fast the opens are, which
		// is the point: both routes must report.
		{"expires during pass 1", 1 * time.Nanosecond},
	} {
		rows := withoutStandingNotes(discoverForHome(context.Background(),
			fsscan.UserHome{Name: "alice", Path: home}, time.Now().Add(testCase.budget)))
		var diagnostics int
		for _, row := range rows {
			if row.Warning.empty() {
				continue
			}
			diagnostics++
			// Equality on the code, not a substring of the sentence. The old assertion
			// matched "scan truncated" anywhere in the text, so it passed for any message
			// containing that phrase and would have kept passing if the cause changed.
			if row.Warning.Code != warnBudgetExhaustedInHome &&
				row.Warning.Code != warnBudgetExhaustedOpening {
				t.Errorf("%s: warning does not name an exhausted budget: %q",
					testCase.name, row.Warning.Code)
			}
			if row.Transport != "unknown" || row.Confidence != "low" {
				t.Errorf("%s: diagnostic breaks the identity contract: %+v", testCase.name, row)
			}
		}
		if diagnostics != 1 {
			t.Errorf("%s: want exactly one diagnostic, got %d: %+v",
				testCase.name, diagnostics, rows)
		}
	}
}

// The home open is charged against the query deadline rather than running outside it.
//
// discoverForHome took a remaining duration and re-based it after opening the home, so the
// open -- which on a network-backed or automounted home blocks for the mount timeout -- cost
// nothing and the home then received the whole budget again. Once per home, that compounds
// across a host. It takes an absolute deadline now, and checks it after the open.
func TestHomeOpenIsChargedAgainstTheDeadline(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
		[]byte(`{"mcpServers":{"x":{"command":"npx"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A deadline already past when the function is entered. Under a duration this arrived as
	// a positive budget and the whole home was walked.
	rows := withoutStandingNotes(discoverForHome(context.Background(),
		fsscan.UserHome{Name: "alice", Path: home}, time.Now().Add(-time.Second)))
	if len(rows) == 0 {
		t.Fatal("an exhausted deadline produced no row at all, which reads as an account " +
			"with no configuration")
	}
	for _, row := range rows {
		if row.Warning.empty() {
			t.Errorf("a server row was produced after the deadline had passed: %+v", row)
		}
	}
}
