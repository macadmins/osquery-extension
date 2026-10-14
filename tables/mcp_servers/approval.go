package mcp_servers

import (
	"encoding/json"
	"path/filepath"
	"slices"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Whether Claude Code will actually run a server declared in a project's .mcp.json.
//
// Four sources of evidence and three different combining rules, which is why this is a
// resolver rather than a lookup:
//
//   - `disabledMcpjsonServers` is a union across every source and beats everything. Claude
//     documents that an entry in any settings file rejects the server, so a disagreement
//     between sources resolves to "will not run".
//   - `enabledMcpjsonServers` is a union of the sources eligible to approve.
//   - `enableAllProjectMcpServers` is a scalar and follows settings *precedence*: a
//     project-local `false` overrides a user-level `true`. Merging it with OR made an
//     explicit opt-out unrepresentable, because an omitted key and a `false` collapsed to the
//     same value.
//
// Eligibility is separate from readability, and has three states rather than two.
//
// Claude ignores repository-provided approvals in a folder whose trust dialog has not been
// accepted, so a committed `.claude/settings.json` cannot approve its own servers in an
// untrusted project -- otherwise any repository could approve its own MCP servers simply by
// shipping a settings file. Rejections still apply: refusing to run something needs no trust.
//
// `.claude/settings.local.json` is the third state. Claude applies its approvals only when the
// file is *untracked*, and it establishes that by running git -- which it does only in a
// trusted folder, or in the configuration home. This table cannot run git: a subprocess per
// project, per account, per scheduled query is not a cost an inventory may impose, and the
// answer would be a race besides. So where that file would otherwise approve, the honest
// answer is `unknown`: Claude might run the server and this scan cannot tell.
//
// An earlier version granted those approvals outright, with a comment reasoning that an
// untracked file belongs to whoever is running Claude. That described the behaviour before
// v2.1.207, which applied them even in a folder never trusted. It is no longer true, and the
// consequence was a clean `enabled` row for an ordinary untrusted project whose only approval
// came from a file Claude would have ignored.

// approvalEvidence is one coherent set of approval facts.
//
// Separated from claudeApproval so the same resolution can be run twice -- once with the
// uncertain source applied and once without -- which is what makes an undecidable case
// report itself instead of picking a side.
type approvalEvidence struct {
	// EnableAll is a pointer so an omitted key and an explicit `false` stay distinguishable.
	// Collapsing them is what let a lower-precedence `true` survive an explicit opt-out.
	EnableAll *bool
	Enabled   []string
	Disabled  []string
}

// overlay applies a higher-precedence source over a lower one.
//
// Name lists union because that is their documented rule; the scalar takes the higher
// source's value when it set one, which is what makes a project-local opt-out effective.
func (lower approvalEvidence) overlay(higher approvalEvidence) approvalEvidence {
	out := approvalEvidence{
		EnableAll: lower.EnableAll,
		Enabled:   append(append([]string(nil), lower.Enabled...), higher.Enabled...),
		Disabled:  append(append([]string(nil), lower.Disabled...), higher.Disabled...),
	}
	if higher.EnableAll != nil {
		out.EnableAll = higher.EnableAll
	}
	return out
}

// resolve answers for one server name, assuming this evidence is the whole of it.
func (e approvalEvidence) resolve(serverName string) approvalState {
	return e.resolveUnder(approvalEvidence{}, serverName)
}

// resolveUnder answers as if higher were overlaid on e, without building the overlay.
//
// Separate from overlay() because the two have different lifetimes. Accumulating sources
// happens once per settings file and wants a real merged value; resolving happens once per
// server and does not -- every use of the merged lists here is a membership test, so
// overlay()'s two concatenated slices were allocated and discarded per row. Those lists are
// fixed while a project's rows are evaluated, which made the cost server count x list
// length: an 889 KB settings file naming 100,000 servers, under the 1 MiB read cap, copied
// 1.6 MB per lookup. Bounding the input does not bound a product.
//
// Checking the two lists in sequence is the same answer, not an approximation. What resolve()
// encodes is precedence between *categories* -- every rejection beats every approval, which
// beats the blanket scalar -- and within a category the loops return on first match, so
// concatenation order was never observable.
func (e approvalEvidence) resolveUnder(higher approvalEvidence, serverName string) approvalState {
	if slices.Contains(e.Disabled, serverName) || slices.Contains(higher.Disabled, serverName) {
		return approvalDisabled
	}
	// An individual approval before the blanket one, so an `enableAllProjectMcpServers:
	// false` does not revoke a name someone approved explicitly.
	if slices.Contains(e.Enabled, serverName) || slices.Contains(higher.Enabled, serverName) {
		return approvalEnabled
	}
	// The scalar follows source precedence rather than unioning, so the higher source's
	// value stands whenever it set one.
	enableAll := e.EnableAll
	if higher.EnableAll != nil {
		enableAll = higher.EnableAll
	}
	if enableAll != nil && *enableAll {
		return approvalEnabled
	}
	return approvalNotApproved
}

// claudeApproval is the approval evidence gathered for one project.
type claudeApproval struct {
	// Certain is everything whose eligibility is established, plus every rejection from
	// anywhere -- a `disabledMcpjsonServers` entry rejects from any settings file, so its
	// weight does not depend on the source being eligible to *approve*.
	Certain approvalEvidence

	// Pending is the approving half of a source whose eligibility this table cannot
	// establish: `.claude/settings.local.json`, which Claude applies only when the file is
	// untracked and which it checks by running git. It sits at higher precedence than
	// everything in Certain, because that file is the highest-precedence project source.
	Pending    approvalEvidence
	HasPending bool

	// Known is false when a source that could have carried approval existed and could not be
	// read, or was refused rather than absent. It gates the approving answers only: a
	// rejection that was read is decisive whatever else failed.
	Known bool
}

// overlay applies a higher-precedence settings source over a lower one.
func (lower claudeApproval) overlay(higher claudeApproval) claudeApproval {
	out := claudeApproval{
		Certain: lower.Certain.overlay(higher.Certain),
		Known:   lower.Known && higher.Known,
	}
	// At most one source is uncertain in practice -- the local settings file, and there is
	// one per project -- so the later sighting wins rather than the two being combined.
	switch {
	case higher.HasPending:
		out.Pending, out.HasPending = higher.Pending, true
	case lower.HasPending:
		out.Pending, out.HasPending = lower.Pending, true
	}
	return out
}

// merge folds in a source with no precedence relationship to this one -- the project-history
// arrays, and the per-origin sightings deduplication produces.
func (a claudeApproval) merge(other claudeApproval) claudeApproval {
	out := a.overlay(claudeApproval{Certain: other.Certain, Known: other.Known})
	if other.HasPending && !a.HasPending {
		out.Pending, out.HasPending = other.Pending, true
	}
	// Scalars cannot be resolved by precedence here because there is none, so a set value
	// wins over an unset one.
	if a.Certain.EnableAll == nil {
		out.Certain.EnableAll = other.Certain.EnableAll
	}
	return out
}

// stateFor resolves one server name against the gathered evidence.
//
// Resolved twice when an uncertain source is present: once as if it is eligible and once as
// if it is not. A definite answer is asserted only when both outcomes agree, which is the
// property that matters and the one a single accumulated "would approve" list could not
// express.
//
// The case that forced it: account settings saying `enableAllProjectMcpServers: true` and a
// trusted project's local file saying `false`. Treating the uncertain source as approvals-only
// kept the account-wide `true` and reported a clean `enabled` -- but if that file is eligible
// its explicit opt-out wins and the answer is the opposite. Both readings are live, so neither
// may be published as fact.
//
// serverName must be the name the configuration file spelled, not the redacted form: the
// arrays hold original names, and redaction is many-to-one so it cannot be an identity key.
func (a claudeApproval) stateFor(serverName string) approvalState {
	// Rejection first, and before the certainty gate. A disabled entry that was successfully
	// read rejects the server however much other evidence is missing, which is both what
	// Claude documents and the safe direction.
	if slices.Contains(a.Certain.Disabled, serverName) {
		return approvalDisabled
	}
	// Only now does missing evidence matter. An approval this scan could not read is not an
	// absence of approval, and reporting not_approved on that basis is a positive claim about
	// a decision nobody observed.
	if !a.Known {
		return approvalUnknown
	}
	ifIneligible := a.Certain.resolve(serverName)
	if !a.HasPending {
		return ifIneligible
	}
	if ifEligible := a.Certain.resolveUnder(a.Pending, serverName); ifEligible == ifIneligible {
		return ifEligible
	}
	return approvalUnknown
}

// mcpApprovalSettings are the three keys a settings file can carry.
//
// Decoded into exactly these fields, for the reason every reader in this package decodes
// narrowly: a settings file also holds permissions, hooks, environment and model
// configuration, and a map would put all of it one field access from a column.
type mcpApprovalSettings struct {
	EnableAllProjectMcpServers *bool    `json:"enableAllProjectMcpServers"`
	EnabledMcpjsonServers      []string `json:"enabledMcpjsonServers"`
	DisabledMcpjsonServers     []string `json:"disabledMcpjsonServers"`
}

// approvalEligibility says how much weight a source's approvals carry. Rejections always
// apply and are not affected by it.
type approvalEligibility int

const (
	// cannotApprove: Claude ignores this source's approvals here. A committed settings file
	// in a folder whose trust dialog was never accepted.
	cannotApprove approvalEligibility = iota
	// mayApprove: Claude applies this source's approvals.
	mayApprove
	// eligibilityUncertain: Claude applies them subject to a condition this table cannot
	// check -- the file being untracked, which Claude determines by running git. Approvals
	// from such a source yield `unknown`.
	eligibilityUncertain
)

// approvalSource is one settings file to consult.
type approvalSource struct {
	// relFile is relative to base.
	relFile string

	eligibility approvalEligibility
}

// readApprovalSettings reads the three keys from one settings file.
//
// projRel is the contained project directory, or "" for a file relative to the home itself.
// When set, the read goes through fsscan.ReadProjectFile rather than ReadBoundedUnder: that
// is the guard carrying the cloud-directory refusal and the placeholder check, and reading a
// project's settings without it defeated the protection for the whole project. The settings
// pass runs *before* the configuration probes, so it was the first thing to touch a
// provider-backed file and could trigger the download the later probe would have refused.
//
// Absence is success with nothing to report: most accounts and most projects have no settings
// file, and treating that as unknown would make every ordinary row unknown. A file that
// exists and cannot be read or parsed sets Known false and returns a warning naming the
// class, because "unknown" alone leaves an administrator unable to tell malformed JSON from
// denied access from an oversized file.
func readApprovalSettings(home, projRel string, source approvalSource) (claudeApproval, []warning) {
	// The source's own path travels with its warnings, so a row naming only the project
	// directory cannot leave an administrator guessing which of two settings files failed.
	// Set on every warning this function returns, at the one point that knows.

	var (
		data []byte
		err  error
	)
	opts := probeReadOpts(MaxFileSize)
	if projRel == "" {
		data, err = fsscan.ReadBoundedUnder(home, filepath.FromSlash(source.relFile), opts)
	} else {
		data, err = fsscan.ReadProjectFile(home, projRel, source.relFile, opts)
	}
	if err != nil {
		// Genuine absence is evidence: there is no file, so it records no approval and the
		// answer is known-empty. A *refusal* is not, and IsExpectedAbsent covers both --
		// it treats a symlink or reparse refusal as benign absence, which is right for
		// deciding whether to warn and wrong for deciding what is known. A symlinked
		// settings file whose target approved every server was reported not_approved: a
		// definitive negative drawn from evidence the table declined to read.
		//
		// The refusal stays silent, as the no-follow policy intends -- a warning naming it
		// would publish the attacker's path -- but it leaves the answer unknown.
		if fsscan.ClassifyError(err) == fsscan.ClassAbsent {
			return claudeApproval{Known: true}, nil
		}
		if fsscan.IsExpectedAbsent(err) {
			return claudeApproval{}, nil
		}
		return claudeApproval{}, []warning{{
			Code: warnApprovalSettingsUnreadable, Class: fsscan.ClassifyError(err),
			Key: settingsSourceKey(source.relFile)}}
	}
	var doc mcpApprovalSettings
	if err := json.Unmarshal(stripBOM(data), &doc); err != nil {
		// The real parser metadata, through the same machinery every other parse failure in
		// this table uses. Labelling every decode error shapeNotAnObject was wrong about
		// most of them: `{"enabledMcpjsonServers":123}` is a perfectly good top-level
		// object with one field of the wrong type, and an administrator told the top level
		// is not an object goes looking for the wrong thing. parseWarning reads the offset,
		// the field name and a validated value kind, and never the parser's message.
		detail := parseWarning(err)
		detail.Code = warnApprovalSettingsUnreadable
		// The field name parseWarning may have taken from our own struct is replaced by the
		// file's identity, which is the more useful of the two here: there are two candidate
		// files and the row names only the directory. Both are bytes this package chose.
		detail.Key = settingsSourceKey(source.relFile)
		return claudeApproval{}, []warning{detail}
	}
	// Rejections are always certain, whatever the source's eligibility to approve.
	out := claudeApproval{
		Certain: approvalEvidence{Disabled: doc.DisabledMcpjsonServers},
		Known:   true,
	}
	switch source.eligibility {
	case mayApprove:
		out.Certain.Enabled = doc.EnabledMcpjsonServers
		out.Certain.EnableAll = doc.EnableAllProjectMcpServers
	case eligibilityUncertain:
		// Held separately, with the scalar's omitted/true/false distinction intact: an
		// explicit `false` here is an opt-out that overrides a lower-precedence `true` if
		// this file turns out to be eligible, and collapsing it to a bool made that
		// unrepresentable.
		out.Pending = approvalEvidence{
			Enabled:   doc.EnabledMcpjsonServers,
			EnableAll: doc.EnableAllProjectMcpServers,
		}
		out.HasPending = true
	case cannotApprove:
		// Rejections only; the approving fields are dropped rather than deferred, because
		// Claude does not apply them here at all.
	}
	return out, nil
}

// userApprovalSettings reads the account-wide settings file.
//
// `~/.claude/settings.local.json` is deliberately not read here. Claude documents it at
// project scope, and it appears in a home only because that home was opened as a project, so
// treating it as account-wide applied one project's decisions to every project.
func userApprovalSettings(home string) (claudeApproval, []warning) {
	// Always eligible. Claude documents approvals from the user settings file, managed
	// settings and `--settings` as applying even in an untrusted folder.
	return readApprovalSettings(home, "",
		approvalSource{relFile: claudeSettingsRel, eligibility: mayApprove})
}

// projectApprovalSettings reads the two settings files inside a project, in precedence order.
//
// trusted says whether this project's trust dialog was accepted, and the two files answer to
// it differently.
//
// `.claude/settings.json` is part of the clone, so honouring its approvals in an untrusted
// folder would let any repository approve its own MCP servers. Trust is the whole of its
// eligibility.
//
// `.claude/settings.local.json` is subject to two conditions, and this table can establish
// neither with confidence. Claude applies its approvals only when the file is untracked, and
// it checks that by running git -- which it does only in a trusted folder, or when the folder
// is the configuration home. So: in an untrusted project Claude waits for the trust dialog
// and the approvals do not apply; in a trusted one, or in the configuration home, they apply
// if untracked, and whether they are is a question this table will not answer by spawning git
// per project per account per query. That case is `eligibilityUncertain`, which resolves to
// `unknown`.
//
// The configuration home is the account's own home directory, which is `projRel == "."`.
// CLAUDE_CONFIG_DIR can name another, and this table cannot read it -- the environment belongs
// to the daemon's account, not the scanned one, the same limitation recorded for
// XDG_CONFIG_HOME. A project relocated that way is treated as an ordinary project, so its
// local approvals read as unknown rather than applying; that is the safe direction.
//
// Applied lowest precedence first, so the local file's scalar overrides the committed one's.
func projectApprovalSettings(home, projRel string, trusted bool) (claudeApproval, []warning) {
	committed := cannotApprove
	if trusted {
		committed = mayApprove
	}
	// The home itself is the configuration home, where Claude reads the local file before the
	// trust dialog. Elsewhere the file needs trust first.
	local := cannotApprove
	if trusted || projRel == "." {
		local = eligibilityUncertain
	}
	out := claudeApproval{Known: true}
	var warnings []warning
	for _, source := range []approvalSource{
		{relFile: filepath.Join(".claude", "settings.json"), eligibility: committed},
		{relFile: filepath.Join(".claude", "settings.local.json"), eligibility: local},
	} {
		evidence, sourceWarnings := readApprovalSettings(home, projRel, source)
		out = out.overlay(evidence)
		warnings = append(warnings, sourceWarnings...)
	}
	return out, warnings
}

// settingsSourceKey names which settings file a warning concerns, in a form the warning
// catalogue admits.
//
// A fixed spelling per file rather than the path, because the path is partly the project
// directory and this package does not publish those -- and because the Key field is gated on
// a bare-identifier grammar, which a path would not satisfy. Two candidate files per project
// and one account-wide one, so three constants answer the question an administrator actually
// has: which file do I go and fix.
func settingsSourceKey(relFile string) string {
	switch filepath.Base(relFile) {
	case "settings.local.json":
		return "settings_local_json"
	case "settings.json":
		return "settings_json"
	default:
		return ""
	}
}
