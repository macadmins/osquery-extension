// Package touchid implements two osquery tables that report macOS Touch ID
// state, populated from bioutil(1) and ioreg(8):
//
//   - touchid_system_config: machine-wide Touch ID / Secure Enclave posture,
//     plus whether a usable fingerprint sensor (built-in or an attached Touch
//     ID accessory) is actually present.
//   - touchid_user_config: per-user Touch ID configuration and the number of
//     enrolled fingerprints.
//
// Apple Silicon only. bioutil reports Touch ID state; the sensor-presence
// columns come from the IORegistry. Both tables shell out via an injected
// utils.CmdRunner so they are unit-testable without touching real binaries.
package touchid

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
)

const (
	bioutilPath = "/usr/bin/bioutil"
	ioregPath   = "/usr/sbin/ioreg"
	dsclPath    = "/usr/bin/dscl"
	sysctlPath  = "/usr/sbin/sysctl"
)

// minHumanUID / maxHumanUID are the inclusive bounds for real (non-system)
// local accounts. macOS reserves uids below 500 for system/service accounts;
// the first human account is 501. Accounts above 60000 (e.g. transient /
// Setup Assistant accounts) are excluded. The filter keeps uids in
// [minHumanUID, maxHumanUID].
const (
	minHumanUID = 501
	maxHumanUID = 60000
)

// maxScanLine is the per-line buffer cap for the parsers below. bioutil/dscl
// lines are short, but a generous cap avoids bufio.Scanner's default 64KiB
// bufio.ErrTooLong on unexpectedly long output, which would otherwise truncate
// a parse silently.
const maxScanLine = 1 << 20 // 1 MiB

// newLineScanner returns a line scanner over out with an enlarged buffer so a
// long line cannot silently truncate the parse. Callers should check Err()
// after the loop.
func newLineScanner(out []byte) *bufio.Scanner {
	s := bufio.NewScanner(bytes.NewReader(out))
	s.Buffer(make([]byte, 0, 64*1024), maxScanLine)
	return s
}

// parseBioutil parses the "Label: value" lines emitted by `bioutil -r` /
// `bioutil -r -s` into a map keyed by label. Keying on the label text (rather
// than line position) keeps the tables correct on macOS releases that add
// configuration lines. Section headers ("System Touch ID configuration:") and
// the trailing "Operation performed successfully." line have no value after the
// colon and are skipped.
// parseBioutil returns the parsed fields and ok=false if a scanner read error
// left the output only partially parsed (so callers can treat the result as
// unknown rather than trusting a truncated parse).
func parseBioutil(out []byte) (map[string]string, bool) {
	fields := make(map[string]string)
	s := newLineScanner(out)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue
		}
		fields[key] = val
	}
	if s.Err() != nil {
		return nil, false
	}
	return fields, true
}

// boolField returns "1" if the named bioutil field equals "1", else "0".
// bioutil reports these flags as the literal characters 0/1. Use this only for
// fields bioutil is guaranteed to emit; for fields that may be absent (and
// where absent must mean "unknown", not "disabled"), use nullableBoolField.
func boolField(fields map[string]string, key string) string {
	if fields[key] == "1" {
		return "1"
	}
	return "0"
}

// nullableBoolField returns "1"/"0" when the key is present, or "" (NULL) when
// it is absent — so a field bioutil did not emit (e.g. on a macOS version that
// omits it) is reported as unknown rather than silently "disabled".
func nullableBoolField(fields map[string]string, key string) (string, bool) {
	v, ok := fields[key]
	if !ok {
		return "", false
	}
	if v == "1" {
		return "1", true
	}
	return "0", true
}

// boolValue renders a Go bool as osquery's "1"/"0" integer-column convention.
func boolValue(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ioregClassPresent reports whether the IORegistry contains at least one
// instance of the given class. `ioreg -a -r -c <class>` emits a plist array of
// matched nodes, or empty output when the class has no instances. We unmarshal
// to a slice and check its length; empty/unparseable output is treated as "not
// present".
func ioregClassPresent(cmder utils.CmdRunner, class string) (bool, error) {
	buf, err := cmder.RunCmd(ioregPath, "-a", "-r", "-c", class)
	if err != nil {
		return false, fmt.Errorf("could not run ioreg for %s: %w", class, err)
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		// No instances: ioreg prints nothing.
		return false, nil
	}
	var nodes []map[string]interface{}
	if err := plist.Unmarshal(buf, &nodes); err != nil {
		// Unexpected shape — be conservative and report not present rather than
		// erroring the whole table.
		return false, nil
	}
	return len(nodes) > 0, nil
}

// SensorPresent reports whether the Mac has a usable Touch ID fingerprint
// sensor: a built-in one (laptops register an AppleBiometricSensor node) OR an
// attached external one (a Magic Keyboard with Touch ID registers an
// AppleMesaAccessory node instead). This is the authoritative "can this Mac
// actually use Touch ID" signal — bioutil's compatibility/enabled flags are "1"
// on every Apple Silicon Mac (the Secure Enclave is on-die) even on a
// keyboard-less Mac mini/Studio with no sensor at all. Both touchid_system_config
// and touchid_user_config gate on this so a sensor-less Mac is handled
// consistently. The accessory half is a live signal: a disconnected Touch ID
// keyboard reads as absent until it reconnects.
func SensorPresent(cmder utils.CmdRunner) (bool, error) {
	builtin, err := ioregClassPresent(cmder, "AppleBiometricSensor")
	if err != nil {
		return false, err
	}
	if builtin {
		return true, nil
	}
	// No built-in sensor — check for an attached external Touch ID accessory.
	// AppleMesaAccessory is a capability class, not a product-string match, so it
	// is name-, transport- (USB or Bluetooth) and localization-independent, and a
	// non-Touch-ID keyboard correctly reads as no sensor. The sibling classes
	// AppleMesaSEPDriver / AppleMesaResources are NOT usable here — they are SEP
	// scaffolding present on every Apple Silicon Mac.
	return ioregClassPresent(cmder, "AppleMesaAccessory")
}

// SystemConfig holds the machine-wide Touch ID posture for one host.
type SystemConfig struct {
	Compatible    string // touchid_compatible: bioutil reports Secure Enclave biometric support
	SecureEnclave string // secure_enclave: SoC model identifier
	Enabled       string // touchid_enabled
	Unlock        string // touchid_unlock
	Builtin       string // touchid_builtin: a built-in AppleBiometricSensor node exists (laptops)
	SensorPresent string // touchid_sensor_present: built-in OR an attached Touch ID accessory
}

// GetSystemConfig builds the single touchid_system_config row. bioutil supplies
// the compatibility/enabled/unlock flags; ioreg supplies the hardware-presence
// flags. The two ioreg-derived columns are independent of bioutil, so they are
// always populated even when bioutil fails.
func GetSystemConfig(cmder utils.CmdRunner) (*SystemConfig, error) {
	cfg := &SystemConfig{
		Compatible:    "0",
		Enabled:       "0",
		Unlock:        "0",
		Builtin:       "0",
		SensorPresent: "0",
	}

	// secure_enclave is the SoC / model identifier (e.g. "Mac16,5"). sysctl
	// returns it directly and cheaply; we avoid system_profiler here because it
	// can take seconds and would add noticeable latency to every query.
	if out, err := cmder.RunCmd(sysctlPath, "-n", "hw.model"); err == nil {
		cfg.SecureEnclave = strings.TrimSpace(string(out))
	}

	if out, err := cmder.RunCmd(bioutilPath, "-r", "-s"); err == nil {
		if fields, ok := parseBioutil(out); ok {
			// Derive compatible from the field VALUE, not merely its presence:
			// if bioutil ever emits "Biometrics functionality: 0" we must report
			// touchid_compatible=0, not 1. (Note: this column is "1" on every
			// Apple Silicon Mac regardless — use touchid_builtin /
			// touchid_sensor_present to detect an actual fingerprint sensor.)
			cfg.Compatible = boolField(fields, "Biometrics functionality")
			cfg.Enabled = boolField(fields, "Biometrics functionality")
			cfg.Unlock = boolField(fields, "Biometrics for unlock")
		}
	}

	// Built-in sensor: laptops expose one or more AppleBiometricSensor nodes;
	// keyboard-less desktops expose none. NOTE: touchid_compatible above is "1"
	// on every Apple Silicon Mac (the Secure Enclave is on-die), so it cannot
	// distinguish a Mac that has a fingerprint sensor from a keyboard-less
	// desktop — that is what touchid_builtin / touchid_sensor_present are for.
	builtin, err := ioregClassPresent(cmder, "AppleBiometricSensor")
	if err != nil {
		return nil, err
	}
	cfg.Builtin = boolValue(builtin)

	// Any usable sensor (built-in OR an attached Touch ID accessory) via the
	// shared SensorPresent helper, so touchid_system_config and touchid_user_config
	// agree on what "has a sensor" means.
	sensorPresent, err := SensorPresent(cmder)
	if err != nil {
		return nil, err
	}
	cfg.SensorPresent = boolValue(sensorPresent)

	return cfg, nil
}

// TouchIDSystemConfigColumns is the schema for touchid_system_config.
func TouchIDSystemConfigColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("touchid_compatible"),
		table.TextColumn("secure_enclave"),
		table.IntegerColumn("touchid_enabled"),
		table.IntegerColumn("touchid_unlock"),
		table.IntegerColumn("touchid_builtin"),
		table.IntegerColumn("touchid_sensor_present"),
	}
}

// TouchIDSystemConfigGenerate is the osquery generate function for
// touchid_system_config.
func TouchIDSystemConfigGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	cfg, err := GetSystemConfig(utils.NewRunner().Runner)
	if err != nil {
		return nil, err
	}
	return []map[string]string{{
		"touchid_compatible":     cfg.Compatible,
		"secure_enclave":         cfg.SecureEnclave,
		"touchid_enabled":        cfg.Enabled,
		"touchid_unlock":         cfg.Unlock,
		"touchid_builtin":        cfg.Builtin,
		"touchid_sensor_present": cfg.SensorPresent,
	}}, nil
}

// parseFingerprintCounts extracts enrolled-template counts from `bioutil -c`
// (single user) or `bioutil -c -s` (all enrolled users, root) output, keyed by
// uid. Lines look like "User 501:\t1 biometric template(s)". Users with zero
// enrolled templates do not appear in `-c -s` output, so a uid absent from the
// returned map should be treated as count 0 when ok is true. ok is false if a
// scanner read error left the output only partially parsed, so the caller can
// treat the counts as unknown (NOT "everyone has 0") rather than trusting a
// truncated parse.
func parseFingerprintCounts(out []byte) (map[string]int, bool) {
	counts := make(map[string]int)
	s := newLineScanner(out)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 || fields[0] != "User" {
			continue
		}
		uid := strings.TrimSuffix(fields[1], ":")
		if _, err := strconv.Atoi(uid); err != nil {
			continue
		}
		for i, f := range fields {
			if strings.HasPrefix(f, "biometric") && i > 0 {
				if n, err := strconv.Atoi(fields[i-1]); err == nil {
					counts[uid] = n
				}
				break
			}
		}
	}
	if s.Err() != nil {
		return nil, false
	}
	return counts, true
}

// parseLocalUIDs parses `dscl . -list /Users UniqueID` (two columns: account
// name, uid) and returns the uids of real local accounts within the human-uid
// range.
func parseLocalUIDs(out []byte) []string {
	var uids []string
	s := newLineScanner(out)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < minHumanUID || n > maxHumanUID {
			continue
		}
		uids = append(uids, fields[1])
	}
	if s.Err() != nil {
		return nil
	}
	return uids
}

// uidExists is injected so tests don't depend on real local accounts.
type uidExists func(uid string) bool

func defaultUIDExists(uid string) bool {
	_, err := user.LookupId(uid)
	return err == nil
}

// UserConfig is one touchid_user_config row.
type UserConfig struct {
	UID                    string
	FingerprintsRegistered string // empty when unknown (e.g. -c -s could not run)
	Unlock                 string // empty when unknown (user not logged in)
	ApplePay               string
	EffectiveUnlock        string
	EffectiveApplePay      string
}

// GetUserConfigs builds touchid_user_config rows. Two bioutil data sources with
// different access models are combined:
//
//   - Enrolled fingerprint count: `bioutil -c -s` (run as root, the context
//     osquery's extension runner provides) reports counts for all enrolled
//     users at once and does not require the user to be logged in.
//   - Config flags: `bioutil -r` must run inside the target user's login
//     session, which only exists while that user is logged in. When it cannot
//     be read the flag columns are left empty (unknown) rather than "0", so an
//     enabled-but-logged-out user is not misreported as disabled.
//
// sensorPresent gates the whole table: a Mac with no usable Touch ID sensor
// emits no rows at all. User enumeration (dscl) is independent of the hardware,
// so without this gate a keyboard-less Mac mini/Studio would report a row per
// local account with every Touch ID column NULL — noise that callers would have
// to filter on touchid_system_config.touchid_sensor_present themselves. Handling
// it here keeps that knowledge in one place.
//
// targetUIDs, when non-empty, restricts the rows (from a `WHERE uid =`
// constraint); otherwise every real local account is reported. perUserRunner
// runs `bioutil -r` as a given uid; it is injected for testability.
func GetUserConfigs(
	cmder utils.CmdRunner,
	sensorPresent bool,
	exists uidExists,
	targetUIDs []string,
	perUserRunner func(uid string) ([]byte, error),
) ([]*UserConfig, error) {
	// No usable Touch ID sensor => no per-user Touch ID configuration to report.
	if !sensorPresent {
		return nil, nil
	}

	counts := map[string]int{}
	countsKnown := false
	if out, err := cmder.RunCmd(bioutilPath, "-c", "-s"); err == nil {
		// Only treat counts as known if parsing actually succeeded — a truncated
		// parse must not be reported as "everyone has 0 enrolled".
		counts, countsKnown = parseFingerprintCounts(out)
	}

	uids := targetUIDs
	if len(uids) == 0 {
		if out, err := cmder.RunCmd(dsclPath, ".", "-list", "/Users", "UniqueID"); err == nil {
			uids = parseLocalUIDs(out)
		}
	}

	var results []*UserConfig
	for _, uid := range uids {
		if _, err := strconv.Atoi(uid); err != nil || !exists(uid) {
			continue
		}

		row := &UserConfig{UID: uid}

		count, hasCount := counts[uid]
		if countsKnown {
			hasCount = true // absent from -c -s output means 0 enrolled
		}
		if hasCount {
			row.FingerprintsRegistered = strconv.Itoa(count)
		}

		if out, err := perUserRunner(uid); err == nil {
			if fields, ok := parseBioutil(out); ok {
				// Use nullableBoolField so a flag bioutil did not emit (e.g. on a
				// macOS version that omits it) is reported as unknown (NULL),
				// not silently "0"/disabled.
				row.Unlock, _ = nullableBoolField(fields, "Biometrics for unlock")
				row.ApplePay, _ = nullableBoolField(fields, "Biometrics for ApplePay")
				row.EffectiveUnlock, _ = nullableBoolField(fields, "Effective biometrics for unlock")
				row.EffectiveApplePay, _ = nullableBoolField(fields, "Effective biometrics for ApplePay")

				// bioutil's "Effective" flags can report 1 with no fingerprints
				// enrolled. Only correct this when the count is known to be 0 and
				// the effective flags were actually present.
				if hasCount && count == 0 {
					if row.EffectiveUnlock != "" {
						row.EffectiveUnlock = "0"
					}
					if row.EffectiveApplePay != "" {
						row.EffectiveApplePay = "0"
					}
				}
			}
		}

		results = append(results, row)
	}

	return results, nil
}

// TouchIDUserConfigColumns is the schema for touchid_user_config.
func TouchIDUserConfigColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("uid"),
		table.IntegerColumn("fingerprints_registered"),
		table.IntegerColumn("touchid_unlock"),
		table.IntegerColumn("touchid_applepay"),
		table.IntegerColumn("effective_unlock"),
		table.IntegerColumn("effective_applepay"),
	}
}

// uidConstraints extracts the values of all `uid =` constraints from the query.
func uidConstraints(queryContext table.QueryContext) []string {
	var uids []string
	if c, ok := queryContext.Constraints["uid"]; ok {
		for _, con := range c.Constraints {
			if con.Operator == table.OperatorEquals {
				uids = append(uids, con.Expression)
			}
		}
	}
	return uids
}

// defaultPerUserRunner runs `bioutil -r` inside the target uid's login session
// via `launchctl asuser`, which is required because per-user Touch ID config
// lives in that user's Secure Enclave keybag context.
func defaultPerUserRunner(cmder utils.CmdRunner) func(uid string) ([]byte, error) {
	return func(uid string) ([]byte, error) {
		return cmder.RunCmd("/bin/launchctl", "asuser", uid, bioutilPath, "-r")
	}
}

// TouchIDUserConfigGenerate is the osquery generate function for
// touchid_user_config.
func TouchIDUserConfigGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	runner := utils.NewRunner().Runner

	// A Mac with no usable Touch ID sensor has no per-user Touch ID config to
	// report, so the table yields no rows (rather than a NULL-filled row per
	// local account). touchid_system_config.touchid_sensor_present exposes the
	// same signal for queries that want it explicitly.
	sensorPresent, err := SensorPresent(runner)
	if err != nil {
		return nil, err
	}

	configs, err := GetUserConfigs(runner, sensorPresent, defaultUIDExists, uidConstraints(queryContext), defaultPerUserRunner(runner))
	if err != nil {
		return nil, err
	}

	return userConfigsToRows(configs), nil
}

// userConfigsToRows shapes UserConfig values into osquery row maps. Each column
// is set only when its value is known; an unknown IntegerColumn must be omitted
// (NULL) rather than set to "" (an invalid integer). Flags are checked
// independently — any one can be individually absent (e.g. a macOS version that
// omits the ApplePay line), so one flag's presence must not be used as a proxy
// for the others. Extracted from the generate function so this NULL-omission
// behavior is unit-testable.
func userConfigsToRows(configs []*UserConfig) []map[string]string {
	var results []map[string]string
	for _, c := range configs {
		row := map[string]string{"uid": c.UID}
		setIfKnown := func(key, val string) {
			if val != "" {
				row[key] = val
			}
		}
		setIfKnown("fingerprints_registered", c.FingerprintsRegistered)
		setIfKnown("touchid_unlock", c.Unlock)
		setIfKnown("touchid_applepay", c.ApplePay)
		setIfKnown("effective_unlock", c.EffectiveUnlock)
		setIfKnown("effective_applepay", c.EffectiveApplePay)
		results = append(results, row)
	}
	return results
}
