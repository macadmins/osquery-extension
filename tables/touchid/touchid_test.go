package touchid

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real `bioutil -r -s` output on Apple Silicon (macOS 15+). The extra timeout
// lines would trip position-based parsing.
const systemBioutil = `System Touch ID configuration:
	Biometrics functionality: 1
	Biometrics for unlock: 1
	Biometric timeout (in seconds): 172800
	Match timeout (in seconds): 14400
	Passcode input timeout (in seconds): 561600
Operation performed successfully.`

const userBioutil = `User Touch ID configuration:
	Biometrics for unlock: 1
	Biometrics for ApplePay: 1
	Effective biometrics for unlock: 1
	Effective biometrics for ApplePay: 1
Operation performed successfully.`

// `bioutil -c -s` (root): one line per enrolled user.
const allCounts = "User 501:\t1 biometric template(s)\nUser 503:\t2 biometric template(s)\nOperation performed successfully."

// `sysctl -n hw.model` output: the SoC / model identifier, with a trailing
// newline (reported as secure_enclave).
const sysctlModel = "Mac16,5\n"

const dsclUsers = "_mbsetupuser  248\nroot  0\nalice  501\nbob  503\n"

// A minimal `ioreg -a -r -c <class>` plist: an array with one matched node.
// ioreg emits a plist array of matched IORegistry entries; for presence we only
// need len(array) > 0.
const ioregOneNode = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>IOClass</key>
		<string>AppleMesaAccessory</string>
	</dict>
</array>
</plist>`

// `ioreg -a -r -c <class>` for a class with no instances: empty output.
const ioregNoNode = ``

func TestParseBioutil(t *testing.T) {
	t.Parallel()
	f, ok := parseBioutil([]byte(systemBioutil))
	require.True(t, ok)
	assert.Equal(t, "1", f["Biometrics functionality"])
	assert.Equal(t, "1", f["Biometrics for unlock"])
	_, hasHeader := f["System Touch ID configuration"]
	assert.False(t, hasHeader, "header line should not parse as a field")
	_, hasFooter := f["Operation performed successfully"]
	assert.False(t, hasFooter, "footer line should not parse as a field")
}

func TestNullableBoolField(t *testing.T) {
	t.Parallel()
	fields := map[string]string{"on": "1", "off": "0"}

	v, ok := nullableBoolField(fields, "on")
	assert.True(t, ok)
	assert.Equal(t, "1", v)

	v, ok = nullableBoolField(fields, "off")
	assert.True(t, ok)
	assert.Equal(t, "0", v)

	// Absent key => unknown (NULL), not "0".
	v, ok = nullableBoolField(fields, "missing")
	assert.False(t, ok)
	assert.Equal(t, "", v)
}

func TestParseFingerprintCounts(t *testing.T) {
	t.Parallel()
	got, ok := parseFingerprintCounts([]byte(allCounts))
	require.True(t, ok)
	assert.Equal(t, map[string]int{"501": 1, "503": 2}, got)

	single, ok := parseFingerprintCounts([]byte("User 501:\t3 biometric template(s)\nOperation performed successfully."))
	require.True(t, ok)
	assert.Equal(t, 3, single["501"])

	empty, ok := parseFingerprintCounts([]byte("nonsense\nOperation performed successfully."))
	require.True(t, ok) // a well-formed read with no matching lines is still "known"
	assert.Empty(t, empty)
}

func TestParseLocalUIDs(t *testing.T) {
	t.Parallel()
	// Only human-range uids (501, 503) survive; system accounts are dropped.
	assert.Equal(t, []string{"501", "503"}, parseLocalUIDs([]byte(dsclUsers)))
}

func TestIORegClassPresent(t *testing.T) {
	t.Parallel()
	present := utils.MockCmdRunner{Output: ioregOneNode}
	ok, err := ioregClassPresent(present, "AppleMesaAccessory")
	require.NoError(t, err)
	assert.True(t, ok)

	absent := utils.MockCmdRunner{Output: ioregNoNode}
	ok, err = ioregClassPresent(absent, "AppleBiometricSensor")
	require.NoError(t, err)
	assert.False(t, ok)
}

// systemRunner mocks every command GetSystemConfig issues. builtinIOReg and
// mesaIOReg are the canned `ioreg -a -r -c <class>` outputs for the two classes.
func systemRunner(builtinIOReg, mesaIOReg string) utils.MultiMockCmdRunner {
	return utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/sbin/sysctl -n hw.model":                  {Output: sysctlModel},
			"/usr/bin/bioutil -r -s":                        {Output: systemBioutil},
			"/usr/sbin/ioreg -a -r -c AppleBiometricSensor": {Output: builtinIOReg},
			"/usr/sbin/ioreg -a -r -c AppleMesaAccessory":   {Output: mesaIOReg},
		},
	}
}

func TestGetSystemConfig_BuiltInSensor(t *testing.T) {
	t.Parallel()
	// Laptop: built-in AppleBiometricSensor present.
	cfg, err := GetSystemConfig(systemRunner(ioregOneNode, ioregNoNode))
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Compatible)
	assert.Equal(t, "Mac16,5", cfg.SecureEnclave)
	assert.Equal(t, "1", cfg.Enabled)
	assert.Equal(t, "1", cfg.Unlock)
	assert.Equal(t, "1", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetSystemConfig_AccessorySensor(t *testing.T) {
	t.Parallel()
	// Desktop with a Magic Keyboard with Touch ID: no built-in sensor, but an
	// AppleMesaAccessory node is present.
	cfg, err := GetSystemConfig(systemRunner(ioregNoNode, ioregOneNode))
	require.NoError(t, err)
	assert.Equal(t, "0", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetSystemConfig_NoSensor(t *testing.T) {
	t.Parallel()
	// Keyboard-less Mac mini / Studio: no sensor of any kind.
	cfg, err := GetSystemConfig(systemRunner(ioregNoNode, ioregNoNode))
	require.NoError(t, err)
	assert.Equal(t, "0", cfg.Builtin)
	assert.Equal(t, "0", cfg.SensorPresent)
	// bioutil still reports compatible=1 (on-die Secure Enclave) — which is
	// exactly why touchid_compatible is not a usable sensor-presence signal.
	assert.Equal(t, "1", cfg.Compatible)
}

func TestGetSystemConfig_CompatibleFromValue(t *testing.T) {
	t.Parallel()
	// If bioutil reports "Biometrics functionality: 0", touchid_compatible must
	// be "0" (derived from the value), not "1" from the key merely being present.
	bioutilOff := "System Touch ID configuration:\n\tBiometrics functionality: 0\n\tBiometrics for unlock: 0\nOperation performed successfully."
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/sbin/sysctl -n hw.model":                  {Output: sysctlModel},
			"/usr/bin/bioutil -r -s":                        {Output: bioutilOff},
			"/usr/sbin/ioreg -a -r -c AppleBiometricSensor": {Output: ioregNoNode},
			"/usr/sbin/ioreg -a -r -c AppleMesaAccessory":   {Output: ioregNoNode},
		},
	}
	cfg, err := GetSystemConfig(runner)
	require.NoError(t, err)
	assert.Equal(t, "0", cfg.Compatible)
	assert.Equal(t, "0", cfg.Enabled)
}

func TestGetSystemConfig_BioutilError(t *testing.T) {
	t.Parallel()
	// bioutil fails, but the ioreg-derived columns must still be populated.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/sbin/sysctl -n hw.model":                  {Output: sysctlModel},
			"/usr/bin/bioutil -r -s":                        {Err: errors.New("boom")},
			"/usr/sbin/ioreg -a -r -c AppleBiometricSensor": {Output: ioregOneNode},
			"/usr/sbin/ioreg -a -r -c AppleMesaAccessory":   {Output: ioregNoNode},
		},
	}
	cfg, err := GetSystemConfig(runner)
	require.NoError(t, err)
	assert.Equal(t, "Mac16,5", cfg.SecureEnclave)
	assert.Equal(t, "0", cfg.Compatible) // unknown -> default 0
	assert.Equal(t, "1", cfg.Builtin)
	assert.Equal(t, "1", cfg.SensorPresent)
}

func TestGetUserConfigs_AllAccounts(t *testing.T) {
	t.Parallel()
	// -c -s reports 501=1, 503=2; 502 absent => 0. Only 501 is "logged in"
	// (its -r succeeds); the others' -r errors but their counts still report.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s":                {Output: allCounts},
			"/usr/bin/dscl . -list /Users UniqueID": {Output: "alice 501\ncarol 502\nbob 503\n"},
		},
	}
	perUser := func(uid string) ([]byte, error) {
		if uid == "501" {
			return []byte(userBioutil), nil
		}
		return nil, errors.New("not logged in")
	}
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, true, exists, nil, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 3)

	byUID := map[string]*UserConfig{}
	for _, c := range configs {
		byUID[c.UID] = c
	}
	// 501: logged in, 1 fingerprint, flags populated.
	assert.Equal(t, "1", byUID["501"].FingerprintsRegistered)
	assert.Equal(t, "1", byUID["501"].Unlock)
	// 502: absent from -c -s => known 0; logged out => flags empty (NULL).
	assert.Equal(t, "0", byUID["502"].FingerprintsRegistered)
	assert.Equal(t, "", byUID["502"].Unlock)
	// 503: 2 fingerprints; logged out => flags empty.
	assert.Equal(t, "2", byUID["503"].FingerprintsRegistered)
	assert.Equal(t, "", byUID["503"].Unlock)
}

func TestGetUserConfigs_ConstraintAndZeroForcesEffective(t *testing.T) {
	t.Parallel()
	// uid 501 constrained; -c -s reports nobody enrolled (known 0). bioutil -r
	// claims effective=1, which the zero-fingerprint workaround must force to 0.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Output: "Operation performed successfully."},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, true, exists, []string{"501"}, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	c := configs[0]
	assert.Equal(t, "0", c.FingerprintsRegistered)
	assert.Equal(t, "0", c.EffectiveUnlock)
	assert.Equal(t, "0", c.EffectiveApplePay)
	// Configured (non-effective) flags stay as bioutil reported.
	assert.Equal(t, "1", c.Unlock)
}

func TestGetUserConfigs_CountUnknownPreservesEffective(t *testing.T) {
	t.Parallel()
	// -c -s fails (not root): count unknown. effective flags must be preserved
	// (the zero-fingerprint workaround must NOT fire on unknown counts).
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Err: errors.New("not root")},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, true, exists, []string{"501"}, perUser)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	c := configs[0]
	assert.Equal(t, "", c.FingerprintsRegistered) // unknown -> empty
	assert.Equal(t, "1", c.EffectiveUnlock)
}

func TestGetUserConfigs_SkipsNonexistentUID(t *testing.T) {
	t.Parallel()
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Output: allCounts},
		},
	}
	perUser := func(string) ([]byte, error) { return nil, errors.New("nope") }
	exists := func(string) bool { return false }

	configs, err := GetUserConfigs(runner, true, exists, []string{"99999"}, perUser)
	require.NoError(t, err)
	assert.Empty(t, configs)
}

func TestGetUserConfigs_NoSensorReturnsNoRows(t *testing.T) {
	t.Parallel()
	// A Mac with no usable Touch ID sensor (sensorPresent=false) must not emit
	// any per-user rows, even though dscl can still enumerate local accounts and
	// bioutil -c -s succeeds. User enumeration is independent of the hardware, so
	// without this gate the table would report a row per account on a sensor-less
	// Mac. This is handled in code (not punted to callers via touchid_sensor_present).
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s":                {Output: allCounts},
			"/usr/bin/dscl . -list /Users UniqueID": {Output: "alice 501\nbob 503\n"},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, false, exists, nil, perUser)
	require.NoError(t, err)
	assert.Empty(t, configs, "no rows when the Mac has no usable Touch ID sensor")
}

func TestGetUserConfigs_NoSensorWithConstraintReturnsNoRows(t *testing.T) {
	t.Parallel()
	// Even an explicit WHERE uid = constraint yields no rows on a sensor-less Mac.
	runner := utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"/usr/bin/bioutil -c -s": {Output: allCounts},
		},
	}
	perUser := func(string) ([]byte, error) { return []byte(userBioutil), nil }
	exists := func(string) bool { return true }

	configs, err := GetUserConfigs(runner, false, exists, []string{"501"}, perUser)
	require.NoError(t, err)
	assert.Empty(t, configs, "no rows even with a uid constraint when no sensor is present")
}

func TestUserConfigsToRows_OmitsUnknownColumns(t *testing.T) {
	t.Parallel()
	// A config where some flags are known and others are unknown (""). The
	// unknown ones must be OMITTED from the row map (NULL), never set to "".
	// Crucially, touchid_unlock being present must NOT pull the other flags in.
	configs := []*UserConfig{{
		UID:                    "501",
		FingerprintsRegistered: "1",
		Unlock:                 "1",
		ApplePay:               "", // unknown
		EffectiveUnlock:        "", // unknown
		EffectiveApplePay:      "", // unknown
	}}

	rows := userConfigsToRows(configs)
	require.Len(t, rows, 1)
	row := rows[0]

	assert.Equal(t, "501", row["uid"])
	assert.Equal(t, "1", row["fingerprints_registered"])
	assert.Equal(t, "1", row["touchid_unlock"])
	for _, k := range []string{"touchid_applepay", "effective_unlock", "effective_applepay"} {
		_, present := row[k]
		assert.False(t, present, "unknown column %q must be omitted (NULL), not set to \"\"", k)
	}
}

func TestUserConfigsToRows_AllKnown(t *testing.T) {
	t.Parallel()
	configs := []*UserConfig{{
		UID:                    "501",
		FingerprintsRegistered: "2",
		Unlock:                 "1",
		ApplePay:               "0",
		EffectiveUnlock:        "1",
		EffectiveApplePay:      "0",
	}}
	rows := userConfigsToRows(configs)
	require.Len(t, rows, 1)
	assert.Equal(t, map[string]string{
		"uid":                     "501",
		"fingerprints_registered": "2",
		"touchid_unlock":          "1",
		"touchid_applepay":        "0",
		"effective_unlock":        "1",
		"effective_applepay":      "0",
	}, rows[0])
}

func columnNames(cols []table.ColumnDefinition) []string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	return names
}

func TestColumns(t *testing.T) {
	t.Parallel()
	// Compare full name slices so a count/order mismatch is a clean assertion
	// failure rather than an index-out-of-range panic.
	wantSys := []string{"touchid_compatible", "secure_enclave", "touchid_enabled", "touchid_unlock", "touchid_builtin", "touchid_sensor_present"}
	assert.Equal(t, wantSys, columnNames(TouchIDSystemConfigColumns()))

	wantUsr := []string{"uid", "fingerprints_registered", "touchid_unlock", "touchid_applepay", "effective_unlock", "effective_applepay"}
	assert.Equal(t, wantUsr, columnNames(TouchIDUserConfigColumns()))
}
