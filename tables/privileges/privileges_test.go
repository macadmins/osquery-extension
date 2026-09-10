package privileges

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantVersion string
		wantBuild   string
	}{
		{"normal", "PrivilegesCLI 2.6.0 (193)\n", "2.6.0", "193"},
		{"garbage", "something unexpected", "", ""},
		{"empty", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, build := parseVersion(tt.output)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantBuild, build)
		})
	}
}

func TestParseExtensionStatus(t *testing.T) {
	assert.True(t, parseExtensionStatus("System extension is enabled\n"))
	assert.False(t, parseExtensionStatus("System extension is disabled\n"))
	assert.False(t, parseExtensionStatus("garbage"))
	assert.False(t, parseExtensionStatus(""))
}

const validEventLine = `{"esf":{"process":{"cdhash":"330081dcbf4f3086cb71af1e1b0152be78fff23a","tty":"","ppid":1,"start_time":"2026-08-11T09:26:42Z","executable":"/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon","is_platform_binary":false,"team_id":"7R5ZEU67FQ","is_es_client":false,"signing_id":"corp.sap.privileges.daemon","pid":64557}},"privileges":{"subject":"user","event_type":"ADMIN_ADD","id":"henry"}}`

func TestParseEvents(t *testing.T) {
	t.Run("two valid lines", func(t *testing.T) {
		input := validEventLine + "\n" + validEventLine + "\n"
		events := parseEvents([]byte(input))
		assert.Len(t, events, 2)
		assert.Equal(t, "ADMIN_ADD", events[0].Privileges.EventType)
		assert.Equal(t, "henry", events[0].Privileges.ID)
		assert.Equal(t, "user", events[0].Privileges.Subject)
		assert.Equal(t, "corp.sap.privileges.daemon", events[0].ESF.Process.SigningID)
		assert.Equal(t, "7R5ZEU67FQ", events[0].ESF.Process.TeamID)
		assert.Equal(t, 64557, events[0].ESF.Process.PID)
		assert.Equal(t, 1, events[0].ESF.Process.PPID)
		assert.False(t, events[0].ESF.Process.IsPlatformBinary)
		assert.Equal(t, "2026-08-11T09:26:42Z", events[0].ESF.Process.StartTime)
	})
	t.Run("malformed line among valid ones is skipped", func(t *testing.T) {
		input := validEventLine + "\nnot json at all\n" + validEventLine + "\n"
		events := parseEvents([]byte(input))
		assert.Len(t, events, 2)
	})
	t.Run("empty output", func(t *testing.T) {
		assert.Empty(t, parseEvents([]byte("")))
		assert.Empty(t, parseEvents([]byte("\n\n")))
	})
}

func TestCliInstalled(t *testing.T) {
	assert.True(t, cliInstalled(utils.MockFileSystem{FileExists: true}))
	assert.False(t, cliInstalled(utils.MockFileSystem{FileExists: false}))
}

func TestBoolToIntString(t *testing.T) {
	assert.Equal(t, "1", boolToIntString(true))
	assert.Equal(t, "0", boolToIntString(false))
}
