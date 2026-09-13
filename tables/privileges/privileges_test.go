package privileges

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// A real tamper-protection event: a clone of a file out of the app bundle.
const tamperEventLine = `{"esf":{"process":{"cdhash":"6336f2b815f60f0816289a349c1f70abe653a198","tty":"/dev/ttys015","ppid":40632,"start_time":"2026-09-11T21:03:32Z","executable":"/bin/cp","is_platform_binary":true,"parent_audit_token":[501,501,20,501,20,40632,100015,170838888],"audit_token":[501,501,20,501,20,41512,100015,170840657],"responsible_audit_token":[501,501,20,501,20,21358,100015,109472378],"team_id":"","is_es_client":false,"signing_id":"com.apple.cp","pid":41512}},"privileges":{"subject":"/Applications/Privileges.app/Contents/Info.plist","event_type":"CLONE"}}`

const validEventLine = `{"esf":{"process":{"cdhash":"330081dcbf4f3086cb71af1e1b0152be78fff23a","tty":"","ppid":1,"start_time":"2026-08-11T09:26:42Z","executable":"/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon","is_platform_binary":false,"parent_audit_token":[4294967295,0,0,0,0,1,100014,1022],"audit_token":[4294967295,0,0,0,0,64557,100014,134239596],"responsible_audit_token":[4294967295,0,0,0,0,64557,100014,134239596],"team_id":"7R5ZEU67FQ","is_es_client":false,"signing_id":"corp.sap.privileges.daemon","pid":64557}},"privileges":{"subject":"user","event_type":"ADMIN_ADD","id":"henry"}}`

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

func TestAuditTokenField(t *testing.T) {
	token := []uint32{4294967295, 501, 20, 501, 20, 41512, 100015, 170840657}
	assert.Equal(t, "-1", auditTokenField(token, 0), "AUDIT_UID_NONE renders as -1")
	assert.Equal(t, "501", auditTokenField(token, 1))
	assert.Equal(t, "20", auditTokenField(token, 2))
	assert.Equal(t, "41512", auditTokenField(token, 5))
	assert.Equal(t, "", auditTokenField(token, 8), "index past the token is empty")
	assert.Equal(t, "", auditTokenField(nil, 0), "missing token is empty")
}
