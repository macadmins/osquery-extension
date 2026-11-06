//go:build windows

package testutil

import (
	"strings"

	"golang.org/x/sys/windows"
)

// Account is the identity files the test creates belong to, as osquery's users table reports
// it: the last component of the process user's SID as the uid, and the whole SID as the uuid.
// It panics when the process token cannot be read.
func Account() (uid, uuid string) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		panic("testutil: reading the process user: " + err.Error())
	}
	sid := tokenUser.User.Sid.String()
	return sid[strings.LastIndex(sid, "-")+1:], sid
}

// privilegedSIDs are the owners fsscan's owner check passes for any account: LocalSystem,
// BUILTIN\Administrators and TrustedInstaller.
var privilegedSIDs = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
}

// PrivilegedOwner reports whether path's owner is one fsscan's owner check passes for any
// account, so a test of a refusal skips. A process running as an administrator typically
// creates files the Administrators group owns.
func PrivilegedOwner(path string) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		panic("testutil: reading the owner of " + path + ": " + err.Error())
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		panic("testutil: no owner recorded for " + path)
	}
	return privilegedSIDs[owner.String()]
}
