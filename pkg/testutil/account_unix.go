//go:build !windows

package testutil

import (
	"os"
	"strconv"
	"syscall"
)

// Account is the identity files the test creates belong to, as osquery's users table reports
// it: the uid, and no uuid SID.
func Account() (uid, uuid string) {
	return strconv.Itoa(os.Getuid()), ""
}

// PrivilegedOwner reports whether root owns path, an owner fsscan's owner check passes for any
// account, so a test of a refusal skips.
func PrivilegedOwner(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		panic("testutil: reading the owner of " + path + ": " + err.Error())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
