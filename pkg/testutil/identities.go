package testutil

import (
	"strconv"
	"strings"
)

// IdentitiesAround returns two identities that are not the account running the test and that
// the roster orders just before and just after it: the uids one below and one above on POSIX,
// and on Windows the SID with its last component replaced by 0 and by 9 followed by it, which
// sort as text before and after any account's SID with the same prefix.
func IdentitiesAround(uid, sid string) (beforeUID, beforeSID, afterUID, afterSID string) {
	if sid == "" {
		number, err := strconv.Atoi(uid)
		if err != nil {
			panic("the test account's uid is not a number: " + uid)
		}
		return strconv.Itoa(number - 1), "", strconv.Itoa(number + 1), ""
	}
	prefix := sid[:strings.LastIndex(sid, "-")+1]
	return "0", prefix + "0", "9" + uid, prefix + "9" + uid
}
