package utils

import "regexp"

// Column helpers for tables that publish one row per user account. Each value comes from
// osquery's users table, whose formats are completely known, so anything else is published
// as "".

// uidRe is the form of a uid: an integer. macOS reports some system accounts' uids as negative
// numbers.
var uidRe = regexp.MustCompile(`^-?[0-9]+$`)

// userIDRe is the form of the two identities osquery reports: a POSIX uid, which macOS reports
// as negative for some system accounts, as uidRe allows, or a Windows SID.
var userIDRe = regexp.MustCompile(`^(S-1-[0-9-]+|-?[0-9]+)$`)

// PublishedUID returns uid if it is an integer, and "" otherwise.
func PublishedUID(uid string) string {
	if !uidRe.MatchString(uid) {
		return ""
	}
	return uid
}

// PublishedUserID returns id if it is a uid or a SID, and "" otherwise. dropped is true when a
// non-empty value was refused, so a table can say why the column is empty.
func PublishedUserID(id string) (published string, dropped bool) {
	if id == "" {
		return "", false
	}
	if !userIDRe.MatchString(id) {
		return "", true
	}
	return id, false
}

// BoolToIntString renders a yes/no value for an INTEGER column: "1" for yes and "0" for no, as
// core osquery's tables do. BoolToString's "true" and "false" are for TEXT columns.
func BoolToIntString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
