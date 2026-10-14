package fsscan

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestSplitSafeComponentsRejectsInteriorDotDotOnEverySeparator pins the traversal guard
// against the separator it is written in terms of.
//
// The guard splits the raw path looking for a "..", because filepath.Clean collapses one and
// a check after Clean sees nothing. Splitting on os.PathSeparator alone made that guard
// platform-dependent: Windows honours both "/" and "\", so "a/../secret.json" split into a
// single part there, matched no "..", and Clean then reduced it to "secret.json" -- the
// contract said the path was rejected while the caller was handed a different file than the
// one it named.
//
// This runs everywhere and encodes the contract rather than the platform: an interior ".."
// is refused however it was spelled.
func TestSplitSafeComponentsRejectsInteriorDotDotOnEverySeparator(t *testing.T) {
	for _, path := range []string{
		"../secret.json",
		"a/../secret.json",
		"a/b/../../secret.json",
		".claude/../../etc/passwd",
	} {
		if _, err := splitSafeComponents(path); err == nil {
			t.Errorf("splitSafeComponents(%q) = nil error, want rejection", path)
		}
	}
}

// TestSplitSafeComponentsTreatsBackslashPerPlatform documents the one case where the answer
// legitimately differs: a backslash is a separator on Windows and an ordinary filename
// character on Unix, so the same string is two components there and one here.
func TestSplitSafeComponentsTreatsBackslashPerPlatform(t *testing.T) {
	got, err := splitSafeComponents(`a\b`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtime.GOOS == "windows" {
		if len(got) != 2 {
			t.Errorf(`splitSafeComponents("a\\b") = %q, want two components on Windows`, got)
		}
		return
	}
	if len(got) != 1 || got[0] != `a\b` {
		t.Errorf(`splitSafeComponents("a\\b") = %q, want one literal component on Unix`, got)
	}
}

// TestIsPathSeparatorMatchesOS guards the rune adapter against drifting from the byte-based
// answer it wraps, for every ASCII value rather than the two that happen to matter today.
func TestIsPathSeparatorMatchesOS(t *testing.T) {
	for c := 0; c < 0x80; c++ {
		if got, want := isPathSeparator(rune(c)), os.IsPathSeparator(byte(c)); got != want {
			t.Errorf("isPathSeparator(%q) = %v, os.IsPathSeparator = %v", rune(c), got, want)
		}
	}
	// A non-ASCII rune is never a separator, and must not be truncated into one: byte(0x15C)
	// is 0x5C, the backslash, which would split a path on a CJK or accented character.
	if isPathSeparator(0x15C) {
		t.Error("isPathSeparator truncated a non-ASCII rune into a separator")
	}
	if strings.ContainsRune("/\\", 0x15C) {
		t.Fatal("test premise wrong: 0x15C should not itself be a separator character")
	}
}
