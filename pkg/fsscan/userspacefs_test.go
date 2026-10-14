package fsscan

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// An ordinary file on the test machine's own filesystem must not be refused.
//
// The positive case cannot be tested without mounting FUSE, which no CI job can do, so what
// is asserted here is the half that a wrong magic number or a sign-extension mistake would
// break: a local file reads normally. A check that refused everything would pass a test that
// only looked for refusals.
func TestLocalFileIsNotRefusedAsUserspace(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	const body = `{"mcpServers":{"srv":{"command":"npx"}}}`
	if err := os.WriteFile(filepath.Join(home, "code", ".mcp.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := ReadProjectFile(home, "code", ".mcp.json", ReadOpts{MaxSize: 1024})
	if err != nil {
		t.Fatalf("a local file was refused: %v", err)
	}
	if string(data) != body {
		t.Errorf("content = %q, want %q", data, body)
	}
	if errors.Is(err, ErrUserspaceFilesystem) {
		t.Error("tmpdir reported as a userspace filesystem")
	}
}

// The sentinel has to classify, or the row reports the generic unreadable warning instead of
// naming the filesystem as the reason.
func TestUserspaceFilesystemClassifies(t *testing.T) {
	wrapped := errors.Join(ErrUserspaceFilesystem, errors.New("FUSE"))
	if got := ClassifyError(wrapped); got != ClassUserspaceFilesystem {
		t.Errorf("ClassifyError = %q, want %q", got, ClassUserspaceFilesystem)
	}
	// And it must not read as an expected absence, which would make the refusal silent --
	// the specific failure this whole mechanism exists to avoid.
	if IsExpectedAbsent(ErrUserspaceFilesystem) {
		t.Error("a userspace-filesystem refusal must not read as expected absence")
	}
}

// Off Linux the check is a no-op, so nothing can regress on the platforms that answer the
// narrower per-file question instead.
func TestUserspaceCheckIsInertOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux has the real implementation")
	}
	file, err := os.CreateTemp(t.TempDir(), "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if reason := fileOnUserspaceFilesystem(file); reason != nil {
		t.Errorf("expected no refusal off linux, got %v", reason)
	}
}
