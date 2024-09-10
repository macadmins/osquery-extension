package utils

import (
	"testing"
)

func TestRunCmd(t *testing.T) {
	runner := MultiMockCmdRunner{
		Commands: map[string]MockCmdRunner{
			"echo test": {
				Output: "test output",
				Err:    nil,
			},
		},
	}
	output, err := runner.RunCmd("echo", "test")
	if err != nil {
		t.Fatalf("RunCmd() error = %v, wantErr nil", err)
		return
	}
	got := string(output)
	if got != runner.Commands["echo test"].Output {
		t.Errorf("RunCmd() = %q, want %q", got, runner.Commands["echo test"].Output)
	}
}

func TestRunCmdWithStdin(t *testing.T) {
	runner := MultiMockCmdRunner{
		Commands: map[string]MockCmdRunner{
			"echo": {
				Output: "test output",
				Err:    nil,
			},
		},
	}
	output, err := runner.RunCmdWithStdin("echo", "test")
	if err != nil {
		t.Fatalf("RunCmdWithStdin() error = %v, wantErr nil", err)
		return
	}
	got := string(output)
	if got != runner.Commands["echo"].Output {
		t.Errorf("RunCmdWithStdin() = %q, want %q", got, runner.Commands["echo"].Output)
	}
}
