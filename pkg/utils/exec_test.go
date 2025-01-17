package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	assert.Equal(t, "test output", string(output))
}

func TestRunCmdWithStdin(t *testing.T) {
	runner := MultiMockCmdRunner{
		Commands: map[string]MockCmdRunner{
			"cat": {
				Output: "test output",
				Err:    nil,
			},
		},
	}
	output, err := runner.RunCmdWithStdin("cat", "test")
	assert.NoError(t, err)
	assert.Equal(t, "test output", string(output))
}

func TestNewRunner(t *testing.T) {
	runner := NewRunner()

	assert.NotNil(t, runner.Runner, "Expected Runner to be initialized, but got nil")
	assert.IsType(t, &ExecCmdRunner{}, runner.Runner, "Expected Runner to be of type *ExecCmdRunner")
}

func TestExecCmdRunner_RunCmd(t *testing.T) {
	runner := &ExecCmdRunner{}
	output, err := runner.RunCmd("echo", "test")
	assert.NoError(t, err)
	assert.Equal(t, "test\n", string(output))
}

func TestExecCmdRunner_RunCmdWithStdin(t *testing.T) {
	runner := &ExecCmdRunner{}
	output, err := runner.RunCmdWithStdin("cat", "test")
	assert.NoError(t, err)
	assert.Equal(t, "test", string(output))
}
