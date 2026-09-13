package utils

import (
	"testing"
	"time"

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

func TestExecCmdCombinedRunner_RunCmd_CapturesStderr(t *testing.T) {
	runner := &ExecCmdCombinedRunner{}
	output, err := runner.RunCmd("sh", "-c", "echo to-stderr 1>&2")
	assert.NoError(t, err)
	assert.Equal(t, "to-stderr\n", string(output))
}

func TestExecCmdCombinedRunner_RunCmd_FailingCommand(t *testing.T) {
	runner := &ExecCmdCombinedRunner{}
	output, err := runner.RunCmd("sh", "-c", "echo boom 1>&2; exit 3")
	assert.Error(t, err)
	assert.Equal(t, "boom\n", err.Error())
	assert.Equal(t, "boom\n", string(output))
}

func TestExecCmdCombinedRunner_RunCmdWithStdin_CapturesStderr(t *testing.T) {
	runner := &ExecCmdCombinedRunner{}
	output, err := runner.RunCmdWithStdin("sh", "from-stdin", "-c", "cat 1>&2")
	assert.NoError(t, err)
	assert.Equal(t, "from-stdin", string(output))
}

func TestExecCmdCombinedRunner_RunCmdWithStdin_FailingCommand(t *testing.T) {
	runner := &ExecCmdCombinedRunner{}
	output, err := runner.RunCmdWithStdin("sh", "ignored", "-c", "echo boom 1>&2; exit 3")
	assert.Error(t, err)
	assert.Equal(t, "boom\n", err.Error())
	assert.Equal(t, "boom\n", string(output))
}

func TestExecCmdCombinedRunner_RunCmd_Timeout(t *testing.T) {
	runner := &ExecCmdCombinedRunner{Timeout: 100 * time.Millisecond}
	start := time.Now()
	_, err := runner.RunCmd("sleep", "5")
	assert.ErrorIs(t, err, ErrCommandTimeout)
	assert.Less(t, time.Since(start), 3*time.Second, "the child must be killed at the deadline")
}

func TestExecCmdCombinedRunner_RunCmd_WithinTimeout(t *testing.T) {
	runner := &ExecCmdCombinedRunner{Timeout: 5 * time.Second}
	output, err := runner.RunCmd("sh", "-c", "echo quick 1>&2")
	assert.NoError(t, err)
	assert.Equal(t, "quick\n", string(output))
}

func TestExecCmdCombinedRunner_RunCmdWithStdin_Timeout(t *testing.T) {
	runner := &ExecCmdCombinedRunner{Timeout: 100 * time.Millisecond}
	start := time.Now()
	_, err := runner.RunCmdWithStdin("sh", "ignored", "-c", "sleep 5")
	assert.ErrorIs(t, err, ErrCommandTimeout)
	assert.Less(t, time.Since(start), 3*time.Second)
}

func TestNewCombinedRunnerWithTimeout(t *testing.T) {
	runner := NewCombinedRunnerWithTimeout(7 * time.Second)
	combined, ok := runner.Runner.(*ExecCmdCombinedRunner)
	assert.True(t, ok)
	assert.Equal(t, 7*time.Second, combined.Timeout)
}

func TestNewCombinedRunner(t *testing.T) {
	runner := NewCombinedRunner()
	assert.NotNil(t, runner.Runner)
	assert.IsType(t, &ExecCmdCombinedRunner{}, runner.Runner)
}
