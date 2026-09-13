package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type CmdRunner interface {
	RunCmd(name string, arg ...string) ([]byte, error)
	RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error)
}

type ExecCmdRunner struct{}

type Runner struct {
	Runner CmdRunner
}

// New creates a new Runner struct
func NewRunner() Runner {
	return Runner{
		Runner: &ExecCmdRunner{},
	}
}

func (r ExecCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return output, errors.New(stderr.String())
	}
	return output, nil
}

func (r *ExecCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = bytes.NewBuffer([]byte(stdin))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return output, errors.New(stderr.String())
	}
	return output, nil
}

// ErrCommandTimeout is returned (wrapped) when a command run by
// ExecCmdCombinedRunner exceeds its Timeout and is killed.
var ErrCommandTimeout = errors.New("command timed out")

// ExecCmdCombinedRunner runs commands capturing stdout and stderr as one
// stream, for CLIs that write their output to stderr. A non-zero Timeout
// kills the command once the deadline passes.
type ExecCmdCombinedRunner struct {
	Timeout time.Duration
}

func NewCombinedRunner() Runner {
	return Runner{
		Runner: &ExecCmdCombinedRunner{},
	}
}

func NewCombinedRunnerWithTimeout(timeout time.Duration) Runner {
	return Runner{
		Runner: &ExecCmdCombinedRunner{Timeout: timeout},
	}
}

func (r *ExecCmdCombinedRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	return r.run(name, nil, arg...)
}

func (r *ExecCmdCombinedRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	return r.run(name, bytes.NewBufferString(stdin), arg...)
}

func (r *ExecCmdCombinedRunner) run(name string, stdin *bytes.Buffer, arg ...string) ([]byte, error) {
	ctx := context.Background()
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, arg...)
	// Do not let a grandchild holding the output pipe keep Wait blocked
	// after the process itself has been killed.
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = stdin
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("%s: %w after %s", name, ErrCommandTimeout, r.Timeout)
	}
	if err != nil {
		return output, errors.New(string(output))
	}
	return output, nil
}
