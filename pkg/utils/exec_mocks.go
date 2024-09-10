package utils

import "strings"

type MockCmdRunner struct {
	Output string
	Err    error
}

func (m MockCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	return []byte(m.Output), m.Err
}

func (m MockCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	return []byte(m.Output), m.Err
}

type MultiMockCmdRunner struct {
	Commands map[string]MockCmdRunner
}

func (m MultiMockCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	key := append([]string{name}, arg...)
	return m.Commands[strings.Join(key, " ")].RunCmd(name, arg...)
}

func (m MultiMockCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	key := append([]string{name}, arg...)
	return m.Commands[strings.Join(key, " ")].RunCmdWithStdin(name, stdin, arg...)
}
