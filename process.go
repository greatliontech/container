package container

import (
	"io"
	"syscall"
)

type Process struct {
	Cmd        string
	Args       []string
	WorkDir    string
	Env        []string
	InheritEnv bool
	Init       bool
	Credential *syscall.Credential
	Stdin      io.Reader `json:"-"`
	Stdout     io.Writer `json:"-"`
	Stderr     io.Writer `json:"-"`
	StdinPipe  bool      `json:"-"`
	StdoutPipe bool      `json:"-"`
	StderrPipe bool      `json:"-"`
}
