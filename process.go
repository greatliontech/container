package container

import (
	"io"
	"os"
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
	Umask      *uint32
	// Terminal indicates the process expects a PTY. When true, the caller
	// must create a socketpair via NewConsoleSocketPair(), set ConsoleSocket
	// to the child end, and call ReceiveConsole() on the parent end.
	Terminal bool
	// ConsoleSocket is one end of a socketpair for PTY fd passing.
	ConsoleSocket *os.File      `json:"-"`
	ConsoleHeight uint          `json:"-"`
	ConsoleWidth  uint          `json:"-"`
	Stdin         io.Reader     `json:"-"`
	Stdout        io.Writer     `json:"-"`
	Stderr        io.Writer     `json:"-"`
	StdinPipe     bool          `json:"-"`
	StdoutPipe    bool          `json:"-"`
	StderrPipe    bool          `json:"-"`
}
