package container

import (
	"io"
	"syscall"
)

type Process struct {
	Cmd           string
	Args          []string
	WorkDir       string
	Env           []string
	InheritEnv    bool
	Init          bool
	Credential    *syscall.Credential
	Umask         *uint32
	Terminal      bool      // Allocate a PTY; master fd available via Container.Console()
	ConsoleHeight uint      // Initial terminal height (rows)
	ConsoleWidth  uint      // Initial terminal width (cols)
	Stdin         io.Reader `json:"-"`
	Stdout        io.Writer `json:"-"`
	Stderr        io.Writer `json:"-"`
	StdinPipe     bool      `json:"-"`
	StdoutPipe    bool      `json:"-"`
	StderrPipe    bool      `json:"-"`
}
