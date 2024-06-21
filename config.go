package container

import (
	"syscall"
)

type Namespaces struct {
	NewIPC  bool
	NewMnt  bool
	NewNet  bool
	NewPID  bool
	NewUTS  bool
	NewUser bool
}

func (n Namespaces) CloneFlags() uintptr {
	var cf uintptr
	if n.NewIPC {
		cf |= syscall.CLONE_NEWIPC
	}
	if n.NewMnt {
		cf |= syscall.CLONE_NEWNS
	}
	if n.NewNet {
		cf |= syscall.CLONE_NEWNET
	}
	if n.NewPID {
		cf |= syscall.CLONE_NEWPID
	}
	if n.NewUTS {
		cf |= syscall.CLONE_NEWUTS
	}
	if n.NewUser {
		cf |= syscall.CLONE_NEWUSER
	}
	return cf
}

type Mount struct {
	Source string
	Target string
	Type   string
	Flags  uintptr
	Data   string
}

type Config struct {
	Root        string
	Namespaces  Namespaces
	Hostname    string
	Mounts      []Mount
	UidMappings []syscall.SysProcIDMap
	GidMappings []syscall.SysProcIDMap
}
