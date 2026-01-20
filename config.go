package container

import (
	"syscall"

	"golang.org/x/sys/unix"
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

	// Security options (Phase 1)
	// UsePivotRoot uses pivot_root instead of chroot for better isolation
	UsePivotRoot bool
	// Capabilities configures Linux capabilities for the container
	Capabilities *Capabilities
	// Seccomp configures the seccomp profile for syscall filtering
	Seccomp *SeccompProfile
	// Devices specifies device nodes to create in /dev
	Devices []Device
	// SetupDev creates a minimal /dev with standard devices
	SetupDev bool
	// NoNewPrivileges sets the no_new_privs flag
	NoNewPrivileges bool
}

// DefaultConfig returns a Config with secure defaults
func DefaultConfig() Config {
	return Config{
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewNet:  true,
			NewPID:  true,
			NewUTS:  true,
			NewUser: true,
		},
		UsePivotRoot:    true,
		Capabilities:    DefaultCapabilitiesConfig(),
		Seccomp:         DefaultSeccompProfile(),
		Devices:         DefaultDevices(),
		SetupDev:        true,
		NoNewPrivileges: true,
	}
}

// MountFlags provides common mount flag combinations
var MountFlags = struct {
	Bind         uintptr
	BindReadOnly uintptr
	Proc         uintptr
	Sysfs        uintptr
	Tmpfs        uintptr
	Devpts       uintptr
	Private      uintptr
	Slave        uintptr
	Shared       uintptr
}{
	Bind:         unix.MS_BIND,
	BindReadOnly: unix.MS_BIND | unix.MS_RDONLY,
	Proc:         unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
	Sysfs:        unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY,
	Tmpfs:        unix.MS_NOSUID | unix.MS_NODEV,
	Devpts:       unix.MS_NOSUID | unix.MS_NOEXEC,
	Private:      unix.MS_PRIVATE,
	Slave:        unix.MS_SLAVE,
	Shared:       unix.MS_SHARED,
}
