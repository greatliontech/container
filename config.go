package container

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type Namespaces struct {
	NewIPC    bool
	NewMnt    bool
	NewNet    bool
	NewPID    bool
	NewUTS    bool
	NewUser   bool
	NewCgroup bool
	NewTime   bool
	// Join existing namespaces instead of creating new ones.
	// Paths to namespace fds, e.g. /proc/<pid>/ns/net.
	JoinIPC    string
	JoinMnt    string
	JoinNet    string
	JoinPID    string
	JoinUTS    string
	JoinUser   string
	JoinCgroup string
	JoinTime   string
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
	if n.NewCgroup {
		cf |= unix.CLONE_NEWCGROUP
	}
	if n.NewTime {
		cf |= unix.CLONE_NEWTIME
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

// Rlimit defines a POSIX resource limit.
type Rlimit struct {
	Type int    // unix.RLIMIT_NOFILE, unix.RLIMIT_NPROC, etc.
	Soft uint64
	Hard uint64
}

type Config struct {
	Root         string
	ReadonlyRoot bool
	Namespaces   Namespaces
	Hostname     string
	Domainname   string
	Mounts       []Mount
	UidMappings []syscall.SysProcIDMap
	GidMappings []syscall.SysProcIDMap

	// Security
	UsePivotRoot    bool
	Capabilities    *Capabilities
	Seccomp         *SeccompProfile
	Devices         []Device
	SetupDev        bool
	NoNewPrivileges bool
	MaskPaths       []string // Paths to mask with /dev/null or tmpfs
	ReadonlyPaths   []string // Paths to remount read-only

	// Resource limits
	Resources *Resources
	Rlimits   []Rlimit

	// Kernel parameters (written to /proc/sys)
	Sysctl map[string]string

	// Lifecycle
	Hooks *Hooks

	// Metadata
	Annotations map[string]string

	// OOM
	OOMScoreAdj *int

	// Console/PTY
	// ConsoleSocket is the path to a Unix socket where the container
	// sends the master PTY fd. The parent receives it via ReceiveConsole().
	// If empty, no PTY is allocated.
	ConsoleSocket string
	ConsoleHeight uint
	ConsoleWidth  uint
}

// DefaultConfig returns a Config with secure defaults.
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
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		UsePivotRoot:    true,
		Capabilities:    DefaultCapabilitiesConfig(),
		Seccomp:         DefaultSeccompProfile(),
		Devices:         DefaultDevices(),
		SetupDev:        true,
		NoNewPrivileges: true,
		MaskPaths:       DefaultMaskPaths(),
		ReadonlyPaths:   DefaultReadonlyPaths(),
	}
}

// DefaultMaskPaths returns paths that should be masked in containers.
func DefaultMaskPaths() []string {
	return []string{
		"/proc/asound",
		"/proc/acpi",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

// DefaultReadonlyPaths returns paths that should be read-only in containers.
func DefaultReadonlyPaths() []string {
	return []string{
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
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
