package container

import (
	"golang.org/x/sys/unix"
)

// Capability represents a Linux capability
type Capability int

// Linux capabilities - subset of most commonly used
const (
	CAP_CHOWN            Capability = 0
	CAP_DAC_OVERRIDE     Capability = 1
	CAP_DAC_READ_SEARCH  Capability = 2
	CAP_FOWNER           Capability = 3
	CAP_FSETID           Capability = 4
	CAP_KILL             Capability = 5
	CAP_SETGID           Capability = 6
	CAP_SETUID           Capability = 7
	CAP_SETPCAP          Capability = 8
	CAP_LINUX_IMMUTABLE  Capability = 9
	CAP_NET_BIND_SERVICE Capability = 10
	CAP_NET_BROADCAST    Capability = 11
	CAP_NET_ADMIN        Capability = 12
	CAP_NET_RAW          Capability = 13
	CAP_IPC_LOCK         Capability = 14
	CAP_IPC_OWNER        Capability = 15
	CAP_SYS_MODULE       Capability = 16
	CAP_SYS_RAWIO        Capability = 17
	CAP_SYS_CHROOT       Capability = 18
	CAP_SYS_PTRACE       Capability = 19
	CAP_SYS_PACCT        Capability = 20
	CAP_SYS_ADMIN        Capability = 21
	CAP_SYS_BOOT         Capability = 22
	CAP_SYS_NICE         Capability = 23
	CAP_SYS_RESOURCE     Capability = 24
	CAP_SYS_TIME         Capability = 25
	CAP_SYS_TTY_CONFIG   Capability = 26
	CAP_MKNOD            Capability = 27
	CAP_LEASE            Capability = 28
	CAP_AUDIT_WRITE      Capability = 29
	CAP_AUDIT_CONTROL    Capability = 30
	CAP_SETFCAP          Capability = 31
	CAP_MAC_OVERRIDE     Capability = 32
	CAP_MAC_ADMIN        Capability = 33
	CAP_SYSLOG           Capability = 34
	CAP_WAKE_ALARM       Capability = 35
	CAP_BLOCK_SUSPEND    Capability = 36
	CAP_AUDIT_READ       Capability = 37
	CAP_PERFMON          Capability = 38
	CAP_BPF              Capability = 39
	CAP_CHECKPOINT_RESTORE Capability = 40
	CAP_LAST_CAP         Capability = 40
)

// DefaultCapabilities returns a minimal set of capabilities for containers
func DefaultCapabilities() []Capability {
	return []Capability{
		CAP_CHOWN,
		CAP_DAC_OVERRIDE,
		CAP_FSETID,
		CAP_FOWNER,
		CAP_MKNOD,
		CAP_NET_RAW,
		CAP_SETGID,
		CAP_SETUID,
		CAP_SETFCAP,
		CAP_SETPCAP,
		CAP_NET_BIND_SERVICE,
		CAP_SYS_CHROOT,
		CAP_KILL,
		CAP_AUDIT_WRITE,
	}
}

// Capabilities configures the capability sets for the container
type Capabilities struct {
	// Bounding set - upper limit on capabilities
	Bounding []Capability
	// Effective set - capabilities used for permission checks
	Effective []Capability
	// Permitted set - capabilities that can be assumed
	Permitted []Capability
	// Inheritable set - capabilities preserved across execve
	Inheritable []Capability
	// Ambient set - capabilities inherited by non-privileged programs
	Ambient []Capability
}

// DefaultCapabilitiesConfig returns a capabilities config with safe defaults
func DefaultCapabilitiesConfig() *Capabilities {
	caps := DefaultCapabilities()
	return &Capabilities{
		Bounding:    caps,
		Effective:   caps,
		Permitted:   caps,
		Inheritable: caps,
		Ambient:     caps,
	}
}

// capabilitySet converts capability slice to a bitmask
func capabilitySet(caps []Capability) uint64 {
	var set uint64
	for _, c := range caps {
		set |= (1 << uint(c))
	}
	return set
}

// applyCapabilities applies the capability configuration
func applyCapabilities(caps *Capabilities) error {
	if caps == nil {
		return nil
	}

	// Drop capabilities from bounding set that aren't in the config
	boundingSet := capabilitySet(caps.Bounding)
	for c := Capability(0); c <= CAP_LAST_CAP; c++ {
		if boundingSet&(1<<uint(c)) == 0 {
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
				// Ignore EINVAL for capabilities that don't exist on this kernel
				if err != unix.EINVAL {
					return err
				}
			}
		}
	}

	// Set ambient capabilities
	// First clear all ambient caps
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		// Ignore if ambient caps not supported
		if err != unix.EINVAL {
			return err
		}
	}

	// Raise specified ambient caps
	for _, c := range caps.Ambient {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			if err != unix.EINVAL && err != unix.EPERM {
				return err
			}
		}
	}

	// Set permitted, effective, and inheritable using capset
	var hdr unix.CapUserHeader
	var data [2]unix.CapUserData

	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0 // Current process

	permittedSet := capabilitySet(caps.Permitted)
	effectiveSet := capabilitySet(caps.Effective)
	inheritableSet := capabilitySet(caps.Inheritable)

	data[0].Permitted = uint32(permittedSet & 0xffffffff)
	data[0].Effective = uint32(effectiveSet & 0xffffffff)
	data[0].Inheritable = uint32(inheritableSet & 0xffffffff)
	data[1].Permitted = uint32(permittedSet >> 32)
	data[1].Effective = uint32(effectiveSet >> 32)
	data[1].Inheritable = uint32(inheritableSet >> 32)

	return unix.Capset(&hdr, &data[0])
}

// Device represents a device node to create in the container
type Device struct {
	Path  string      // Path inside container (e.g., "/dev/null")
	Type  uint32      // S_IFCHR (character) or S_IFBLK (block)
	Major uint32      // Major device number
	Minor uint32      // Minor device number
	Mode  uint32      // File permissions (e.g., 0666)
	Uid   uint32      // Owner UID
	Gid   uint32      // Owner GID
}

// DefaultDevices returns the minimal set of devices for a container
func DefaultDevices() []Device {
	return []Device{
		{Path: "/dev/null", Type: unix.S_IFCHR, Major: 1, Minor: 3, Mode: 0666, Uid: 0, Gid: 0},
		{Path: "/dev/zero", Type: unix.S_IFCHR, Major: 1, Minor: 5, Mode: 0666, Uid: 0, Gid: 0},
		{Path: "/dev/full", Type: unix.S_IFCHR, Major: 1, Minor: 7, Mode: 0666, Uid: 0, Gid: 0},
		{Path: "/dev/random", Type: unix.S_IFCHR, Major: 1, Minor: 8, Mode: 0666, Uid: 0, Gid: 0},
		{Path: "/dev/urandom", Type: unix.S_IFCHR, Major: 1, Minor: 9, Mode: 0666, Uid: 0, Gid: 0},
		{Path: "/dev/tty", Type: unix.S_IFCHR, Major: 5, Minor: 0, Mode: 0666, Uid: 0, Gid: 0},
	}
}

// mkdev creates a device number from major and minor numbers
func mkdev(major, minor uint32) uint64 {
	return uint64(major)<<8 | uint64(minor)
}

// createDevices creates device nodes in the container
func createDevices(devices []Device) error {
	for _, dev := range devices {
		devNum := mkdev(dev.Major, dev.Minor)
		mode := dev.Type | dev.Mode

		// Remove existing node if present
		unix.Unlink(dev.Path)

		if err := unix.Mknod(dev.Path, mode, int(devNum)); err != nil {
			return err
		}
		if err := unix.Chown(dev.Path, int(dev.Uid), int(dev.Gid)); err != nil {
			return err
		}
	}
	return nil
}

// createDevSymlinks creates standard /dev symlinks
func createDevSymlinks() error {
	links := []struct {
		oldname, newname string
	}{
		{"/proc/self/fd", "/dev/fd"},
		{"/proc/self/fd/0", "/dev/stdin"},
		{"/proc/self/fd/1", "/dev/stdout"},
		{"/proc/self/fd/2", "/dev/stderr"},
	}

	for _, link := range links {
		unix.Unlink(link.newname) // Remove if exists
		if err := unix.Symlink(link.oldname, link.newname); err != nil {
			return err
		}
	}
	return nil
}
