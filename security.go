package container

import (
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Capabilities configures the capability sets for the container
// Uses kernel.org/pub/linux/libs/security/libcap/cap for proper POSIX semantics
type Capabilities struct {
	// Bounding set - upper limit on capabilities that can be gained
	Bounding []cap.Value
	// Effective set - capabilities used for permission checks
	Effective []cap.Value
	// Permitted set - capabilities that can be assumed
	Permitted []cap.Value
	// Inheritable set - capabilities preserved across execve
	Inheritable []cap.Value
	// Ambient set - capabilities inherited by non-privileged programs
	Ambient []cap.Value
}

// DefaultCapabilities returns a minimal set of capabilities for containers
// This matches Docker's default capability set
func DefaultCapabilities() []cap.Value {
	return []cap.Value{
		cap.CHOWN,
		cap.DAC_OVERRIDE,
		cap.FSETID,
		cap.FOWNER,
		cap.MKNOD,
		cap.NET_RAW,
		cap.SETGID,
		cap.SETUID,
		cap.SETFCAP,
		cap.SETPCAP,
		cap.NET_BIND_SERVICE,
		cap.SYS_CHROOT,
		cap.KILL,
		cap.AUDIT_WRITE,
	}
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

// applyCapabilities applies the capability configuration using libcap
func applyCapabilities(caps *Capabilities) error {
	if caps == nil {
		return nil
	}

	// Build sets for quick lookup
	boundingSet := make(map[cap.Value]bool)
	for _, c := range caps.Bounding {
		boundingSet[c] = true
	}

	ambientSet := make(map[cap.Value]bool)
	for _, c := range caps.Ambient {
		ambientSet[c] = true
	}

	// Drop capabilities from bounding set
	// We need to drop caps NOT in our desired bounding set
	for v := cap.Value(0); v <= cap.MaxBits(); v++ {
		if !boundingSet[v] {
			if err := cap.DropBound(v); err != nil {
				// Ignore errors for caps that don't exist on this kernel
				continue
			}
		}
	}

	// Create a new capability set
	c := cap.NewSet()

	// Set permitted capabilities
	if err := c.SetFlag(cap.Permitted, true, caps.Permitted...); err != nil {
		return err
	}

	// Set effective capabilities
	if err := c.SetFlag(cap.Effective, true, caps.Effective...); err != nil {
		return err
	}

	// Set inheritable capabilities
	if err := c.SetFlag(cap.Inheritable, true, caps.Inheritable...); err != nil {
		return err
	}

	// Apply the capability set to current process
	if err := c.SetProc(); err != nil {
		return err
	}

	// Set ambient capabilities (must be done after SetProc)
	// First clear all ambient caps
	cap.ResetAmbient()

	// Then raise the ones we want
	for _, v := range caps.Ambient {
		if err := cap.SetAmbient(true, v); err != nil {
			// Ignore errors - ambient caps may not be supported
			continue
		}
	}

	return nil
}

// Device represents a device node to create in the container
type Device struct {
	Path  string // Path inside container (e.g., "/dev/null")
	Type  uint32 // S_IFCHR (character) or S_IFBLK (block)
	Major uint32 // Major device number
	Minor uint32 // Minor device number
	Mode  uint32 // File permissions (e.g., 0666)
	Uid   uint32 // Owner UID
	Gid   uint32 // Owner GID
}

// DefaultDevices returns the minimal set of devices for a container
func DefaultDevices() []Device {
	return []Device{
		{Path: "/dev/null", Type: unix.S_IFCHR, Major: 1, Minor: 3, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: "/dev/zero", Type: unix.S_IFCHR, Major: 1, Minor: 5, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: "/dev/full", Type: unix.S_IFCHR, Major: 1, Minor: 7, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: "/dev/random", Type: unix.S_IFCHR, Major: 1, Minor: 8, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: "/dev/urandom", Type: unix.S_IFCHR, Major: 1, Minor: 9, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: "/dev/tty", Type: unix.S_IFCHR, Major: 5, Minor: 0, Mode: 0o666, Uid: 0, Gid: 0},
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
		// Explicitly set permissions to override umask
		if err := unix.Chmod(dev.Path, dev.Mode); err != nil {
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
