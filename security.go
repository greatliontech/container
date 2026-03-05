package container

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Capabilities configures the capability sets for the container
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

// Linux prctl constants for capability manipulation
const (
	prCapBSetRead = 23 // PR_CAPBSET_READ
	prCapBSetDrop = 24 // PR_CAPBSET_DROP
	prCapAmbient  = 47 // PR_CAP_AMBIENT
	prCapAmbRaise = 2  // PR_CAP_AMBIENT_RAISE
	prCapAmbClear = 4  // PR_CAP_AMBIENT_CLEAR_ALL
)

// capHeader is the header for the capget/capset syscalls (version 3, 64-bit)
type capHeader struct {
	version uint32
	pid     int32
}

// capData is a single word of capability data (32 bits each for effective/permitted/inheritable)
type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

const capV3 = 0x20080522 // _LINUX_CAPABILITY_VERSION_3

// lastCap probes the kernel for the highest supported capability bit.
func lastCap() int {
	for c := 0; c < 64; c++ {
		r, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prCapBSetRead, uintptr(c), 0)
		if int(r) < 0 {
			return c - 1
		}
	}
	return 63
}

// applyCapabilities applies the capability configuration using raw syscalls.
//
// This avoids the libcap/psx library which uses syscall.AllThreadsSyscall to
// synchronize capability changes across all OS threads. That mechanism can
// hang when called from init() (the container child re-exec path) because
// the Go runtime's thread management isn't fully settled yet.
//
// Since the child process is about to syscall.Exec() into the target command,
// we only need to set capabilities on the current thread — raw prctl/capset
// syscalls are sufficient and safe.
func applyCapabilities(caps *Capabilities) error {
	if caps == nil {
		return nil
	}

	// Lock this goroutine to its OS thread since we're doing per-thread
	// capability operations.
	runtime.LockOSThread()
	// Note: we don't UnlockOSThread — the child calls syscall.Exec next.

	// Build lookup sets
	boundingSet := make(map[cap.Value]bool)
	for _, c := range caps.Bounding {
		boundingSet[c] = true
	}

	// Drop capabilities from bounding set that aren't in our desired set.
	max := lastCap()
	for v := 0; v <= max; v++ {
		if !boundingSet[cap.Value(v)] {
			_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prCapBSetDrop, uintptr(v), 0)
			if errno != 0 {
				// Ignore EINVAL (cap doesn't exist on this kernel) and
				// EPERM (not privileged to drop — can happen in user namespaces)
				continue
			}
		}
	}

	// Build capability bitmasks (version 3 uses two 32-bit words = 64 bits)
	var data [2]capData
	for _, v := range caps.Permitted {
		word := uint(v) / 32
		bit := uint(v) % 32
		if word < 2 {
			data[word].permitted |= 1 << bit
		}
	}
	for _, v := range caps.Effective {
		word := uint(v) / 32
		bit := uint(v) % 32
		if word < 2 {
			data[word].effective |= 1 << bit
		}
	}
	for _, v := range caps.Inheritable {
		word := uint(v) / 32
		bit := uint(v) % 32
		if word < 2 {
			data[word].inheritable |= 1 << bit
		}
	}

	// Apply with capset(2)
	hdr := capHeader{version: capV3, pid: 0}
	_, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	// Clear all ambient capabilities first
	_, _, errno = syscall.RawSyscall6(syscall.SYS_PRCTL,
		prCapAmbient, prCapAmbClear, 0, 0, 0, 0)
	// Ignore errors — ambient caps may not be supported on older kernels

	// Raise desired ambient capabilities
	for _, v := range caps.Ambient {
		_, _, errno = syscall.RawSyscall6(syscall.SYS_PRCTL,
			prCapAmbient, prCapAmbRaise, uintptr(v), 0, 0, 0)
		if errno != 0 {
			// Ignore errors — ambient caps require the cap to be in
			// both permitted and inheritable sets, and may not be supported
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

// createDevices creates device nodes in the container rootfs.
// It first attempts mknod, and falls back to bind-mounting the device from the
// host if mknod fails (as happens in user namespaces). This matches the
// approach used by runc/libcontainer.
func createDevices(root string, devices []Device) error {
	for _, dev := range devices {
		if err := createDeviceNode(root, dev); err != nil {
			return err
		}
	}
	return nil
}

func createDeviceNode(root string, dev Device) error {
	// Resolve the device path relative to the container rootfs.
	containerPath := filepath.Join(root, dev.Path)
	devNum := mkdev(dev.Major, dev.Minor)
	mode := dev.Type | dev.Mode

	// Remove existing node if present
	unix.Unlink(containerPath)

	// Try mknod first (works when running as real root).
	err := unix.Mknod(containerPath, mode, int(devNum))
	if err == nil {
		if err := unix.Chmod(containerPath, dev.Mode); err != nil {
			return err
		}
		return unix.Chown(containerPath, int(dev.Uid), int(dev.Gid))
	}

	// mknod failed — fall back to bind-mounting from the host.
	// This is the standard approach in user namespaces (matches runc).

	// Create an empty file on the tmpfs as the bind-mount target.
	f, err := os.OpenFile(containerPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create device target %s: %w", containerPath, err)
	}
	f.Close()

	// Bind-mount the host device node onto the empty file.
	return unix.Mount(dev.Path, containerPath, "bind", unix.MS_BIND, "")
}

// createDevSymlinks creates standard /dev symlinks
func createDevSymlinks(devDir string) error {
	links := []struct {
		target, name string
	}{
		{"/proc/self/fd", "fd"},
		{"/proc/self/fd/0", "stdin"},
		{"/proc/self/fd/1", "stdout"},
		{"/proc/self/fd/2", "stderr"},
	}

	for _, link := range links {
		path := filepath.Join(devDir, link.name)
		unix.Unlink(path) // Remove if exists
		if err := unix.Symlink(link.target, path); err != nil {
			return err
		}
	}
	return nil
}
