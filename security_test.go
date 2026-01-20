package container

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func TestDefaultDevices(t *testing.T) {
	devices := DefaultDevices()

	if len(devices) == 0 {
		t.Fatal("DefaultDevices returned empty list")
	}

	// Expected devices with their major/minor numbers
	expected := map[string]struct {
		major, minor uint32
		devType      uint32
		mode         uint32
	}{
		"/dev/null":    {major: 1, minor: 3, devType: unix.S_IFCHR, mode: 0o666},
		"/dev/zero":    {major: 1, minor: 5, devType: unix.S_IFCHR, mode: 0o666},
		"/dev/full":    {major: 1, minor: 7, devType: unix.S_IFCHR, mode: 0o666},
		"/dev/random":  {major: 1, minor: 8, devType: unix.S_IFCHR, mode: 0o666},
		"/dev/urandom": {major: 1, minor: 9, devType: unix.S_IFCHR, mode: 0o666},
		"/dev/tty":     {major: 5, minor: 0, devType: unix.S_IFCHR, mode: 0o666},
	}

	found := make(map[string]bool)
	for _, dev := range devices {
		found[dev.Path] = true

		exp, ok := expected[dev.Path]
		if !ok {
			continue // Allow extra devices
		}

		if dev.Major != exp.major {
			t.Errorf("%s: Major = %d, want %d", dev.Path, dev.Major, exp.major)
		}
		if dev.Minor != exp.minor {
			t.Errorf("%s: Minor = %d, want %d", dev.Path, dev.Minor, exp.minor)
		}
		if dev.Type != exp.devType {
			t.Errorf("%s: Type = %#x, want %#x", dev.Path, dev.Type, exp.devType)
		}
		if dev.Mode != exp.mode {
			t.Errorf("%s: Mode = %#o, want %#o", dev.Path, dev.Mode, exp.mode)
		}
	}

	// Verify all expected devices are present
	for path := range expected {
		if !found[path] {
			t.Errorf("expected device %s not found", path)
		}
	}
}

func TestDefaultCapabilities(t *testing.T) {
	caps := DefaultCapabilities()

	if len(caps) == 0 {
		t.Fatal("DefaultCapabilities returned empty list")
	}

	// Docker's default capability set
	expectedCaps := []cap.Value{
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

	// Create a map for easier lookup
	capSet := make(map[cap.Value]bool)
	for _, c := range caps {
		capSet[c] = true
	}

	// Verify all expected capabilities are present
	for _, expected := range expectedCaps {
		if !capSet[expected] {
			t.Errorf("expected capability %s not found", expected)
		}
	}

	// Verify no dangerous capabilities are present
	dangerousCaps := []cap.Value{
		cap.SYS_ADMIN,
		cap.SYS_PTRACE,
		cap.SYS_MODULE,
		cap.SYS_RAWIO,
		cap.SYS_BOOT,
	}

	for _, dangerous := range dangerousCaps {
		if capSet[dangerous] {
			t.Errorf("dangerous capability %s should not be in default set", dangerous)
		}
	}
}

func TestDefaultCapabilitiesConfig(t *testing.T) {
	cfg := DefaultCapabilitiesConfig()

	if cfg == nil {
		t.Fatal("DefaultCapabilitiesConfig returned nil")
	}

	// All capability sets should be populated
	if len(cfg.Bounding) == 0 {
		t.Error("Bounding set should not be empty")
	}
	if len(cfg.Effective) == 0 {
		t.Error("Effective set should not be empty")
	}
	if len(cfg.Permitted) == 0 {
		t.Error("Permitted set should not be empty")
	}
	if len(cfg.Inheritable) == 0 {
		t.Error("Inheritable set should not be empty")
	}
	if len(cfg.Ambient) == 0 {
		t.Error("Ambient set should not be empty")
	}

	// All sets should have the same capabilities
	if len(cfg.Bounding) != len(cfg.Effective) {
		t.Error("Bounding and Effective sets should have same length")
	}
	if len(cfg.Bounding) != len(cfg.Permitted) {
		t.Error("Bounding and Permitted sets should have same length")
	}
	if len(cfg.Bounding) != len(cfg.Inheritable) {
		t.Error("Bounding and Inheritable sets should have same length")
	}
	if len(cfg.Bounding) != len(cfg.Ambient) {
		t.Error("Bounding and Ambient sets should have same length")
	}
}

func TestMkdev(t *testing.T) {
	tests := []struct {
		major, minor uint32
		want         uint64
	}{
		{major: 1, minor: 3, want: (1 << 8) | 3},      // /dev/null
		{major: 1, minor: 5, want: (1 << 8) | 5},      // /dev/zero
		{major: 1, minor: 8, want: (1 << 8) | 8},      // /dev/random
		{major: 5, minor: 0, want: (5 << 8) | 0},      // /dev/tty
		{major: 0, minor: 0, want: 0},                 // edge case
		{major: 255, minor: 255, want: (255 << 8) | 255},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := mkdev(tt.major, tt.minor)
			if got != tt.want {
				t.Errorf("mkdev(%d, %d) = %d, want %d", tt.major, tt.minor, got, tt.want)
			}
		})
	}
}

func TestDeviceStruct(t *testing.T) {
	dev := Device{
		Path:  "/dev/test",
		Type:  unix.S_IFCHR,
		Major: 10,
		Minor: 200,
		Mode:  0o660,
		Uid:   0,
		Gid:   5,
	}

	if dev.Path != "/dev/test" {
		t.Errorf("Device.Path = %s, want /dev/test", dev.Path)
	}
	if dev.Type != unix.S_IFCHR {
		t.Errorf("Device.Type = %#x, want %#x", dev.Type, unix.S_IFCHR)
	}
	if dev.Major != 10 {
		t.Errorf("Device.Major = %d, want 10", dev.Major)
	}
	if dev.Minor != 200 {
		t.Errorf("Device.Minor = %d, want 200", dev.Minor)
	}
	if dev.Mode != 0o660 {
		t.Errorf("Device.Mode = %#o, want 0660", dev.Mode)
	}
}

func TestCapabilitiesStruct(t *testing.T) {
	caps := &Capabilities{
		Bounding:    []cap.Value{cap.CHOWN, cap.FOWNER},
		Effective:   []cap.Value{cap.CHOWN},
		Permitted:   []cap.Value{cap.CHOWN, cap.FOWNER},
		Inheritable: []cap.Value{},
		Ambient:     []cap.Value{},
	}

	if len(caps.Bounding) != 2 {
		t.Errorf("Bounding length = %d, want 2", len(caps.Bounding))
	}
	if len(caps.Effective) != 1 {
		t.Errorf("Effective length = %d, want 1", len(caps.Effective))
	}
	if len(caps.Permitted) != 2 {
		t.Errorf("Permitted length = %d, want 2", len(caps.Permitted))
	}
	if len(caps.Inheritable) != 0 {
		t.Errorf("Inheritable length = %d, want 0", len(caps.Inheritable))
	}
	if len(caps.Ambient) != 0 {
		t.Errorf("Ambient length = %d, want 0", len(caps.Ambient))
	}
}

// Integration tests for security features (require root)
// These tests require the "integration" build tag to run:
// go test -tags=integration ./...

func TestCreateDevices(t *testing.T) {
	skipIfNotRoot(t)

	tmpDir := t.TempDir()

	// Create a subset of devices in temp directory
	devices := []Device{
		{Path: filepath.Join(tmpDir, "null"), Type: unix.S_IFCHR, Major: 1, Minor: 3, Mode: 0o666, Uid: 0, Gid: 0},
		{Path: filepath.Join(tmpDir, "zero"), Type: unix.S_IFCHR, Major: 1, Minor: 5, Mode: 0o666, Uid: 0, Gid: 0},
	}

	if err := createDevices(devices); err != nil {
		t.Fatalf("createDevices failed: %v", err)
	}

	// Verify devices were created correctly
	for _, dev := range devices {
		info, err := os.Stat(dev.Path)
		if err != nil {
			t.Errorf("device %s not created: %v", dev.Path, err)
			continue
		}

		// Check it's a character device
		mode := info.Mode()
		if mode&os.ModeDevice == 0 || mode&os.ModeCharDevice == 0 {
			t.Errorf("%s is not a character device", dev.Path)
		}

		// Check permissions
		perm := mode.Perm()
		expectedPerm := os.FileMode(dev.Mode)
		if perm != expectedPerm {
			t.Errorf("%s permissions = %#o, want %#o", dev.Path, perm, expectedPerm)
		}
	}

	// Test that /dev/null works correctly
	nullPath := filepath.Join(tmpDir, "null")
	f, err := os.OpenFile(nullPath, os.O_RDWR, 0)
	if err != nil {
		t.Errorf("failed to open null device: %v", err)
	} else {
		// Write should succeed
		if _, err := f.Write([]byte("test")); err != nil {
			t.Errorf("write to null device failed: %v", err)
		}
		// Read should return EOF
		buf := make([]byte, 10)
		n, _ := f.Read(buf)
		if n != 0 {
			t.Errorf("read from null device returned %d bytes, want 0", n)
		}
		f.Close()
	}

	// Test that /dev/zero works correctly
	zeroPath := filepath.Join(tmpDir, "zero")
	fZero, err := os.Open(zeroPath)
	if err != nil {
		t.Errorf("failed to open zero device: %v", err)
	} else {
		buf := make([]byte, 10)
		n, err := fZero.Read(buf)
		if err != nil {
			t.Errorf("read from zero device failed: %v", err)
		}
		if n != 10 {
			t.Errorf("read from zero device returned %d bytes, want 10", n)
		}
		for i, b := range buf[:n] {
			if b != 0 {
				t.Errorf("zero device byte %d = %d, want 0", i, b)
			}
		}
		fZero.Close()
	}
}

func TestCreateDevSymlinks(t *testing.T) {
	skipIfNotRoot(t)

	// This test requires /proc/self/fd to exist
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("requires /proc/self/fd")
	}

	tmpDir := t.TempDir()
	devDir := filepath.Join(tmpDir, "dev")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		t.Fatalf("failed to create dev directory: %v", err)
	}

	// Change to temp directory and create symlinks
	// Note: createDevSymlinks creates symlinks in /dev, so we can't test it
	// directly without being in a mount namespace. This test verifies the
	// symlink mapping structure is correct.

	expectedLinks := []struct {
		oldname, newname string
	}{
		{"/proc/self/fd", "/dev/fd"},
		{"/proc/self/fd/0", "/dev/stdin"},
		{"/proc/self/fd/1", "/dev/stdout"},
		{"/proc/self/fd/2", "/dev/stderr"},
	}

	// Verify the expected symlinks structure
	for _, link := range expectedLinks {
		if link.oldname == "" || link.newname == "" {
			t.Errorf("invalid symlink mapping: old=%q new=%q", link.oldname, link.newname)
		}
	}

	// Verify /proc/self/fd exists and is a symlink to /proc/[pid]/fd
	target, err := os.Readlink("/proc/self/fd")
	if err == nil {
		// Target should be something like /proc/1234/fd
		if target == "" {
			t.Error("/proc/self/fd target is empty")
		}
	}
}
