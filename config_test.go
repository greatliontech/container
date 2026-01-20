package container

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNamespaces_CloneFlags(t *testing.T) {
	tests := []struct {
		name       string
		namespaces Namespaces
		wantFlags  uintptr
	}{
		{
			name:       "empty namespaces",
			namespaces: Namespaces{},
			wantFlags:  0,
		},
		{
			name: "all namespaces",
			namespaces: Namespaces{
				NewIPC:  true,
				NewMnt:  true,
				NewNet:  true,
				NewPID:  true,
				NewUTS:  true,
				NewUser: true,
			},
			wantFlags: syscall.CLONE_NEWIPC | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
				syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWUSER,
		},
		{
			name: "only IPC namespace",
			namespaces: Namespaces{
				NewIPC: true,
			},
			wantFlags: syscall.CLONE_NEWIPC,
		},
		{
			name: "only mount namespace",
			namespaces: Namespaces{
				NewMnt: true,
			},
			wantFlags: syscall.CLONE_NEWNS,
		},
		{
			name: "only network namespace",
			namespaces: Namespaces{
				NewNet: true,
			},
			wantFlags: syscall.CLONE_NEWNET,
		},
		{
			name: "only PID namespace",
			namespaces: Namespaces{
				NewPID: true,
			},
			wantFlags: syscall.CLONE_NEWPID,
		},
		{
			name: "only UTS namespace",
			namespaces: Namespaces{
				NewUTS: true,
			},
			wantFlags: syscall.CLONE_NEWUTS,
		},
		{
			name: "only user namespace",
			namespaces: Namespaces{
				NewUser: true,
			},
			wantFlags: syscall.CLONE_NEWUSER,
		},
		{
			name: "network and PID namespaces",
			namespaces: Namespaces{
				NewNet: true,
				NewPID: true,
			},
			wantFlags: syscall.CLONE_NEWNET | syscall.CLONE_NEWPID,
		},
		{
			name: "typical container namespaces",
			namespaces: Namespaces{
				NewIPC: true,
				NewMnt: true,
				NewNet: true,
				NewPID: true,
				NewUTS: true,
			},
			wantFlags: syscall.CLONE_NEWIPC | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
				syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.namespaces.CloneFlags()
			if got != tt.wantFlags {
				t.Errorf("CloneFlags() = %#x, want %#x", got, tt.wantFlags)
			}
		})
	}
}

func TestNamespaces_CloneFlagsValues(t *testing.T) {
	// Verify that the syscall constants have expected values
	// This catches if constants change in the syscall package
	if syscall.CLONE_NEWIPC == 0 {
		t.Error("CLONE_NEWIPC should not be 0")
	}
	if syscall.CLONE_NEWNS == 0 {
		t.Error("CLONE_NEWNS should not be 0")
	}
	if syscall.CLONE_NEWNET == 0 {
		t.Error("CLONE_NEWNET should not be 0")
	}
	if syscall.CLONE_NEWPID == 0 {
		t.Error("CLONE_NEWPID should not be 0")
	}
	if syscall.CLONE_NEWUTS == 0 {
		t.Error("CLONE_NEWUTS should not be 0")
	}
	if syscall.CLONE_NEWUSER == 0 {
		t.Error("CLONE_NEWUSER should not be 0")
	}

	// Verify flags don't overlap unexpectedly
	flags := []uintptr{
		syscall.CLONE_NEWIPC,
		syscall.CLONE_NEWNS,
		syscall.CLONE_NEWNET,
		syscall.CLONE_NEWPID,
		syscall.CLONE_NEWUTS,
		syscall.CLONE_NEWUSER,
	}

	for i := 0; i < len(flags); i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i]&flags[j] != 0 {
				t.Errorf("flags %#x and %#x overlap", flags[i], flags[j])
			}
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify namespaces are all enabled
	if !cfg.Namespaces.NewIPC {
		t.Error("DefaultConfig should enable IPC namespace")
	}
	if !cfg.Namespaces.NewMnt {
		t.Error("DefaultConfig should enable mount namespace")
	}
	if !cfg.Namespaces.NewNet {
		t.Error("DefaultConfig should enable network namespace")
	}
	if !cfg.Namespaces.NewPID {
		t.Error("DefaultConfig should enable PID namespace")
	}
	if !cfg.Namespaces.NewUTS {
		t.Error("DefaultConfig should enable UTS namespace")
	}
	if !cfg.Namespaces.NewUser {
		t.Error("DefaultConfig should enable user namespace")
	}

	// Verify security settings
	if !cfg.UsePivotRoot {
		t.Error("DefaultConfig should enable pivot_root")
	}
	if cfg.Capabilities == nil {
		t.Error("DefaultConfig should set capabilities")
	}
	if cfg.Seccomp == nil {
		t.Error("DefaultConfig should set seccomp profile")
	}
	if cfg.Devices == nil || len(cfg.Devices) == 0 {
		t.Error("DefaultConfig should set default devices")
	}
	if !cfg.SetupDev {
		t.Error("DefaultConfig should enable /dev setup")
	}
	if !cfg.NoNewPrivileges {
		t.Error("DefaultConfig should enable no_new_privs")
	}

	// Verify default values for optional fields
	if cfg.Root != "" {
		t.Error("DefaultConfig should not set Root")
	}
	if cfg.Hostname != "" {
		t.Error("DefaultConfig should not set Hostname")
	}
	if cfg.Resources != nil {
		t.Error("DefaultConfig should not set Resources")
	}
	if cfg.Network != nil {
		t.Error("DefaultConfig should not set Network")
	}
	if cfg.Hooks != nil {
		t.Error("DefaultConfig should not set Hooks")
	}
}

func TestMountFlags(t *testing.T) {
	// Verify MountFlags contains correct syscall constants
	if MountFlags.Bind != unix.MS_BIND {
		t.Errorf("MountFlags.Bind = %#x, want %#x", MountFlags.Bind, unix.MS_BIND)
	}

	if MountFlags.BindReadOnly != unix.MS_BIND|unix.MS_RDONLY {
		t.Errorf("MountFlags.BindReadOnly = %#x, want %#x", MountFlags.BindReadOnly, unix.MS_BIND|unix.MS_RDONLY)
	}

	expectedProc := unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if MountFlags.Proc != uintptr(expectedProc) {
		t.Errorf("MountFlags.Proc = %#x, want %#x", MountFlags.Proc, expectedProc)
	}

	expectedSysfs := unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY
	if MountFlags.Sysfs != uintptr(expectedSysfs) {
		t.Errorf("MountFlags.Sysfs = %#x, want %#x", MountFlags.Sysfs, expectedSysfs)
	}

	expectedTmpfs := unix.MS_NOSUID | unix.MS_NODEV
	if MountFlags.Tmpfs != uintptr(expectedTmpfs) {
		t.Errorf("MountFlags.Tmpfs = %#x, want %#x", MountFlags.Tmpfs, expectedTmpfs)
	}

	expectedDevpts := unix.MS_NOSUID | unix.MS_NOEXEC
	if MountFlags.Devpts != uintptr(expectedDevpts) {
		t.Errorf("MountFlags.Devpts = %#x, want %#x", MountFlags.Devpts, expectedDevpts)
	}

	if MountFlags.Private != unix.MS_PRIVATE {
		t.Errorf("MountFlags.Private = %#x, want %#x", MountFlags.Private, unix.MS_PRIVATE)
	}

	if MountFlags.Slave != unix.MS_SLAVE {
		t.Errorf("MountFlags.Slave = %#x, want %#x", MountFlags.Slave, unix.MS_SLAVE)
	}

	if MountFlags.Shared != unix.MS_SHARED {
		t.Errorf("MountFlags.Shared = %#x, want %#x", MountFlags.Shared, unix.MS_SHARED)
	}
}

func TestMountStruct(t *testing.T) {
	// Test Mount struct can be properly created
	mount := Mount{
		Source: "proc",
		Target: "/proc",
		Type:   "proc",
		Flags:  MountFlags.Proc,
		Data:   "",
	}

	if mount.Source != "proc" {
		t.Errorf("Mount.Source = %s, want proc", mount.Source)
	}
	if mount.Target != "/proc" {
		t.Errorf("Mount.Target = %s, want /proc", mount.Target)
	}
	if mount.Type != "proc" {
		t.Errorf("Mount.Type = %s, want proc", mount.Type)
	}
}

func TestConfigStruct(t *testing.T) {
	// Test Config struct can be properly created and modified
	cfg := Config{
		Root:     "/rootfs",
		Hostname: "testcontainer",
		Namespaces: Namespaces{
			NewPID: true,
			NewMnt: true,
		},
		Mounts: []Mount{
			{
				Source: "proc",
				Target: "/proc",
				Type:   "proc",
				Flags:  MountFlags.Proc,
			},
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	if cfg.Root != "/rootfs" {
		t.Errorf("Config.Root = %s, want /rootfs", cfg.Root)
	}
	if cfg.Hostname != "testcontainer" {
		t.Errorf("Config.Hostname = %s, want testcontainer", cfg.Hostname)
	}
	if !cfg.Namespaces.NewPID {
		t.Error("Config.Namespaces.NewPID should be true")
	}
	if !cfg.Namespaces.NewMnt {
		t.Error("Config.Namespaces.NewMnt should be true")
	}
	if len(cfg.Mounts) != 1 {
		t.Errorf("Config.Mounts length = %d, want 1", len(cfg.Mounts))
	}
}
