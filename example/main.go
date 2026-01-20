package main

import (
	"log/slog"
	"os"
	"syscall"

	"github.com/greatliontech/container"
	"github.com/greatliontech/ocifs"
)

func main() {
	contID := "example-container"

	ofs, err := ocifs.New(ocifs.WithExtraDirs([]string{
		"/proc", "/sys",
	}))
	if err != nil {
		slog.Error("failed to create ocifs", "msg", err)
		os.Exit(1)
	}

	trgtroot, err := os.MkdirTemp(os.TempDir(), "trgt")
	if err != nil {
		slog.Error("failed to create trgt temp dir", "msg", err)
		os.Exit(1)
	}
	defer os.RemoveAll(trgtroot)

	im, err := ofs.Mount("docker.io/busybox:latest", ocifs.MountWithID(contID))
	if err != nil {
		slog.Error("failed to mount", "msg", err)
		os.Exit(1)
	}

	// Start with secure defaults
	cfg := container.DefaultConfig()
	cfg.Root = trgtroot
	cfg.Hostname = "test"
	cfg.Mounts = []container.Mount{
		{
			Source: im.MountPoint(),
			Target: trgtroot,
			Type:   "auto",
			Flags:  container.MountFlags.Bind,
		},
		{
			Source: "none",
			Target: trgtroot + "/proc",
			Type:   "proc",
			Flags:  container.MountFlags.Proc,
		},
		{
			Source: "none",
			Target: trgtroot + "/sys",
			Type:   "sysfs",
			Flags:  container.MountFlags.Sysfs,
		},
	}
	cfg.UidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      syscall.Getuid(),
			Size:        1,
		},
	}
	cfg.GidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      syscall.Getgid(),
			Size:        1,
		},
	}
	// Security features enabled by DefaultConfig():
	// - UsePivotRoot: true (uses pivot_root instead of chroot)
	// - Capabilities: minimal set for containers
	// - Seccomp: blocks dangerous syscalls
	// - SetupDev: true (creates /dev with minimal devices)
	// - NoNewPrivileges: true

	cont, err := container.New("/tmp/contstatetest", contID, cfg)
	if err != nil {
		slog.Error("failed to create container", "msg", err)
		os.Exit(1)
	}

	p := &container.Process{
		Cmd:    "/bin/sh",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if err := cont.Run(p); err != nil {
		slog.Error("failed to run", "msg", err)
		os.Exit(1)
	}

	if err := cont.Wait(); err != nil {
		slog.Error("failed to wait", "msg", err)
	}

	if im.Unmount() != nil {
		slog.Error("failed to unmount", "msg", err)
	}
}
