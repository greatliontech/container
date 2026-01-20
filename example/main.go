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

	// Resource limits (cgroups v2)
	// Note: requires cgroups v2 and appropriate permissions
	cfg.Resources = &container.Resources{
		Memory: &container.MemoryResources{
			Max:  512 * 1024 * 1024, // 512MB memory limit
			High: 256 * 1024 * 1024, // 256MB throttling threshold
		},
		CPU: &container.CPUResources{
			Quota:  50000,  // 50ms per 100ms period = 50% of one CPU
			Period: 100000, // 100ms period
		},
		Pids: &container.PidsResources{
			Max: 100, // Max 100 processes (fork bomb protection)
		},
	}

	// Networking (bridge mode)
	// Note: requires root privileges and creates network interfaces
	// Uncomment to enable:
	// cfg.Network = &container.NetworkConfig{
	// 	Mode:      container.NetworkModeBridge,
	// 	Bridge:    "container0",           // bridge name (created if doesn't exist)
	// 	IPAddress: "10.88.0.2/16",         // container IP
	// 	Gateway:   "10.88.0.1",            // gateway (bridge IP)
	// 	DNS:       []string{"8.8.8.8"},    // DNS servers
	// }
	// Also write resolv.conf before running:
	// container.WriteResolvConf(trgtroot, cfg.Network.DNS)
	// container.WriteHosts(trgtroot, cfg.Hostname, cfg.Network.IPAddress)

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

	// Clean up container resources (cgroup, state files)
	if err := cont.Destroy(); err != nil {
		slog.Error("failed to destroy container", "msg", err)
	}

	if im.Unmount() != nil {
		slog.Error("failed to unmount", "msg", err)
	}
}
