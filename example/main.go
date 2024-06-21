package main

import (
	"log/slog"
	"os"
	"syscall"

	"github.com/greatliontech/container"
	"github.com/greatliontech/ocifs"
)

func main() {
	ofs, err := ocifs.New()
	if err != nil {
		slog.Error("failed to create ocifs", "msg", err)
		os.Exit(1)
	}

	h, err := ofs.Pull("docker.io/busybox:latest")
	if err != nil {
		slog.Error("failed to pull", "msg", err)
		os.Exit(1)
	}

	srcroot, err := os.MkdirTemp(os.TempDir(), "src")
	if err != nil {
		slog.Error("failed to create src temp dir", "msg", err)
		os.Exit(1)
	}
	defer os.RemoveAll(srcroot)

	trgtroot, err := os.MkdirTemp(os.TempDir(), "trgt")
	if err != nil {
		slog.Error("failed to create trgt temp dir", "msg", err)
		os.Exit(1)
	}
	defer os.RemoveAll(trgtroot)

	srv, err := ofs.Mount(h, srcroot)
	if err != nil {
		slog.Error("failed to mount", "msg", err)
		os.Exit(1)
	}
	go srv.Wait()

	cfg := container.Config{
		Root:     trgtroot,
		Hostname: "test",
		Namespaces: container.Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewNet:  true,
			NewPID:  true,
			NewUTS:  true,
			NewUser: true,
		},
		Mounts: []container.Mount{
			{
				Source: srcroot,
				Target: trgtroot,
				Type:   "auto",
				Flags:  syscall.MS_BIND | syscall.MS_RDONLY,
			},
			{
				Source: "none",
				Target: trgtroot + "/proc",
				Type:   "proc",
			},
			{
				Source: "none",
				Target: trgtroot + "/sys",
				Type:   "sysfs",
			},
		},
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      syscall.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      syscall.Getgid(),
				Size:        1,
			},
		},
	}

	cont, err := container.New("/tmp/contstate", "testcont", cfg)
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

	if srv.Unmount() != nil {
		slog.Error("failed to unmount", "msg", err)
	}
}
