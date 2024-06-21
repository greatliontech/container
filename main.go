package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/greatliontech/ocifs"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__child" {
		child()
		return
	}

	supervised := flag.Bool("supervised", false, "run in supervised mode")
	flag.Parse()
	slog.Info("running in supervised mode", "supervised", *supervised)

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

	srcroot := "/home/nikolas/repos/thegrumpylion/chroot/src"
	srv, err := ofs.Mount(h, srcroot)
	if err != nil {
		slog.Error("failed to mount", "msg", err)
		os.Exit(1)
	}
	go srv.Wait()

	localAddresses()

	cmd := exec.Command("/proc/self/exe", "__child")
	if supervised != nil && *supervised {
		slog.Info("running in supervised mode", "supervised", *supervised)
		cmd.Args = append(cmd.Args, "--supervised")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
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
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		slog.Error("failed to run", "msg", err)
	}

	if srv.Unmount() != nil {
		slog.Error("failed to unmount", "msg", err)
	}
}

func child() {
	srcroot := "/home/nikolas/repos/thegrumpylion/chroot/src"
	newroot := "/home/nikolas/repos/thegrumpylion/chroot/mnt"

	supervised := flag.Bool("supervised", false, "run in supervised mode")
	flag.Parse()

	// bind mount srcroot to newroot
	if err := unix.Mount(srcroot, newroot, "auto", unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		fmt.Printf("failed to bind mount /tmp: %v\n", err)
	}

	// mount proc
	if err := unix.Mount("none", filepath.Join(newroot, "proc"), "proc", 0, ""); err != nil {
		fmt.Printf("failed to mount procfs: %v\n", err)
	}

	// mount sys
	if err := unix.Mount("none", filepath.Join(newroot, "sys"), "sysfs", 0, ""); err != nil {
		fmt.Printf("failed to mount sysfs: %v\n", err)
	}

	// mount dev
	if err := unix.Mount("none", filepath.Join(newroot, "dev"), "tmpfs", 0, ""); err != nil {
		fmt.Printf("failed to mount devfs: %v\n", err)
	}

	// chroot
	if err := unix.Chroot(newroot); err != nil {
		fmt.Printf("chroot err: %v\n", err)
	}

	// cd /
	if err := os.Chdir("/"); err != nil {
		fmt.Printf("chdir err: %v\n", err)
	}

	// print the current working directory
	cwd, err := os.Getwd()
	fmt.Printf("cwd: %s, err: %v\n", cwd, err)

	if supervised != nil && !*supervised {
		// exec /bin/sh
		if err := unix.Exec("/bin/sh", []string{"/bin/sh"}, os.Environ()); err != nil {
			fmt.Printf("exec err: %v\n", err)
		}
	}

	// exec /bin/sh
	cmd := exec.Command("/bin/sh")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		slog.Error("failed to run", "msg", err)
	}
}

func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		slog.Error("failed to get local addresses", "msg", err)
		return
	}
	for _, i := range ifaces {
		slog.Info("interface", "name", i.Name)
	}
}
