//go:build !cgo

package container

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// startChild launches the child using SysProcAttr.Cloneflags (no CGO).
func (c *Container) startChild(subcommand string, p *Process, extraArgs []string, rp *readyPipes) (int, error) {
	initR, initW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("init pipe: %w", err)
	}

	args := []string{subcommand}
	args = append(args, extraArgs...)

	cmd := exec.Command("/proc/self/exe", args...)
	extraFiles := []*os.File{initR}
	fdOffset := 3 + len(extraFiles)
	env := append(os.Environ(),
		fmt.Sprintf("_CONTAINER_INITFD=%d", 3+0),
	)

	// Shared: ready pipes + console socket.
	consoleParent, err := addChildPipes(&extraFiles, &env, fdOffset, p, rp)
	if err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}

	cmd.ExtraFiles = extraFiles
	cmd.Env = env

	// Pure Go: namespaces via clone flags at fork time.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  c.cfg.Namespaces.CloneFlags(),
		UidMappings: c.cfg.UidMappings,
		GidMappings: c.cfg.GidMappings,
	}
	closeCgroupFD, err := c.applyCgroupClone(cmd)
	if err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}
	defer closeCgroupFD()

	if err := c.setupStdio(cmd, p); err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}

	c.cmd = cmd

	if err := cmd.Start(); err != nil {
		initW.Close()
		return 0, fmt.Errorf("start child: %w", err)
	}

	initR.Close()

	// Shared: write init data JSON + receive console.
	if err := c.finishChildStart(initW, p, consoleParent); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}

// ExecWithNsenter enters namespaces of the target process and executes a command.
// Without CGO, returns an error if the target has a different user or mount
// namespace (these require single-threaded setns).
func ExecWithNsenter(pid int, config ExecConfig) (*exec.Cmd, error) {
	pidStr := fmt.Sprintf("%d", pid)
	if nsDiffers(pidStr, "user") {
		return nil, fmt.Errorf("cannot join user namespace without CGO (requires single-threaded setns)")
	}
	if nsDiffers(pidStr, "mnt") {
		return nil, fmt.Errorf("cannot join mount namespace without CGO (requires single-threaded setns)")
	}
	return execReexec(pid, config)
}

// nsenterJoinHandler joins safe namespaces from Go, then execs.
func nsenterJoinHandler() {
	pidStr := os.Getenv("_CONTAINER_PID")
	if pidStr != "" {
		if err := joinNamespacesPureGo(pidStr); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse: __nsenter [--root=X] [--wd=X] -- cmd args...
	args := os.Args[2:]

	var root, wd string
	cmdStart := -1

	for i, arg := range args {
		if arg == "--" {
			cmdStart = i + 1
			break
		}
		if strings.HasPrefix(arg, "--root=") {
			root = strings.TrimPrefix(arg, "--root=")
		} else if strings.HasPrefix(arg, "--wd=") {
			wd = strings.TrimPrefix(arg, "--wd=")
		}
	}

	if cmdStart < 0 || cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "nsenter: no command specified\n")
		os.Exit(1)
	}

	if root != "" {
		if err := syscall.Chroot(root); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chroot %s: %v\n", root, err)
			os.Exit(1)
		}
		if err := syscall.Chdir("/"); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chdir /: %v\n", err)
			os.Exit(1)
		}
	}

	if wd != "" {
		if err := syscall.Chdir(wd); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chdir %s: %v\n", wd, err)
			os.Exit(1)
		}
	}

	cmdPath := args[cmdStart]
	cmdArgs := args[cmdStart:]
	env := os.Environ()

	if err := syscall.Exec(cmdPath, cmdArgs, env); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: exec %s: %v\n", cmdPath, err)
		os.Exit(1)
	}
}

// joinNamespacesPureGo joins namespaces that are safe from Go (uts, ipc, net, pid).
func joinNamespacesPureGo(pidStr string) error {
	runtime.LockOSThread()

	safeNs := []struct {
		name string
		flag int
	}{
		{"uts", unix.CLONE_NEWUTS},
		{"ipc", unix.CLONE_NEWIPC},
		{"net", unix.CLONE_NEWNET},
		{"pid", unix.CLONE_NEWPID},
		{"cgroup", unix.CLONE_NEWCGROUP},
		{"time", unix.CLONE_NEWTIME},
	}

	for _, ns := range safeNs {
		if !nsDiffers(pidStr, ns.name) {
			continue
		}
		nsPath := fmt.Sprintf("/proc/%s/ns/%s", pidStr, ns.name)
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			return fmt.Errorf("setns %s: %w", ns.name, err)
		}
		unix.Close(fd)
	}

	return nil
}
