package container

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// ExecConfig configures how to exec into a running container
type ExecConfig struct {
	// Cmd is the command to execute
	Cmd string
	// Args are the command arguments
	Args []string
	// Env are environment variables
	Env []string
	// WorkDir is the working directory
	WorkDir string
	// Root is the root filesystem path (for chroot-based containers)
	Root string
	// Stdin is the stdin reader
	Stdin io.Reader
	// Stdout is the stdout writer
	Stdout io.Writer
	// Stderr is the stderr writer
	Stderr io.Writer
}

// Exec executes a command in the container's namespaces
// Note: Due to Go's multithreading model, we cannot safely join user namespaces.
// This uses nsenter(1) as a workaround for proper namespace joining.
func (c *Container) Exec(config ExecConfig) (*exec.Cmd, error) {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil, fmt.Errorf("container not running")
	}

	// Only set root for chroot mode - pivot_root changes the mount namespace root
	if config.Root == "" && !c.cfg.UsePivotRoot {
		config.Root = c.cfg.Root
	}

	pid := c.cmd.Process.Pid
	return ExecWithNsenter(pid, config)
}

// ExecWithNsenter uses the nsenter(1) utility to properly enter all namespaces
// This is the safest approach as nsenter is a single-threaded C program
func ExecWithNsenter(pid int, config ExecConfig) (*exec.Cmd, error) {
	// Build nsenter command
	// nsenter will enter all namespaces of the target process
	args := []string{
		fmt.Sprintf("--target=%d", pid),
		"--mount",
		"--uts",
		"--ipc",
		"--net",
		"--pid",
	}

	// Only enter user namespace if target is in a different user namespace than us
	// Every process has /proc/PID/ns/user, but entering the same namespace fails
	targetUserNs, err1 := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", pid))
	selfUserNs, err2 := os.Readlink("/proc/self/ns/user")
	if err1 == nil && err2 == nil && targetUserNs != selfUserNs {
		args = append(args, "--user")
	}

	// Add root filesystem if specified (needed for chroot-based containers)
	if config.Root != "" {
		args = append(args, fmt.Sprintf("--root=%s", config.Root))
	}

	// Add working directory if specified
	if config.WorkDir != "" {
		args = append(args, fmt.Sprintf("--wd=%s", config.WorkDir))
	}

	// Add the command to execute
	args = append(args, "--", config.Cmd)
	args = append(args, config.Args...)

	cmd := exec.Command("nsenter", args...)
	cmd.Env = config.Env
	if len(cmd.Env) == 0 {
		cmd.Env = os.Environ()
	}

	cmd.Stdin = config.Stdin
	cmd.Stdout = config.Stdout
	cmd.Stderr = config.Stderr

	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	return cmd, nil
}

// ExecNoUserNs executes in container namespaces except user namespace.
//
// WARNING: This function has significant limitations due to Go's runtime being
// multithreaded. The setns() syscall for mount namespace requires a single-threaded
// process, which Go cannot guarantee. This will likely fail with EINVAL.
//
// For reliable exec into containers, use ExecWithNsenter instead, which delegates
// to the nsenter(1) utility (a single-threaded C program).
//
// This function is kept for cases where you only need to enter non-mount namespaces
// or when called very early before Go's runtime spawns additional threads.
func ExecNoUserNs(pid int, config ExecConfig) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Enter non-user namespaces (these are safe to enter from Go)
	nsTypes := []struct {
		name string
		flag int
	}{
		{"mnt", unix.CLONE_NEWNS},
		{"uts", unix.CLONE_NEWUTS},
		{"ipc", unix.CLONE_NEWIPC},
		{"net", unix.CLONE_NEWNET},
		// Note: PID namespace only affects children, not the calling process
	}

	for _, ns := range nsTypes {
		nsPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns", ns.name)
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue // Namespace might not exist
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			return fmt.Errorf("setns %s: %w", ns.name, err)
		}
		unix.Close(fd)
	}

	// Change to container's root filesystem via /proc/PID/root
	rootPath := fmt.Sprintf("/proc/%d/root", pid)
	if err := unix.Chroot(rootPath); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}

	if config.WorkDir != "" {
		if err := unix.Chdir(config.WorkDir); err != nil {
			return fmt.Errorf("chdir workdir: %w", err)
		}
	}

	// Execute the command (replaces current process)
	env := config.Env
	if len(env) == 0 {
		env = os.Environ()
	}

	return syscall.Exec(config.Cmd, append([]string{config.Cmd}, config.Args...), env)
}

// nsenterExec is called when binary is invoked with __exec
// Uses the /proc/PID/root approach which doesn't require joining user namespace
func nsenterExec() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: __exec <pid> <cmd> [args...]\n")
		os.Exit(1)
	}

	var pid int
	if _, err := fmt.Sscanf(os.Args[2], "%d", &pid); err != nil {
		fmt.Fprintf(os.Stderr, "invalid pid: %s\n", os.Args[2])
		os.Exit(1)
	}

	config := ExecConfig{
		Cmd:  os.Args[3],
		Args: os.Args[4:],
		Env:  os.Environ(),
	}

	if err := ExecNoUserNs(pid, config); err != nil {
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		os.Exit(1)
	}
}

// JoinNetworkNamespace joins the network namespace of another process
// This is safe to call from Go as network namespace doesn't have the
// same threading issues as user namespace
func JoinNetworkNamespace(pid int) error {
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return err
	}
	defer ns.Close()

	runtime.LockOSThread()
	return netns.Set(ns)
}

// GetNamespacePaths returns paths to all namespace files for a process
func GetNamespacePaths(pid int) map[string]string {
	nsTypes := []string{"user", "mnt", "uts", "ipc", "net", "pid", "cgroup"}
	result := make(map[string]string)

	for _, ns := range nsTypes {
		path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns", ns)
		if _, err := os.Stat(path); err == nil {
			result[ns] = path
		}
	}

	return result
}
