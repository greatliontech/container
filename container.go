package container

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__container":
			nsenterCreateHandler()
		case "__self":
			nsenterSelfHandler()
		case "__nsenter":
			nsenterJoinHandler()
		}
	}
}

type Container struct {
	id           string
	cfg          Config
	cmd          *exec.Cmd
	containerPid int
	exitCode     int
	exited       bool
	cgroup       *Cgroup
	stdinPipe    io.WriteCloser
	stdoutPipe   io.ReadCloser
	stderrPipe   io.ReadCloser
}

// New creates a new container with the given configuration.
func New(id string, cfg Config) *Container {
	return &Container{
		id:  id,
		cfg: cfg,
	}
}

// Run starts the container with the given process.
// Namespaces are configured via the C constructor (CGO) or SysProcAttr (pure Go).
func (c *Container) Run(p *Process) error {
	containerPid, err := c.startChild("__container", p, nil)
	if err != nil {
		return err
	}
	c.containerPid = containerPid
	return c.postStart()
}

// RunSelf starts a container where the target binary is this process itself.
// The child re-execs /proc/self/exe through namespace setup, and main()
// detects InContainer() to run container-specific logic.
func (c *Container) RunSelf(args ...string) error {
	containerPid, err := c.startChild("__self", nil, args)
	if err != nil {
		return err
	}
	c.containerPid = containerPid
	return c.postStart()
}

// postStart handles cgroup and network setup after the container process starts.
func (c *Container) postStart() error {
	if c.cfg.Resources != nil {
		cg, err := NewCgroup("container-" + c.id)
		if err != nil {
			slog.Warn("failed to create cgroup, running without resource limits", "error", err)
		} else {
			c.cgroup = cg
			if err := cg.Apply(c.cfg.Resources); err != nil {
				slog.Warn("failed to apply resource limits", "error", err)
			}
			if err := cg.AddProcess(c.containerPid); err != nil {
				slog.Warn("failed to add process to cgroup", "error", err)
			}
		}
	}

	return nil
}

// setupStdio configures stdio pipes on the command.
func (c *Container) setupStdio(cmd *exec.Cmd, p *Process) error {
	if p == nil {
		return nil
	}
	if p.StdinPipe {
		pipe, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		c.stdinPipe = pipe
	} else {
		cmd.Stdin = p.Stdin
	}
	if p.StdoutPipe {
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		c.stdoutPipe = pipe
	} else {
		cmd.Stdout = p.Stdout
	}
	if p.StderrPipe {
		pipe, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		c.stderrPipe = pipe
	} else {
		cmd.Stderr = p.Stderr
	}
	return nil
}

func (c *Container) StdinPipe() (io.WriteCloser, error) {
	if c.stdinPipe == nil {
		return nil, syscall.EINVAL
	}
	return c.stdinPipe, nil
}

func (c *Container) StdoutPipe() (io.ReadCloser, error) {
	if c.stdoutPipe == nil {
		return nil, syscall.EINVAL
	}
	return c.stdoutPipe, nil
}

func (c *Container) StderrPipe() (io.ReadCloser, error) {
	if c.stderrPipe == nil {
		return nil, syscall.EINVAL
	}
	return c.stderrPipe, nil
}

// Wait waits for the container process to exit.
func (c *Container) Wait() error {
	if c.cmd == nil {
		return fmt.Errorf("container not started")
	}

	if c.containerPid == c.cmd.Process.Pid {
		// No fork — direct child is the container process.
		err := c.cmd.Wait()
		c.exited = true
		if c.cmd.ProcessState != nil {
			c.exitCode = c.cmd.ProcessState.ExitCode()
		}
		return err
	}

	// Fork happened. cmd.Wait() blocks until all pipes close
	// (which happens when the grandchild exits, since it inherited the fds).
	_ = c.cmd.Wait()

	// Reap the grandchild to get its exit status.
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(c.containerPid, &ws, 0, nil)
	c.exited = true
	if err != nil {
		return fmt.Errorf("wait4 container: %w", err)
	}
	c.exitCode = ws.ExitStatus()
	if ws.Signaled() {
		c.exitCode = 128 + int(ws.Signal())
		return fmt.Errorf("container killed by signal %d", ws.Signal())
	}
	if ws.ExitStatus() != 0 {
		return fmt.Errorf("container exited with status %d", ws.ExitStatus())
	}
	return nil
}

// Destroy cleans up container resources.
func (c *Container) Destroy() error {
	var errs []error

	if c.cgroup != nil {
		if err := c.cgroup.Delete(); err != nil {
			errs = append(errs, err)
		}
		c.cgroup = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Stats returns current resource usage statistics.
func (c *Container) Stats() (*CgroupStats, error) {
	if c.cgroup == nil {
		return nil, nil
	}
	return c.cgroup.Stats()
}

// pivotRoot changes the root filesystem using pivot_root syscall.
func pivotRoot(newRoot string) error {
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}

	oldRoot := filepath.Join(newRoot, ".pivot_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return err
	}

	if err := unix.PivotRoot(newRoot, oldRoot); err != nil {
		return err
	}

	if err := unix.Chdir("/"); err != nil {
		return err
	}

	oldRoot = "/.pivot_root"
	if err := unix.Unmount(oldRoot, unix.MNT_DETACH); err != nil {
		return err
	}

	os.RemoveAll(oldRoot)
	return nil
}

// setupDev creates a minimal /dev filesystem inside the container rootfs.
func setupDev(root string, devices []Device) error {
	devDir := filepath.Join(root, "dev")

	if err := unix.Mount("tmpfs", devDir, "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "mode=755,size=65536k"); err != nil {
		return fmt.Errorf("mount tmpfs on /dev: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(devDir, "pts"), 0755); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(devDir, "shm"), 1777); err != nil {
		return err
	}

	if devices == nil {
		devices = DefaultDevices()
	}
	if err := createDevices(root, devices); err != nil {
		return err
	}

	return createDevSymlinks(devDir)
}

// lookPath resolves a command name to an absolute path using PATH from env.
func lookPath(cmd string, env []string) (string, error) {
	var path string
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			path = e[5:]
			break
		}
	}
	if path == "" {
		return "", errors.New("PATH not set")
	}
	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, cmd)
		if err := unix.Access(candidate, unix.X_OK); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("command %q not found in PATH", cmd)
}
