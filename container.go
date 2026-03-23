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
	readyW       *os.File // parent writes "go" here to unblock child exec
	console      *os.File // master PTY fd (when Process.Terminal is true)
	stdinPipe    io.WriteCloser
	stdoutPipe   io.ReadCloser
	stderrPipe   io.ReadCloser
}

// readyPipes holds the pipe pair used for Create/Start separation.
// The child writes to statusW after setup, then blocks reading readyR.
// The parent reads statusR in Create(), writes readyW in Start().
type readyPipes struct {
	statusR *os.File // parent reads "setup done"
	statusW *os.File // child writes "setup done"
	readyR  *os.File // child reads "go"
	readyW  *os.File // parent writes "go"
}

func newReadyPipes() (*readyPipes, error) {
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("status pipe: %w", err)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		statusR.Close()
		statusW.Close()
		return nil, fmt.Errorf("ready pipe: %w", err)
	}
	return &readyPipes{
		statusR: statusR,
		statusW: statusW,
		readyR:  readyR,
		readyW:  readyW,
	}, nil
}

func (rp *readyPipes) closeAll() {
	rp.statusR.Close()
	rp.statusW.Close()
	rp.readyR.Close()
	rp.readyW.Close()
}

// New creates a new container with the given configuration.
func New(id string, cfg Config) *Container {
	return &Container{
		id:  id,
		cfg: cfg,
	}
}

// Create sets up the container (namespaces, mounts, security) but does NOT
// exec the target process. The container is in "created" state after this
// returns. Call Start() to exec the target.
//
// This enables OCI-style lifecycle hooks between create and start:
//
//	c.Create(proc)
//	// createRuntime / createContainer hooks run here
//	c.Start()
//	// startContainer / poststart hooks run here
func Create(id string, cfg Config, p *Process) (*Container, error) {
	c := New(id, cfg)

	rp, err := newReadyPipes()
	if err != nil {
		return nil, err
	}

	containerPid, err := c.startChild("__container", p, nil, rp)
	if err != nil {
		rp.closeAll()
		return nil, err
	}
	c.containerPid = containerPid

	// Close child-side ends.
	rp.statusW.Close()
	rp.readyR.Close()

	// Wait for child to signal "setup done".
	var buf [1]byte
	if _, err := rp.statusR.Read(buf[:]); err != nil {
		rp.statusR.Close()
		rp.readyW.Close()
		return nil, fmt.Errorf("wait for child ready: %w", err)
	}
	rp.statusR.Close()

	// Store readyW for Start().
	c.readyW = rp.readyW

	if err := c.postStart(); err != nil {
		return nil, err
	}

	return c, nil
}

// Start signals the container child to exec the target process.
// Must be called after Create(). The container moves to "running" state.
func (c *Container) Start() error {
	if c.readyW == nil {
		return fmt.Errorf("container not in created state (use Create, not Run)")
	}

	_, err := c.readyW.Write([]byte{0})
	c.readyW.Close()
	c.readyW = nil
	return err
}

// Run creates and starts the container in one call.
// Equivalent to Create() + Start().
func (c *Container) Run(p *Process) error {
	rp, err := newReadyPipes()
	if err != nil {
		return err
	}

	containerPid, err := c.startChild("__container", p, nil, rp)
	if err != nil {
		rp.closeAll()
		return err
	}
	c.containerPid = containerPid

	rp.statusW.Close()
	rp.readyR.Close()

	// Wait for "setup done".
	var buf [1]byte
	if _, err := rp.statusR.Read(buf[:]); err != nil {
		rp.statusR.Close()
		rp.readyW.Close()
		return fmt.Errorf("wait for child ready: %w", err)
	}
	rp.statusR.Close()

	// Immediately signal "go".
	if _, err := rp.readyW.Write([]byte{0}); err != nil {
		rp.readyW.Close()
		return fmt.Errorf("signal child start: %w", err)
	}
	rp.readyW.Close()

	return c.postStart()
}

// RunSelf starts a container where the target binary is this process itself.
// No Create/Start separation — the child returns to main() after setup.
func (c *Container) RunSelf(args ...string) error {
	containerPid, err := c.startChild("__self", nil, args, nil)
	if err != nil {
		return err
	}
	c.containerPid = containerPid
	return c.postStart()
}

// postStart handles cgroup setup after the container process starts.
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

// Console returns the master PTY fd when the process was started with
// Terminal: true. Returns nil if no terminal was requested.
func (c *Container) Console() *os.File {
	return c.console
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
		err := c.cmd.Wait()
		c.exited = true
		if c.cmd.ProcessState != nil {
			c.exitCode = c.cmd.ProcessState.ExitCode()
		}
		return err
	}

	_ = c.cmd.Wait()

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
	if c.readyW != nil {
		c.readyW.Close()
		c.readyW = nil
	}
	if c.console != nil {
		c.console.Close()
		c.console = nil
	}

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
