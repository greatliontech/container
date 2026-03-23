package container

import (
	"encoding/json"
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
	network      *Network
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
// The process is executed inside namespaces configured via the C constructor.
func (c *Container) Run(p *Process) error {
	if c.cfg.Resources != nil {
		cg, err := NewCgroup("container-" + c.id)
		if err != nil {
			slog.Warn("failed to create cgroup, running without resource limits", "error", err)
		} else {
			c.cgroup = cg
			if err := cg.Apply(c.cfg.Resources); err != nil {
				slog.Warn("failed to apply resource limits", "error", err)
			}
		}
	}

	containerPid, err := c.startChild("__container", p, nil)
	if err != nil {
		return err
	}
	c.containerPid = containerPid

	// Add container process to cgroup.
	if c.cgroup != nil {
		if err := c.cgroup.AddProcess(c.containerPid); err != nil {
			slog.Warn("failed to add process to cgroup", "error", err)
		}
	}

	// Setup networking (needs PID for netns).
	if c.cfg.Network != nil && c.cfg.Network.Mode == NetworkModeBridge {
		net, err := SetupContainerNetwork(c.containerPid, *c.cfg.Network)
		if err != nil {
			slog.Warn("failed to setup network", "error", err)
		} else {
			c.network = net
		}
	}

	return nil
}

// RunSelf starts a container where the target binary is this process itself.
// The child re-execs /proc/self/exe through the C constructor, and main()
// detects InContainer() to run container-specific logic.
func (c *Container) RunSelf(args ...string) error {
	if c.cfg.Resources != nil {
		cg, err := NewCgroup("container-" + c.id)
		if err != nil {
			slog.Warn("failed to create cgroup, running without resource limits", "error", err)
		} else {
			c.cgroup = cg
			if err := cg.Apply(c.cfg.Resources); err != nil {
				slog.Warn("failed to apply resource limits", "error", err)
			}
		}
	}

	containerPid, err := c.startChild("__self", nil, args)
	if err != nil {
		return err
	}
	c.containerPid = containerPid

	if c.cgroup != nil {
		if err := c.cgroup.AddProcess(c.containerPid); err != nil {
			slog.Warn("failed to add process to cgroup", "error", err)
		}
	}

	if c.cfg.Network != nil && c.cfg.Network.Mode == NetworkModeBridge {
		net, err := SetupContainerNetwork(c.containerPid, *c.cfg.Network)
		if err != nil {
			slog.Warn("failed to setup network", "error", err)
		} else {
			c.network = net
		}
	}

	return nil
}

// startChild launches the child process.
// With CGO: uses the C constructor for namespace setup (pipes + sync protocol).
// Without CGO: uses SysProcAttr.Cloneflags (pure Go).
// Returns the container PID.
func (c *Container) startChild(subcommand string, p *Process, extraArgs []string) (int, error) {
	if builtinNsenter {
		return c.startChildCGO(subcommand, p, extraArgs)
	}
	return c.startChildPureGo(subcommand, p, extraArgs)
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

// startChildCGO launches the child via the C constructor (pipes + sync protocol).
func (c *Container) startChildCGO(subcommand string, p *Process, extraArgs []string) (int, error) {
	// Set child subreaper so forked grandchild reparents to us.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("prctl child subreaper: %w", err)
	}

	// Create pipes.
	configR, configW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("config pipe: %w", err)
	}
	initR, initW, err := os.Pipe()
	if err != nil {
		configR.Close()
		configW.Close()
		return 0, fmt.Errorf("init pipe: %w", err)
	}
	syncParent, syncChild, err := newSyncSocketpair()
	if err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		return 0, fmt.Errorf("sync socketpair: %w", err)
	}

	args := []string{subcommand}
	args = append(args, extraArgs...)

	cmd := exec.Command("/proc/self/exe", args...)
	cmd.ExtraFiles = []*os.File{configR, syncChild, initR}
	cmd.Env = append(os.Environ(),
		"_CONTAINER_MODE=setup",
		fmt.Sprintf("_CONTAINER_CONFIGFD=%d", 3+0),
		fmt.Sprintf("_CONTAINER_SYNCFD=%d", 3+1),
		fmt.Sprintf("_CONTAINER_INITFD=%d", 3+2),
	)

	if err := c.setupStdio(cmd, p); err != nil {
		return 0, err
	}

	c.cmd = cmd

	if err := cmd.Start(); err != nil {
		syncParent.Close()
		configW.Close()
		initW.Close()
		return 0, fmt.Errorf("start child: %w", err)
	}

	configR.Close()
	syncChild.Close()
	initR.Close()

	// Write C config.
	cConfig := &nsenterCConfig{
		CloneFlags: uint32(c.cfg.Namespaces.CloneFlags()),
	}
	if c.cfg.Namespaces.NewUser && isSingleMapping(c.cfg.UidMappings, c.cfg.GidMappings) {
		cConfig.SelfMap = 1
		if len(c.cfg.UidMappings) > 0 {
			cConfig.UID = uint32(c.cfg.UidMappings[0].HostID)
		}
		if len(c.cfg.GidMappings) > 0 {
			cConfig.GID = uint32(c.cfg.GidMappings[0].HostID)
		}
	}
	joins := buildJoinSpecs(&c.cfg.Namespaces)
	cConfig.JoinCount = uint32(len(joins))

	if err := writeNsenterCConfig(configW, cConfig, joins); err != nil {
		configW.Close()
		initW.Close()
		syncParent.Close()
		return 0, fmt.Errorf("write C config: %w", err)
	}
	configW.Close()

	// Write init data (JSON).
	data := initData{Config: c.cfg, Process: p}
	if err := json.NewEncoder(initW).Encode(&data); err != nil {
		initW.Close()
		syncParent.Close()
		return 0, fmt.Errorf("write init data: %w", err)
	}
	initW.Close()

	// Run sync protocol.
	containerPid, err := runParentSync(syncParent, cmd.Process.Pid, &c.cfg)
	syncParent.Close()
	if err != nil {
		return 0, fmt.Errorf("sync protocol: %w", err)
	}

	return containerPid, nil
}

// startChildPureGo launches the child using SysProcAttr.Cloneflags (no CGO).
// Namespace creation happens at fork time via clone(). The child starts
// directly in the new namespaces as PID 1.
func (c *Container) startChildPureGo(subcommand string, p *Process, extraArgs []string) (int, error) {
	initR, initW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("init pipe: %w", err)
	}

	args := []string{subcommand}
	args = append(args, extraArgs...)

	cmd := exec.Command("/proc/self/exe", args...)
	cmd.ExtraFiles = []*os.File{initR}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("_CONTAINER_INITFD=%d", 3+0),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  c.cfg.Namespaces.CloneFlags(),
		UidMappings: c.cfg.UidMappings,
		GidMappings: c.cfg.GidMappings,
	}

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

	// Write init data (JSON).
	data := initData{Config: c.cfg, Process: p}
	if err := json.NewEncoder(initW).Encode(&data); err != nil {
		initW.Close()
		return 0, fmt.Errorf("write init data: %w", err)
	}
	initW.Close()

	return cmd.Process.Pid, nil
}

// isSingleMapping returns true if the UID/GID mappings are suitable for
// rootless self-write (single mapping with size 1).
func isSingleMapping(uid, gid []syscall.SysProcIDMap) bool {
	return len(uid) == 1 && uid[0].Size == 1 &&
		len(gid) == 1 && gid[0].Size == 1
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

	if c.network != nil {
		if err := c.network.Cleanup(); err != nil {
			errs = append(errs, err)
		}
		c.network = nil
	}

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
