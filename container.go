package container

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "__child" {
		child()
	}
}

type Container struct {
	id         string
	cfg        Config
	stf        string
	cmd        *exec.Cmd
	stdinPipe  io.WriteCloser
	stdoutPipe io.ReadCloser
	stderrPipe io.ReadCloser
}

func New(statedir, id string, cfg Config) (*Container, error) {
	if err := os.MkdirAll(statedir, 0700); err != nil {
		return nil, err
	}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	stf := filepath.Join(statedir, id)
	if err := os.WriteFile(stf, cfgData, 0600); err != nil {
		return nil, err
	}
	return &Container{
		id:  id,
		cfg: cfg,
		stf: stf,
	}, nil
}

func (c *Container) Run(p *Process) error {
	cmd := exec.Command("/proc/self/exe", "__child", c.stf)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  c.cfg.Namespaces.CloneFlags(),
		UidMappings: c.cfg.UidMappings,
		GidMappings: c.cfg.GidMappings,
		Credential:  p.Credential,
	}

	if p.StdinPipe {
		slog.Info("stdin pipe requested")
		pipe, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		c.stdinPipe = pipe
	} else {
		cmd.Stdin = p.Stdin
	}

	if p.StdoutPipe {
		slog.Info("stdout pipe requested")
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		c.stdoutPipe = pipe
	} else {
		cmd.Stdout = p.Stdout
	}

	if p.StderrPipe {
		slog.Info("stderr pipe requested")
		pipe, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		c.stderrPipe = pipe
	} else {
		cmd.Stderr = p.Stderr
	}

	pData, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.stf+".process", pData, 0600); err != nil {
		return err
	}

	c.cmd = cmd

	slog.Info("starting child", "cmd", cmd.Path, "args", cmd.Args)
	return cmd.Start()
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

func (c *Container) Wait() error {
	return c.cmd.Wait()
}

func child() {
	if len(os.Args) < 3 {
		os.Exit(1)
	}
	stf := os.Args[2]
	pf := stf + ".process"
	lfPath := stf + ".log"

	lf, err := os.Create(lfPath)
	if err != nil {
		os.Exit(2)
	}
	defer lf.Close()

	loggr := slog.New(slog.NewTextHandler(lf, nil))
	slog.SetDefault(loggr)

	slog.Info("child started", "stf", stf)

	cfgData, err := os.ReadFile(stf)
	if err != nil {
		slog.Error("read config file:", "error", err)
		os.Exit(1)
	}

	cfg := &Config{}
	if err := json.Unmarshal(cfgData, cfg); err != nil {
		slog.Error("unmarshal config:", "error", err)
		os.Exit(1)
	}

	pfData, err := os.ReadFile(pf)
	if err != nil {
		slog.Error("read process file:", "error", err)
		os.Exit(1)
	}

	p := &Process{}
	if err := json.Unmarshal(pfData, p); err != nil {
		slog.Error("unmarshal process:", "error", err)
		os.Exit(1)
	}

	// Make mount namespace private to prevent propagation leaks
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		slog.Error("mount private:", "error", err)
		os.Exit(1)
	}

	// Execute user-specified mounts
	for _, m := range cfg.Mounts {
		if err := syscall.Mount(m.Source, m.Target, m.Type, m.Flags, m.Data); err != nil {
			slog.Error("mount:", "error", err, "source", m.Source, "target", m.Target, "type", m.Type, "flags", m.Flags, "data", m.Data)
			os.Exit(1)
		}
	}

	if cfg.Hostname != "" {
		if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
			slog.Error("sethostname:", "error", err)
			os.Exit(1)
		}
	}

	// Setup root filesystem
	if cfg.Root != "" {
		if cfg.UsePivotRoot {
			if err := pivotRoot(cfg.Root); err != nil {
				slog.Error("pivot_root:", "error", err)
				os.Exit(1)
			}
		} else {
			// Fallback to chroot
			if err := syscall.Chroot(cfg.Root); err != nil {
				slog.Error("chroot:", "error", err)
				os.Exit(1)
			}
			if err := syscall.Chdir("/"); err != nil {
				slog.Error("chdir:", "error", err)
				os.Exit(1)
			}
		}
	}

	// Setup /dev with minimal devices
	if cfg.SetupDev {
		if err := setupDev(cfg.Devices); err != nil {
			slog.Error("setup dev:", "error", err)
			os.Exit(1)
		}
	}

	if p.WorkDir != "" {
		if err := syscall.Chdir(p.WorkDir); err != nil {
			slog.Error("chdir:", "error", err)
			os.Exit(1)
		}
	}

	// Apply capabilities first (before seccomp, as seccomp may block cap changes)
	if cfg.Capabilities != nil {
		if err := applyCapabilities(cfg.Capabilities); err != nil {
			slog.Error("apply capabilities:", "error", err)
			os.Exit(1)
		}
	}

	// Set no_new_privs if not using seccomp (seccomp library sets it automatically)
	if cfg.NoNewPrivileges && cfg.Seccomp == nil {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			slog.Error("set no_new_privs:", "error", err)
			os.Exit(1)
		}
	}

	// Apply seccomp filter (sets NO_NEW_PRIVS automatically)
	if cfg.Seccomp != nil {
		if err := applySeccomp(cfg.Seccomp); err != nil {
			slog.Error("apply seccomp:", "error", err)
			os.Exit(1)
		}
	}

	env := []string{}
	if p.InheritEnv {
		env = os.Environ()
	}
	if len(p.Env) > 0 {
		env = append(env, p.Env...)
	}

	if err := syscall.Exec(p.Cmd, append([]string{p.Cmd}, p.Args...), env); err != nil {
		slog.Error("exec:", "error", err)
		os.Exit(1)
	}
}

// pivotRoot changes the root filesystem using pivot_root syscall
// This is more secure than chroot as it properly isolates the filesystem
func pivotRoot(newRoot string) error {
	// pivot_root requires the new root to be a mount point
	// Bind mount the new root to itself to ensure it's a mount point
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}

	// Create directory for old root
	oldRoot := filepath.Join(newRoot, ".pivot_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return err
	}

	// Perform the pivot_root
	if err := unix.PivotRoot(newRoot, oldRoot); err != nil {
		return err
	}

	// Change to new root
	if err := unix.Chdir("/"); err != nil {
		return err
	}

	// Unmount old root
	oldRoot = "/.pivot_root"
	if err := unix.Unmount(oldRoot, unix.MNT_DETACH); err != nil {
		return err
	}

	// Remove old root mount point
	return os.RemoveAll(oldRoot)
}

// setupDev creates a minimal /dev filesystem
func setupDev(devices []Device) error {
	// Mount tmpfs on /dev
	if err := unix.Mount("tmpfs", "/dev", "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "mode=755,size=65536k"); err != nil {
		return err
	}

	// Create pts directory for pseudo-terminals
	if err := os.MkdirAll("/dev/pts", 0755); err != nil {
		return err
	}

	// Create shm directory for shared memory
	if err := os.MkdirAll("/dev/shm", 1777); err != nil {
		return err
	}

	// Create device nodes
	if devices == nil {
		devices = DefaultDevices()
	}
	if err := createDevices(devices); err != nil {
		return err
	}

	// Create standard symlinks
	return createDevSymlinks()
}
