package container

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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

	if cfg.Root != "" {
		if err := syscall.Chroot(cfg.Root); err != nil {
			slog.Error("chroot:", "error", err)
			os.Exit(1)
		}
		if err := syscall.Chdir("/"); err != nil {
			slog.Error("chdir:", "error", err)
			os.Exit(1)
		}
	}

	if p.WorkDir != "" {
		if err := syscall.Chdir(p.WorkDir); err != nil {
			slog.Error("chdir:", "error", err)
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
