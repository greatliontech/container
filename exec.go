package container

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/vishvananda/netns"
)

// ExecConfig configures how to exec into a running container.
type ExecConfig struct {
	Cmd     string
	Args    []string
	Env     []string
	WorkDir string
	Root    string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// Exec executes a command in the container's namespaces.
func (c *Container) Exec(config ExecConfig) (*exec.Cmd, error) {
	if c.containerPid == 0 {
		return nil, fmt.Errorf("container not running")
	}

	if config.Root == "" && !c.cfg.UsePivotRoot {
		config.Root = c.cfg.Root
	}

	return ExecWithNsenter(c.containerPid, config)
}

// execReexec builds a re-exec command that joins the target's namespaces.
// With CGO, the C constructor handles setns + exec.
// Without CGO, the Go join handler does setns for safe namespaces.
func execReexec(pid int, config ExecConfig) (*exec.Cmd, error) {
	args := []string{"__nsenter"}

	if config.Root != "" {
		args = append(args, fmt.Sprintf("--root=%s", config.Root))
	}
	if config.WorkDir != "" {
		args = append(args, fmt.Sprintf("--wd=%s", config.WorkDir))
	}

	args = append(args, "--", config.Cmd)
	args = append(args, config.Args...)

	cmd := exec.Command("/proc/self/exe", args...)

	env := config.Env
	if len(env) == 0 {
		env = os.Environ()
	}
	env = append(env,
		"_CONTAINER_MODE=join",
		fmt.Sprintf("_CONTAINER_PID=%d", pid),
	)
	cmd.Env = env

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

// SelfContainerize re-execs the current process inside a container.
// The original process waits for the containerized instance and returns its exit code.
// The containerized instance's main() should check InContainer() to detect it's inside.
func SelfContainerize(cfg Config) (int, error) {
	c := New("self", cfg)

	if err := c.RunSelf(os.Args[1:]...); err != nil {
		return 1, err
	}

	err := c.Wait()
	c.Destroy()
	return c.ExitCode(), err
}

// JoinNetworkNamespace joins the network namespace of another process.
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

// GetNamespacePaths returns paths to all namespace files for a process.
func GetNamespacePaths(pid int) map[string]string {
	nsTypes := []string{"user", "mnt", "uts", "ipc", "net", "pid", "cgroup"}
	result := make(map[string]string)

	for _, ns := range nsTypes {
		path := fmt.Sprintf("/proc/%d/ns/%s", pid, ns)
		if _, err := os.Stat(path); err == nil {
			result[ns] = path
		}
	}

	return result
}
