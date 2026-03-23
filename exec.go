package container

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

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

// ExecWithNsenter enters all namespaces of the target process and executes a command.
// When built with CGO, this uses the built-in C constructor (no external dependencies).
// Without CGO, falls back to the external nsenter(1) utility.
func ExecWithNsenter(pid int, config ExecConfig) (*exec.Cmd, error) {
	if builtinNsenter {
		return execBuiltin(pid, config)
	}
	return execExternal(pid, config)
}

// execBuiltin uses /proc/self/exe re-exec with the C constructor for namespace joining.
func execBuiltin(pid int, config ExecConfig) (*exec.Cmd, error) {
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
	// Add mode and target PID for the C constructor.
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

// execExternal uses the external nsenter(1) utility (fallback when CGO is disabled).
func execExternal(pid int, config ExecConfig) (*exec.Cmd, error) {
	args := []string{
		fmt.Sprintf("--target=%d", pid),
		"--mount",
		"--uts",
		"--ipc",
		"--net",
		"--pid",
	}

	targetUserNs, err1 := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", pid))
	selfUserNs, err2 := os.Readlink("/proc/self/ns/user")
	if err1 == nil && err2 == nil && targetUserNs != selfUserNs {
		args = append(args, "--user")
	}

	if config.Root != "" {
		args = append(args, fmt.Sprintf("--root=%s", config.Root))
	}
	if config.WorkDir != "" {
		args = append(args, fmt.Sprintf("--wd=%s", config.WorkDir))
	}

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

// SelfContainerize re-execs the current process inside a container.
// The original process waits for the containerized instance and returns its exit code.
// The containerized instance's main() should check InContainer() to detect it's inside.
func SelfContainerize(cfg Config) (int, error) {
	c := New("self", cfg)

	if err := c.RunSelf(os.Args[1:]...); err != nil {
		return 1, err
	}

	err := c.Wait()
	exitCode := 0
	if err != nil {
		exitCode = 1
		// Try to extract exit code from error message.
		if strings.Contains(err.Error(), "exited with status") {
			fmt.Sscanf(err.Error(), "container exited with status %d", &exitCode)
		}
	}

	c.Destroy()
	return exitCode, err
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
