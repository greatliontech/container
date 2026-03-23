package container

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// State represents the container's current state
type State string

const (
	StateCreated State = "created"
	StateRunning State = "running"
	StateStopped State = "stopped"
)

// ContainerState holds the complete state of a container
type ContainerState struct {
	ID          string            `json:"id"`
	State       State             `json:"state"`
	Pid         int               `json:"pid"`
	ExitCode    int               `json:"exit_code"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   time.Time         `json:"started_at,omitempty"`
	StoppedAt   time.Time         `json:"stopped_at,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// HookType defines when a hook should be executed
type HookType string

const (
	HookPrestart        HookType = "prestart"
	HookCreateRuntime   HookType = "createRuntime"
	HookCreateContainer HookType = "createContainer"
	HookStartContainer  HookType = "startContainer"
	HookPoststart       HookType = "poststart"
	HookPoststop        HookType = "poststop"
)

// Hook defines a lifecycle hook command
type Hook struct {
	// Path is the command to execute
	Path string `json:"path"`
	// Args are the command arguments
	Args []string `json:"args,omitempty"`
	// Env are environment variables
	Env []string `json:"env,omitempty"`
	// Timeout is the maximum time to wait for the hook
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Hooks defines all lifecycle hooks
type Hooks struct {
	Prestart        []Hook `json:"prestart,omitempty"`
	CreateRuntime   []Hook `json:"createRuntime,omitempty"`
	CreateContainer []Hook `json:"createContainer,omitempty"`
	StartContainer  []Hook `json:"startContainer,omitempty"`
	Poststart       []Hook `json:"poststart,omitempty"`
	Poststop        []Hook `json:"poststop,omitempty"`
}

// runHook executes a single hook
func runHook(hook Hook, state *ContainerState) error {
	cmd := exec.Command(hook.Path, hook.Args...)
	cmd.Env = hook.Env

	// Pass container state as JSON on stdin.
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal hook state: %w", err)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := stdin.Write(stateJSON); err != nil {
		stdin.Close()
		_ = cmd.Wait() // reap process; error is irrelevant since write already failed
		return fmt.Errorf("write hook state: %w", err)
	}
	stdin.Close()

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	timeout := hook.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		cmd.Process.Kill()
		return fmt.Errorf("hook timed out after %v", timeout)
	}
}

// RunHooks executes all hooks of the specified type
func RunHooks(hooks *Hooks, hookType HookType, state *ContainerState) error {
	if hooks == nil {
		return nil
	}

	var hookList []Hook
	switch hookType {
	case HookPrestart:
		hookList = hooks.Prestart
	case HookCreateRuntime:
		hookList = hooks.CreateRuntime
	case HookCreateContainer:
		hookList = hooks.CreateContainer
	case HookStartContainer:
		hookList = hooks.StartContainer
	case HookPoststart:
		hookList = hooks.Poststart
	case HookPoststop:
		hookList = hooks.Poststop
	}

	for _, hook := range hookList {
		if err := runHook(hook, state); err != nil {
			return fmt.Errorf("hook %s failed: %w", hook.Path, err)
		}
	}
	return nil
}

// SignalConfig configures signal handling
type SignalConfig struct {
	// StopSignal is the signal to send for graceful stop (default SIGTERM)
	StopSignal syscall.Signal
	// StopTimeout is how long to wait before sending SIGKILL
	StopTimeout time.Duration
	// ForwardSignals lists signals to forward to the container
	ForwardSignals []syscall.Signal
}

// DefaultSignalConfig returns the default signal configuration
func DefaultSignalConfig() SignalConfig {
	return SignalConfig{
		StopSignal:  syscall.SIGTERM,
		StopTimeout: 10 * time.Second,
		ForwardSignals: []syscall.Signal{
			syscall.SIGTERM,
			syscall.SIGINT,
			syscall.SIGHUP,
			syscall.SIGUSR1,
			syscall.SIGUSR2,
		},
	}
}

// Stop sends stop signal and waits, then kills if necessary
func (c *Container) Stop(config SignalConfig) error {
	if c.containerPid == 0 {
		return nil
	}

	if err := syscall.Kill(c.containerPid, config.StopSignal); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(config.StopTimeout):
		return syscall.Kill(c.containerPid, syscall.SIGKILL)
	}
}

// Signal sends a signal to the container process
func (c *Container) Signal(sig syscall.Signal) error {
	if c.containerPid == 0 {
		return fmt.Errorf("container not running")
	}
	return syscall.Kill(c.containerPid, sig)
}

// State returns the current container state
func (c *Container) State() State {
	if c.cmd == nil {
		return StateCreated
	}
	if c.cmd.ProcessState == nil {
		return StateRunning
	}
	return StateStopped
}

// Pid returns the container's main process ID
func (c *Container) Pid() int {
	return c.containerPid
}

// ExitCode returns the container's exit code (0 if still running or not yet waited)
func (c *Container) ExitCode() int {
	if !c.exited {
		return 0
	}
	return c.exitCode
}
