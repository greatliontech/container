package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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
	ID        string    `json:"id"`
	State     State     `json:"state"`
	Pid       int       `json:"pid"`
	ExitCode  int       `json:"exit_code"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt time.Time `json:"started_at,omitempty"`
	StoppedAt time.Time `json:"stopped_at,omitempty"`
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

	// Pass container state as JSON on stdin
	stateJSON, _ := json.Marshal(state)
	cmd.Stdin = nil // We'll write to stdin pipe

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// Write state to stdin
	stdin.Write(stateJSON)
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

// SignalForwarder forwards signals to a process
type SignalForwarder struct {
	pid     int
	signals []syscall.Signal
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewSignalForwarder creates a new signal forwarder
func NewSignalForwarder(pid int, signals []syscall.Signal) *SignalForwarder {
	return &SignalForwarder{
		pid:     pid,
		signals: signals,
		done:    make(chan struct{}),
	}
}

// Start begins forwarding signals
func (sf *SignalForwarder) Start() {
	// Note: Full signal forwarding requires os/signal.Notify
	// This is a simplified version - in production you'd use
	// signal.Notify to catch signals and forward them
	sf.wg.Add(1)
	go func() {
		defer sf.wg.Done()
		<-sf.done
	}()
}

// Stop stops forwarding signals
func (sf *SignalForwarder) Stop() {
	close(sf.done)
	sf.wg.Wait()
}

// ForwardSignal sends a signal to the process
func (sf *SignalForwarder) ForwardSignal(sig syscall.Signal) error {
	return syscall.Kill(sf.pid, sig)
}

// StateManager manages container state persistence
type StateManager struct {
	stateDir string
}

// NewStateManager creates a new state manager
func NewStateManager(stateDir string) *StateManager {
	return &StateManager{stateDir: stateDir}
}

// SaveState saves container state to disk
func (sm *StateManager) SaveState(state *ContainerState) error {
	if err := os.MkdirAll(sm.stateDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(sm.stateDir, state.ID+".state"), data, 0600)
}

// LoadState loads container state from disk
func (sm *StateManager) LoadState(id string) (*ContainerState, error) {
	data, err := os.ReadFile(filepath.Join(sm.stateDir, id+".state"))
	if err != nil {
		return nil, err
	}

	state := &ContainerState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, err
	}

	return state, nil
}

// DeleteState removes container state from disk
func (sm *StateManager) DeleteState(id string) error {
	return os.Remove(filepath.Join(sm.stateDir, id+".state"))
}

// ListStates returns all container states
func (sm *StateManager) ListStates() ([]*ContainerState, error) {
	entries, err := os.ReadDir(sm.stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var states []*ContainerState
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".state" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-6] // Remove .state suffix
		state, err := sm.LoadState(id)
		if err != nil {
			continue
		}
		states = append(states, state)
	}

	return states, nil
}

// Stop sends stop signal and waits, then kills if necessary
func (c *Container) Stop(config SignalConfig) error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}

	// Send stop signal
	if err := c.cmd.Process.Signal(config.StopSignal); err != nil {
		return err
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- c.cmd.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(config.StopTimeout):
		// Force kill
		return c.cmd.Process.Kill()
	}
}

// Signal sends a signal to the container process
func (c *Container) Signal(sig syscall.Signal) error {
	if c.cmd == nil || c.cmd.Process == nil {
		return fmt.Errorf("container not running")
	}
	return c.cmd.Process.Signal(sig)
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
	if c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// ExitCode returns the container's exit code (0 if still running)
func (c *Container) ExitCode() int {
	if c.cmd == nil || c.cmd.ProcessState == nil {
		return 0
	}
	return c.cmd.ProcessState.ExitCode()
}
