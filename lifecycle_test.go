package container

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// Unit tests for lifecycle (no root required)

func TestContainerState_Transitions(t *testing.T) {
	// Test state constants
	if StateCreated != "created" {
		t.Errorf("StateCreated = %s, want created", StateCreated)
	}
	if StateRunning != "running" {
		t.Errorf("StateRunning = %s, want running", StateRunning)
	}
	if StateStopped != "stopped" {
		t.Errorf("StateStopped = %s, want stopped", StateStopped)
	}
}

func TestDefaultSignalConfig(t *testing.T) {
	cfg := DefaultSignalConfig()

	// Verify stop signal
	if cfg.StopSignal != syscall.SIGTERM {
		t.Errorf("StopSignal = %v, want SIGTERM", cfg.StopSignal)
	}

	// Verify stop timeout
	if cfg.StopTimeout != 10*time.Second {
		t.Errorf("StopTimeout = %v, want 10s", cfg.StopTimeout)
	}

	// Verify forward signals list
	if len(cfg.ForwardSignals) == 0 {
		t.Error("ForwardSignals should not be empty")
	}

	// Check required signals are in the forward list
	requiredSignals := []syscall.Signal{
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGHUP,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	}

	signalSet := make(map[syscall.Signal]bool)
	for _, sig := range cfg.ForwardSignals {
		signalSet[sig] = true
	}

	for _, req := range requiredSignals {
		if !signalSet[req] {
			t.Errorf("ForwardSignals missing %v", req)
		}
	}
}

func TestRunHooks_NilHooks(t *testing.T) {
	state := &ContainerState{
		ID:    "test",
		State: StateRunning,
	}

	// Running hooks with nil hooks should be no-op
	err := RunHooks(nil, HookPrestart, state)
	if err != nil {
		t.Errorf("RunHooks with nil hooks failed: %v", err)
	}
}

func TestRunHooks_EmptyHooks(t *testing.T) {
	hooks := &Hooks{}
	state := &ContainerState{
		ID:    "test",
		State: StateRunning,
	}

	// Running with empty hooks should be no-op
	hookTypes := []HookType{
		HookPrestart,
		HookCreateRuntime,
		HookCreateContainer,
		HookStartContainer,
		HookPoststart,
		HookPoststop,
	}

	for _, ht := range hookTypes {
		err := RunHooks(hooks, ht, state)
		if err != nil {
			t.Errorf("RunHooks(%s) with empty hooks failed: %v", ht, err)
		}
	}
}

func TestHookTypeConstants(t *testing.T) {
	// Verify hook type constants
	if HookPrestart != "prestart" {
		t.Errorf("HookPrestart = %s, want prestart", HookPrestart)
	}
	if HookCreateRuntime != "createRuntime" {
		t.Errorf("HookCreateRuntime = %s, want createRuntime", HookCreateRuntime)
	}
	if HookCreateContainer != "createContainer" {
		t.Errorf("HookCreateContainer = %s, want createContainer", HookCreateContainer)
	}
	if HookStartContainer != "startContainer" {
		t.Errorf("HookStartContainer = %s, want startContainer", HookStartContainer)
	}
	if HookPoststart != "poststart" {
		t.Errorf("HookPoststart = %s, want poststart", HookPoststart)
	}
	if HookPoststop != "poststop" {
		t.Errorf("HookPoststop = %s, want poststop", HookPoststop)
	}
}

func TestHookStruct(t *testing.T) {
	hook := Hook{
		Path:    "/bin/true",
		Args:    []string{"--flag"},
		Env:     []string{"VAR=value"},
		Timeout: 5 * time.Second,
	}

	if hook.Path != "/bin/true" {
		t.Errorf("Path = %s, want /bin/true", hook.Path)
	}
	if len(hook.Args) != 1 || hook.Args[0] != "--flag" {
		t.Errorf("Args = %v, want [--flag]", hook.Args)
	}
	if len(hook.Env) != 1 || hook.Env[0] != "VAR=value" {
		t.Errorf("Env = %v, want [VAR=value]", hook.Env)
	}
	if hook.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", hook.Timeout)
	}
}

func TestHooksStruct(t *testing.T) {
	hooks := Hooks{
		Prestart: []Hook{
			{Path: "/bin/pre1"},
			{Path: "/bin/pre2"},
		},
		Poststart: []Hook{
			{Path: "/bin/post1"},
		},
		Poststop: []Hook{
			{Path: "/bin/stop1"},
		},
	}

	if len(hooks.Prestart) != 2 {
		t.Errorf("Prestart length = %d, want 2", len(hooks.Prestart))
	}
	if len(hooks.Poststart) != 1 {
		t.Errorf("Poststart length = %d, want 1", len(hooks.Poststart))
	}
	if len(hooks.Poststop) != 1 {
		t.Errorf("Poststop length = %d, want 1", len(hooks.Poststop))
	}
}

func TestContainerStateStruct(t *testing.T) {
	now := time.Now()
	state := ContainerState{
		ID:        "container-123",
		State:     StateRunning,
		Pid:       9999,
		ExitCode:  0,
		CreatedAt: now,
		StartedAt: now.Add(time.Second),
	}

	if state.ID != "container-123" {
		t.Errorf("ID = %s, want container-123", state.ID)
	}
	if state.State != StateRunning {
		t.Errorf("State = %s, want running", state.State)
	}
	if state.Pid != 9999 {
		t.Errorf("Pid = %d, want 9999", state.Pid)
	}
	if state.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", state.ExitCode)
	}
}

func TestSignalConfigStruct(t *testing.T) {
	cfg := SignalConfig{
		StopSignal:  syscall.SIGKILL,
		StopTimeout: 30 * time.Second,
		ForwardSignals: []syscall.Signal{
			syscall.SIGTERM,
		},
	}

	if cfg.StopSignal != syscall.SIGKILL {
		t.Errorf("StopSignal = %v, want SIGKILL", cfg.StopSignal)
	}
	if cfg.StopTimeout != 30*time.Second {
		t.Errorf("StopTimeout = %v, want 30s", cfg.StopTimeout)
	}
	if len(cfg.ForwardSignals) != 1 {
		t.Errorf("ForwardSignals length = %d, want 1", len(cfg.ForwardSignals))
	}
}

func TestRunHooks_WithTrueCommand(t *testing.T) {
	// Skip if /bin/true doesn't exist
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}

	hooks := &Hooks{
		Prestart: []Hook{
			{Path: "/bin/true", Timeout: time.Second},
		},
	}
	state := &ContainerState{
		ID:    "test",
		State: StateCreated,
	}

	err := RunHooks(hooks, HookPrestart, state)
	if err != nil {
		t.Errorf("RunHooks with /bin/true failed: %v", err)
	}
}

func TestRunHooks_WithFailingCommand(t *testing.T) {
	// Skip if /bin/false doesn't exist
	if _, err := os.Stat("/bin/false"); err != nil {
		t.Skip("/bin/false not available")
	}

	hooks := &Hooks{
		Prestart: []Hook{
			{Path: "/bin/false", Timeout: time.Second},
		},
	}
	state := &ContainerState{
		ID:    "test",
		State: StateCreated,
	}

	err := RunHooks(hooks, HookPrestart, state)
	if err == nil {
		t.Error("RunHooks with /bin/false should fail")
	}
}

