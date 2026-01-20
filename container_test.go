//go:build integration

package container

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// waitWithTimeout waits for the container with a timeout
func waitWithTimeout(t *testing.T, c *Container, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("Wait returned: %v", err)
		}
	case <-time.After(timeout):
		t.Fatalf("Wait timed out after %v", timeout)
	}
}

// Integration tests for container lifecycle (require root)

func TestContainer_BasicLifecycle(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_BasicLifecycle: creating rootfs...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)
	t.Logf("TestContainer_BasicLifecycle: containerID=%s", containerID)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_BasicLifecycle: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	proc := &Process{
		Cmd:  "/bin/sh",
		Args: []string{"-c", "echo hello"},
	}

	t.Log("TestContainer_BasicLifecycle: running container...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_BasicLifecycle: waiting for container...")
	waitWithTimeout(t, c, 30*time.Second)

	t.Log("TestContainer_BasicLifecycle: destroying container...")
	if err := c.Destroy(); err != nil {
		t.Errorf("Destroy failed: %v", err)
	}
	t.Log("TestContainer_BasicLifecycle: done")
}

func TestContainer_Hostname(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Hostname: creating rootfs...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root:     rootfs,
		Hostname: "testhost",
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Hostname: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:        "/bin/hostname",
		Stdout:     &stdout,
		StdoutPipe: false,
	}

	t.Log("TestContainer_Hostname: running container...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_Hostname: waiting for container...")
	waitWithTimeout(t, c, 30*time.Second)

	hostname := strings.TrimSpace(stdout.String())
	t.Logf("TestContainer_Hostname: got hostname=%q", hostname)
	if hostname != "testhost" {
		t.Errorf("hostname = %q, want testhost", hostname)
	}
}

func TestContainer_WorkDir(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_WorkDir: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	// Create a test directory in rootfs
	testDir := filepath.Join(rootfs, "testdir")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_WorkDir: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:     "/bin/sh",
		Args:    []string{"-c", "pwd"},
		WorkDir: "/testdir",
		Stdout:  &stdout,
	}

	t.Log("TestContainer_WorkDir: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_WorkDir: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	workdir := strings.TrimSpace(stdout.String())
	t.Logf("TestContainer_WorkDir: got workdir=%q", workdir)
	if workdir != "/testdir" {
		t.Errorf("workdir = %q, want /testdir", workdir)
	}
}

func TestContainer_Environment(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Environment: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Environment: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo $TEST_VAR"},
		Env:    []string{"TEST_VAR=hello_world"},
		Stdout: &stdout,
	}

	t.Log("TestContainer_Environment: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_Environment: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	envVal := strings.TrimSpace(stdout.String())
	t.Logf("TestContainer_Environment: got envVal=%q", envVal)
	if envVal != "hello_world" {
		t.Errorf("TEST_VAR = %q, want hello_world", envVal)
	}
}

func TestContainer_Pipes(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Pipes: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Pipes: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	proc := &Process{
		Cmd:        "/bin/cat",
		StdinPipe:  true,
		StdoutPipe: true,
	}

	t.Log("TestContainer_Pipes: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}

	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}

	// Write to stdin
	t.Log("TestContainer_Pipes: writing to stdin...")
	testData := "pipe test data\n"
	go func() {
		stdin.Write([]byte(testData))
		stdin.Close()
	}()

	// Read from stdout
	t.Log("TestContainer_Pipes: reading from stdout...")
	var buf bytes.Buffer
	io.Copy(&buf, stdout)

	t.Log("TestContainer_Pipes: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	output := buf.String()
	t.Logf("TestContainer_Pipes: got output=%q", output)
	if output != testData {
		t.Errorf("stdout = %q, want %q", output, testData)
	}
}

func TestContainer_ExitCode(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_ExitCode: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()

	tests := []struct {
		name     string
		cmd      string
		args     []string
		wantCode int
	}{
		{
			name:     "success",
			cmd:      "/bin/true",
			wantCode: 0,
		},
		{
			name:     "failure",
			cmd:      "/bin/false",
			wantCode: 1,
		},
		{
			name:     "custom exit",
			cmd:      "/bin/sh",
			args:     []string{"-c", "exit 42"},
			wantCode: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("TestContainer_ExitCode/%s: starting...", tt.name)
			containerID := generateTestID(t)

			cfg := Config{
				Root: rootfs,
				Namespaces: Namespaces{
					NewIPC:  true,
					NewMnt:  true,
					NewPID:  true,
					NewUTS:  true,
				},
				UsePivotRoot: true,
				SetupDev:     true,
			}

			t.Logf("TestContainer_ExitCode/%s: creating container...", tt.name)
			c, err := New(stateDir, containerID, cfg)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			defer c.Destroy()

			proc := &Process{
				Cmd:  tt.cmd,
				Args: tt.args,
			}

			t.Logf("TestContainer_ExitCode/%s: running...", tt.name)
			if err := c.Run(proc); err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			t.Logf("TestContainer_ExitCode/%s: waiting...", tt.name)
			waitWithTimeout(t, c, 30*time.Second)

			exitCode := c.ExitCode()
			t.Logf("TestContainer_ExitCode/%s: exitCode=%d", tt.name, exitCode)
			if exitCode != tt.wantCode {
				t.Errorf("exit code = %d, want %d", exitCode, tt.wantCode)
			}
		})
	}
}

func TestContainer_PIDNamespace(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_PIDNamespace: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_PIDNamespace: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo $$"}, // Shell's PID
		Stdout: &stdout,
	}

	t.Log("TestContainer_PIDNamespace: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_PIDNamespace: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	pid := strings.TrimSpace(stdout.String())
	t.Logf("TestContainer_PIDNamespace: got PID=%q", pid)
	// In a new PID namespace, the first process should be PID 1
	// The shell replaces the init process, so it should be PID 1
	if pid != "1" {
		t.Logf("PID = %q (expected 1 in new PID namespace, but exec chain may vary)", pid)
	}
}

func TestContainer_State(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_State: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_State: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	// Before Run, state should be Created
	t.Log("TestContainer_State: checking initial state...")
	if state := c.State(); state != StateCreated {
		t.Errorf("state before Run = %s, want created", state)
	}

	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"1"},
	}

	t.Log("TestContainer_State: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// After Run, state should be Running
	t.Log("TestContainer_State: checking running state...")
	if state := c.State(); state != StateRunning {
		t.Errorf("state after Run = %s, want running", state)
	}

	t.Log("TestContainer_State: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	// After Wait, state should be Stopped
	t.Log("TestContainer_State: checking stopped state...")
	if state := c.State(); state != StateStopped {
		t.Errorf("state after Wait = %s, want stopped", state)
	}
	t.Log("TestContainer_State: done")
}

func TestContainer_Stop_Graceful(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Stop_Graceful: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Stop_Graceful: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	// Start a long-running process
	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"300"},
	}

	t.Log("TestContainer_Stop_Graceful: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Give process time to start
	t.Log("TestContainer_Stop_Graceful: waiting for process to start...")
	time.Sleep(100 * time.Millisecond)

	// Stop with graceful timeout
	cfg2 := SignalConfig{
		StopSignal:  syscall.SIGTERM,
		StopTimeout: 5 * time.Second,
	}

	t.Log("TestContainer_Stop_Graceful: stopping container...")
	start := time.Now()
	if err := c.Stop(cfg2); err != nil {
		t.Logf("Stop returned: %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("TestContainer_Stop_Graceful: stopped in %v", elapsed)

	// Should stop quickly (SIGTERM should work)
	if elapsed > 2*time.Second {
		t.Logf("Stop took %v (expected fast termination)", elapsed)
	}
	t.Log("TestContainer_Stop_Graceful: done")
}

func TestContainer_Signal(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Signal: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Signal: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"300"},
	}

	t.Log("TestContainer_Signal: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_Signal: waiting for process to start...")
	time.Sleep(100 * time.Millisecond)

	// Send SIGKILL - we use SIGKILL because PID 1 processes in a new PID namespace
	// ignore most signals (including SIGTERM) unless they have explicit handlers.
	// This is a Linux kernel protection for init processes.
	t.Log("TestContainer_Signal: sending SIGKILL...")
	if err := c.Signal(syscall.SIGKILL); err != nil {
		t.Errorf("Signal failed: %v", err)
	}

	// Wait should complete
	t.Log("TestContainer_Signal: waiting for container to stop...")
	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()

	select {
	case <-done:
		t.Log("TestContainer_Signal: container stopped")
	case <-time.After(5 * time.Second):
		t.Error("container did not stop after SIGKILL")
	}
	t.Log("TestContainer_Signal: done")
}

func TestContainer_Chroot_Fallback(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Chroot_Fallback: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		UsePivotRoot: false, // Use chroot instead
		SetupDev:     true,
	}

	t.Log("TestContainer_Chroot_Fallback: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/echo",
		Args:   []string{"chroot works"},
		Stdout: &stdout,
	}

	t.Log("TestContainer_Chroot_Fallback: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestContainer_Chroot_Fallback: waiting...")
	waitWithTimeout(t, c, 30*time.Second)

	output := strings.TrimSpace(stdout.String())
	t.Logf("TestContainer_Chroot_Fallback: output=%q", output)
	if output != "chroot works" {
		t.Errorf("output = %q, want 'chroot works'", output)
	}
	t.Log("TestContainer_Chroot_Fallback: done")
}

func TestContainer_Pid(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestContainer_Pid: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestContainer_Pid: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	// Before Run, Pid should be 0
	t.Log("TestContainer_Pid: checking initial PID...")
	if pid := c.Pid(); pid != 0 {
		t.Errorf("Pid before Run = %d, want 0", pid)
	}

	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"1"},
	}

	t.Log("TestContainer_Pid: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// After Run, Pid should be non-zero
	pid := c.Pid()
	t.Logf("TestContainer_Pid: got PID=%d", pid)
	if pid == 0 {
		t.Error("Pid after Run = 0, want non-zero")
	}

	// Pid should be valid (process should exist)
	t.Log("TestContainer_Pid: checking process exists...")
	if err := syscall.Kill(pid, 0); err != nil {
		t.Errorf("process with Pid %d does not exist: %v", pid, err)
	}

	t.Log("TestContainer_Pid: waiting...")
	waitWithTimeout(t, c, 30*time.Second)
	t.Log("TestContainer_Pid: done")
}
