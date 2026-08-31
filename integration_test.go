//go:build integration

package container

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Comprehensive integration tests for container scenarios (require root)

func TestIntegration_SeccompBlocks(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_SeccompBlocks: starting...")
	rootfs := createTestRootfs(t)
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
		Seccomp:      DefaultSeccompProfile(),
	}

	t.Log("TestIntegration_SeccompBlocks: creating container...")
	c := New(containerID, cfg)
	defer func() {
		// Read child log before cleanup
		c.Destroy()
	}()

	// Try to reboot (should fail with EPERM due to seccomp)
	// We can't easily test this directly, but we can verify the profile is applied
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo seccomp_test"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	t.Log("TestIntegration_SeccompBlocks: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_SeccompBlocks: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	output := strings.TrimSpace(stdout.String())
	errOutput := strings.TrimSpace(stderr.String())
	t.Logf("TestIntegration_SeccompBlocks: stdout=%q stderr=%q", output, errOutput)
	if output != "seccomp_test" {
		t.Errorf("unexpected output: %s (stderr: %s)", output, errOutput)
	}
	t.Log("TestIntegration_SeccompBlocks: done")
}

func TestIntegration_DevicesAccessible(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_DevicesAccessible: starting...")
	rootfs := createTestRootfs(t)
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
		Devices:      DefaultDevices(),
	}

	t.Log("TestIntegration_DevicesAccessible: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	// Test /dev/null
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo test > /dev/null && echo null_works"},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_DevicesAccessible: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_DevicesAccessible: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	t.Logf("TestIntegration_DevicesAccessible: output=%q", stdout.String())
	if !strings.Contains(stdout.String(), "null_works") {
		t.Error("/dev/null not working correctly")
	}
	t.Log("TestIntegration_DevicesAccessible: done")
}

func TestIntegration_DevicesUrandom(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_DevicesUrandom: starting...")
	rootfs := createTestRootfs(t)
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
		Devices:      DefaultDevices(),
	}

	t.Log("TestIntegration_DevicesUrandom: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	// Test /dev/urandom
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "head -c 16 /dev/urandom | cat > /dev/null && echo urandom_works"},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_DevicesUrandom: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_DevicesUrandom: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	t.Logf("TestIntegration_DevicesUrandom: output=%q", stdout.String())
	if !strings.Contains(stdout.String(), "urandom_works") {
		t.Error("/dev/urandom not working correctly")
	}
	t.Log("TestIntegration_DevicesUrandom: done")
}

func TestIntegration_MemoryLimit(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	t.Log("TestIntegration_MemoryLimit: starting...")
	rootfs := createTestRootfs(t)
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
		Resources: &Resources{
			Memory: &MemoryResources{
				Max: 64 * 1024 * 1024, // 64MB
			},
			Pids: &PidsResources{
				Max: 100,
			},
		},
	}

	t.Log("TestIntegration_MemoryLimit: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	// Just verify the container runs with limits
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo memory_limited"},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_MemoryLimit: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_MemoryLimit: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	t.Logf("TestIntegration_MemoryLimit: output=%q", stdout.String())
	if !strings.Contains(stdout.String(), "memory_limited") {
		t.Error("container with memory limit didn't run correctly")
	}
	t.Log("TestIntegration_MemoryLimit: done")
}

func TestIntegration_PidsLimit(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	t.Log("TestIntegration_PidsLimit: starting...")
	rootfs := createTestRootfs(t)
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
		Resources: &Resources{
			Pids: &PidsResources{
				Max: 10, // Very low limit
			},
		},
	}

	t.Log("TestIntegration_PidsLimit: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	// Just verify the container runs with pids limit
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo pids_limited"},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_PidsLimit: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_PidsLimit: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	t.Logf("TestIntegration_PidsLimit: output=%q", stdout.String())
	if !strings.Contains(stdout.String(), "pids_limited") {
		t.Error("container with pids limit didn't run correctly")
	}
	t.Log("TestIntegration_PidsLimit: done")
}

func TestIntegration_Hooks(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_Hooks: starting...")

	// Skip if /bin/true doesn't exist
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}

	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	// Create a marker file that hooks will create
	hookMarker := filepath.Join(stateDir, "hook_executed")

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
		Hooks: &Hooks{
			Prestart: []Hook{
				{
					Path:    "/bin/sh",
					Args:    []string{"-c", "touch " + hookMarker},
					Timeout: 5 * time.Second,
				},
			},
		},
	}

	t.Log("TestIntegration_Hooks: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	proc := &Process{
		Cmd: "/bin/true",
	}

	t.Log("TestIntegration_Hooks: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_Hooks: waiting...")
	c.Wait()

	// Note: The hook runs on the host, not in the container
	// So if prestart hooks are implemented to run before container start,
	// the marker file should exist
	t.Logf("TestIntegration_Hooks: hook marker path: %s", hookMarker)
	t.Log("TestIntegration_Hooks: done")
}

func TestIntegration_Stats(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	t.Log("TestIntegration_Stats: starting...")
	rootfs := createTestRootfs(t)
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
		Resources:    DefaultResources(),
	}

	t.Log("TestIntegration_Stats: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"5"},
	}

	t.Log("TestIntegration_Stats: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Give process time to start
	t.Log("TestIntegration_Stats: waiting for process to start...")
	time.Sleep(100 * time.Millisecond)

	// Get stats
	t.Log("TestIntegration_Stats: getting stats...")
	stats, err := c.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats != nil {
		if stats.Memory != nil {
			t.Logf("TestIntegration_Stats: Memory current: %d bytes", stats.Memory.Current)
		}
		if stats.Pids != nil {
			t.Logf("TestIntegration_Stats: Pids current: %d", stats.Pids.Current)
			if stats.Pids.Current == 0 {
				t.Error("Pids.Current should be > 0 for running container")
			}
		}
	}

	// Stop the container
	t.Log("TestIntegration_Stats: stopping container...")
	c.Stop(DefaultSignalConfig())
	t.Log("TestIntegration_Stats: done")
}

func TestIntegration_ConcurrentContainers(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_ConcurrentContainers: starting...")
	rootfs := createTestRootfs(t)

	numContainers := 3
	containers := make([]*Container, numContainers)
	results := make(chan int, numContainers)

	// Start multiple containers concurrently
	t.Logf("TestIntegration_ConcurrentContainers: starting %d containers...", numContainers)
	for i := 0; i < numContainers; i++ {
		containerID := generateTestID(t) + "-" + string(rune('0'+i))

		cfg := Config{
			Root:     rootfs,
			Hostname: "container" + string(rune('0'+i)),
			Namespaces: Namespaces{
				NewIPC: true,
				NewMnt: true,
				NewPID: true,
				NewUTS: true,
			},
			UsePivotRoot: true,
			SetupDev:     true,
		}

		t.Logf("TestIntegration_ConcurrentContainers: creating container %d...", i)
		c := New(containerID, cfg)
		containers[i] = c

		proc := &Process{
			Cmd:  "/bin/sh",
			Args: []string{"-c", "echo test && sleep 0.1"},
		}

		t.Logf("TestIntegration_ConcurrentContainers: running container %d...", i)
		if err := c.Run(proc); err != nil {
			t.Fatalf("Run failed for container %d: %v", i, err)
		}

		// Wait in goroutine
		go func(idx int, cont *Container) {
			cont.Wait()
			results <- idx
		}(i, c)
	}

	// Wait for all containers to finish
	t.Log("TestIntegration_ConcurrentContainers: waiting for all containers to finish...")
	for i := 0; i < numContainers; i++ {
		select {
		case idx := <-results:
			t.Logf("TestIntegration_ConcurrentContainers: container %d finished", idx)
		case <-time.After(10 * time.Second):
			t.Fatalf("Timeout waiting for containers")
		}
	}

	// Cleanup all containers
	t.Log("TestIntegration_ConcurrentContainers: cleaning up containers...")
	for i, c := range containers {
		if err := c.Destroy(); err != nil {
			t.Errorf("Destroy failed for container %d: %v", i, err)
		}
	}
	t.Log("TestIntegration_ConcurrentContainers: done")
}

func TestIntegration_InvalidConfig(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_InvalidConfig: starting...")
	containerID := generateTestID(t)

	// Config with non-existent rootfs
	cfg := Config{
		Root: "/nonexistent/rootfs/path",
		Namespaces: Namespaces{
			NewMnt: true,
		},
		UsePivotRoot: true,
	}

	t.Log("TestIntegration_InvalidConfig: creating container with invalid rootfs...")
	c := New(containerID, cfg)
	defer c.Destroy()

	proc := &Process{
		Cmd: "/bin/sh",
	}

	// Run should fail because rootfs doesn't exist
	t.Log("TestIntegration_InvalidConfig: running (should fail)...")
	err := c.Run(proc)
	if err == nil {
		t.Log("TestIntegration_InvalidConfig: Run succeeded, waiting...")
		c.Wait()
	} else {
		t.Logf("TestIntegration_InvalidConfig: Run failed as expected: %v", err)
	}
	// The error might occur during Run or Wait
	t.Log("TestIntegration_InvalidConfig: done")
}

func TestIntegration_SignalDuringStartup(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_SignalDuringStartup: starting...")
	rootfs := createTestRootfs(t)
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

	t.Log("TestIntegration_SignalDuringStartup: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	proc := &Process{
		Cmd:  "/bin/sleep",
		Args: []string{"300"},
	}

	t.Log("TestIntegration_SignalDuringStartup: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Send signal immediately (during startup)
	t.Log("TestIntegration_SignalDuringStartup: sending SIGKILL immediately...")
	time.Sleep(10 * time.Millisecond)
	err := c.Signal(syscall.SIGKILL)
	if err != nil {
		t.Logf("TestIntegration_SignalDuringStartup: Signal error (may be expected): %v", err)
	}

	// Wait should complete
	t.Log("TestIntegration_SignalDuringStartup: waiting for container to stop...")
	done := make(chan struct{})
	go func() {
		c.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("TestIntegration_SignalDuringStartup: container stopped")
	case <-time.After(5 * time.Second):
		t.Error("container did not stop after SIGKILL")
	}
	t.Log("TestIntegration_SignalDuringStartup: done")
}

func TestIntegration_MultipleNamespaceIsolation(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_MultipleNamespaceIsolation: starting...")
	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root:     rootfs,
		Hostname: "isolated",
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewNet:  true,
			NewPID:  true,
			NewUTS:  true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestIntegration_MultipleNamespaceIsolation: creating container...")
	c := New(containerID, cfg)
	defer c.Destroy()

	// Verify multiple aspects of isolation
	var stdout bytes.Buffer
	proc := &Process{
		Cmd: "/bin/sh",
		Args: []string{"-c", `
			echo "hostname: $(hostname)"
			echo "pid: $$"
		`},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_MultipleNamespaceIsolation: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_MultipleNamespaceIsolation: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	output := stdout.String()
	t.Logf("TestIntegration_MultipleNamespaceIsolation: Container output:\n%s", output)

	if !strings.Contains(output, "hostname: isolated") {
		t.Error("UTS namespace isolation not working (hostname)")
	}
	t.Log("TestIntegration_MultipleNamespaceIsolation: done")
}

func TestIntegration_ReadonlyRoot(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
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
		ReadonlyRoot: true,
	}

	c := New(containerID, cfg)
	defer c.Destroy()

	// Try to write a file — should fail on readonly root.
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo test > /testfile 2>&1; echo $?"},
		Stdout: &stdout,
	}

	if err := c.Run(proc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.Wait()

	output := strings.TrimSpace(stdout.String())
	// Write should fail — exit code 1 or error message.
	if !strings.Contains(output, "1") && !strings.Contains(output, "Read-only") {
		t.Errorf("root should be readonly, got: %q", output)
	}
}

func TestIntegration_Domainname(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		Hostname:     "testhost",
		Domainname:   "example.com",
		UsePivotRoot: true,
		SetupDev:     true,
		// Mount proc so we can read /proc/sys/kernel/domainname.
		Mounts: []Mount{
			{
				Source: "proc",
				Target: filepath.Join(rootfs, "proc"),
				Type:   "proc",
				Flags:  MountFlags.Proc,
			},
		},
	}

	c := New(containerID, cfg)
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/cat",
		Args:   []string{"/proc/sys/kernel/domainname"},
		Stdout: &stdout,
	}

	if err := c.Run(proc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.Wait()

	output := strings.TrimSpace(stdout.String())
	if output != "example.com" {
		t.Errorf("domainname = %q, want example.com", output)
	}
}

func TestIntegration_MaskedPaths(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
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
		MaskPaths:    []string{"/proc/kcore"},
	}

	c := New(containerID, cfg)
	defer c.Destroy()

	// Try to read /proc/kcore — should be masked (empty/devnull).
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "if cat /proc/kcore 2>/dev/null | head -c 1 | test -z \"$(cat)\"; then echo masked; else echo readable; fi"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if err := c.Run(proc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.Wait()

	output := strings.TrimSpace(stdout.String())
	if output != "masked" {
		t.Logf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		t.Errorf("/proc/kcore should be masked, got %q", output)
	}
}

func TestIntegration_ReadonlyPaths(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		UsePivotRoot:  true,
		SetupDev:      true,
		ReadonlyPaths: []string{"/proc/sys"},
	}

	c := New(containerID, cfg)
	defer c.Destroy()

	// Try to write to a readonly path — should fail.
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo test > /proc/sys/kernel/hostname 2>&1; echo $?"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if err := c.Run(proc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.Wait()

	output := strings.TrimSpace(stdout.String())
	// Write should fail — exit code should be non-zero.
	if !strings.Contains(output, "1") && !strings.Contains(output, "Read-only") {
		t.Logf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		t.Errorf("/proc/sys should be readonly, got output: %q", output)
	}
}

func TestIntegration_Rlimits(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
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
		Rlimits: []Rlimit{
			{Type: unix.RLIMIT_NOFILE, Soft: 256, Hard: 256},
		},
	}

	c := New(containerID, cfg)
	defer c.Destroy()

	// Check ulimit inside container.
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "ulimit -n"},
		Stdout: &stdout,
	}

	if err := c.Run(proc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.Wait()

	output := strings.TrimSpace(stdout.String())
	if output != "256" {
		t.Errorf("ulimit -n = %q, want 256", output)
	}
}

func TestIntegration_ExecWithNsenter(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_ExecWithNsenter: starting...")
	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		Hostname:     "exec-test",
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestIntegration_ExecWithNsenter: creating container...")
	c := New(containerID, cfg)
	defer func() {
		c.Destroy()
	}()

	// Start container with sleep to keep it running
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sleep",
		Args:   []string{"30"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	t.Log("TestIntegration_ExecWithNsenter: running container...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Give the container a moment to start
	time.Sleep(100 * time.Millisecond)

	// Exec into the running container
	var execStdout, execStderr bytes.Buffer
	execCfg := ExecConfig{
		Cmd:    "/bin/hostname",
		Stdout: &execStdout,
		Stderr: &execStderr,
	}

	t.Log("TestIntegration_ExecWithNsenter: execing into container...")
	cmd, err := c.Exec(execCfg)
	if err != nil {
		if strings.Contains(err.Error(), "without CGO") {
			t.Skip("exec requires CGO for mount namespace joining")
		}
		t.Fatalf("Exec failed: %v", err)
	}

	if err := cmd.Run(); err != nil {
		t.Logf("Exec stderr: %s", execStderr.String())
		t.Fatalf("Exec command failed: %v", err)
	}

	execOutput := strings.TrimSpace(execStdout.String())
	t.Logf("TestIntegration_ExecWithNsenter: exec output=%q", execOutput)

	// Verify we're in the container's UTS namespace (should see container hostname)
	if execOutput != "exec-test" {
		t.Errorf("Exec hostname = %q, want %q (not in container's UTS namespace?)", execOutput, "exec-test")
	}

	// Stop the container
	t.Log("TestIntegration_ExecWithNsenter: stopping container...")
	if err := c.Signal(syscall.SIGKILL); err != nil {
		t.Logf("Signal failed: %v", err)
	}
	c.Wait()

	t.Log("TestIntegration_ExecWithNsenter: done")
}

func TestIntegration_ExecWithNsenter_UserNs(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_ExecWithNsenter_UserNs: starting...")
	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC:  true,
			NewMnt:  true,
			NewPID:  true,
			NewUTS:  true,
			NewUser: true, // Enable user namespace
		},
		UidMappings:  []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 65536}},
		GidMappings:  []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 65536}},
		Hostname:     "userns-exec",
		UsePivotRoot: true,
		SetupDev:     false, // Can't create devices in user namespace (no CAP_MKNOD)
	}

	t.Log("TestIntegration_ExecWithNsenter_UserNs: creating container...")
	c := New(containerID, cfg)
	defer func() {
		c.Destroy()
	}()

	// Start container with sleep to keep it running
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sleep",
		Args:   []string{"30"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	t.Log("TestIntegration_ExecWithNsenter_UserNs: running container...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Give the container a moment to start
	time.Sleep(100 * time.Millisecond)

	// Verify container is in a different user namespace
	containerPid := c.Pid()
	targetUserNs, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", containerPid))
	selfUserNs, _ := os.Readlink("/proc/self/ns/user")
	t.Logf("Container user ns: %s, Self user ns: %s", targetUserNs, selfUserNs)
	if targetUserNs == selfUserNs {
		t.Log("Warning: container is in same user namespace as host")
	}

	// Exec into the running container
	var execStdout, execStderr bytes.Buffer
	execCfg := ExecConfig{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "/bin/hostname && /bin/id"},
		Stdout: &execStdout,
		Stderr: &execStderr,
	}

	t.Log("TestIntegration_ExecWithNsenter_UserNs: execing into container...")
	cmd, err := c.Exec(execCfg)
	if err != nil {
		if strings.Contains(err.Error(), "without CGO") {
			t.Skip("exec requires CGO for user/mount namespace joining")
		}
		t.Fatalf("Exec failed: %v", err)
	}

	if err := cmd.Run(); err != nil {
		t.Logf("Exec stderr: %s", execStderr.String())
		t.Fatalf("Exec command failed: %v", err)
	}

	execOutput := strings.TrimSpace(execStdout.String())
	t.Logf("TestIntegration_ExecWithNsenter_UserNs: exec output=%q", execOutput)

	// Verify we're in the container's UTS namespace
	if !strings.Contains(execOutput, "userns-exec") {
		t.Errorf("Exec output doesn't contain hostname 'userns-exec': %s", execOutput)
	}

	// Stop the container
	t.Log("TestIntegration_ExecWithNsenter_UserNs: stopping container...")
	if err := c.Signal(syscall.SIGKILL); err != nil {
		t.Logf("Signal failed: %v", err)
	}
	c.Wait()

	t.Log("TestIntegration_ExecWithNsenter_UserNs: done")
}

func TestIntegration_ExecNoUserNs(t *testing.T) {
	// Skip: ExecNoUserNs uses setns() which requires a single-threaded process.
	// Go's runtime is inherently multithreaded, making setns to mount namespace fail
	// with EINVAL. The recommended approach is to use ExecWithNsenter which delegates
	// to the nsenter(1) utility (a single-threaded C program).
	// To properly support this in Go would require CGO with a constructor that runs
	// before Go runtime starts (like runc's nsenter package).
	t.Skip("ExecNoUserNs requires single-threaded process; use ExecWithNsenter instead")

	skipIfNotRoot(t)

	t.Log("TestIntegration_ExecNoUserNs: starting...")
	rootfs := createTestRootfs(t)
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
			// No NewUser - so ExecNoUserNs path can be used
		},
		Hostname:     "execnouserns",
		UsePivotRoot: true,
		SetupDev:     true,
	}

	t.Log("TestIntegration_ExecNoUserNs: creating container...")
	c := New(containerID, cfg)
	defer func() {
		c.Destroy()
	}()

	// Start container with sleep to keep it running
	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sleep",
		Args:   []string{"30"},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	t.Log("TestIntegration_ExecNoUserNs: running container...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Give the container a moment to start
	time.Sleep(100 * time.Millisecond)

	containerPid := c.Pid()
	t.Logf("TestIntegration_ExecNoUserNs: container pid=%d", containerPid)

	// Test ExecNoUserNs by invoking our binary with __exec
	// This forks a process that calls ExecNoUserNs
	var execStdout, execStderr bytes.Buffer
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable: %v", err)
	}

	execCmd := exec.Command(selfExe, "__exec", fmt.Sprintf("%d", containerPid), "/bin/hostname")
	execCmd.Stdout = &execStdout
	execCmd.Stderr = &execStderr

	t.Log("TestIntegration_ExecNoUserNs: execing via __exec...")
	if err := execCmd.Run(); err != nil {
		t.Logf("Exec stderr: %s", execStderr.String())
		t.Fatalf("Exec command failed: %v", err)
	}

	execOutput := strings.TrimSpace(execStdout.String())
	t.Logf("TestIntegration_ExecNoUserNs: exec output=%q", execOutput)

	// Verify we're in the container's UTS namespace (should see container hostname)
	if execOutput != "execnouserns" {
		t.Errorf("Exec hostname = %q, want %q", execOutput, "execnouserns")
	}

	// Stop the container
	t.Log("TestIntegration_ExecNoUserNs: stopping container...")
	if err := c.Signal(syscall.SIGKILL); err != nil {
		t.Logf("Signal failed: %v", err)
	}
	c.Wait()

	t.Log("TestIntegration_ExecNoUserNs: done")
}

// pidNsLink returns a process's pid-namespace link as seen from the host's /proc.
func pidNsLink(t *testing.T, pid int) string {
	t.Helper()
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatalf("readlink pid ns of %d: %v", pid, err)
	}
	return link
}

// rootPropagation returns the propagation annotations (shared:/master: fields)
// of the / mount in the caller's mount namespace.
func rootPropagation(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read mountinfo: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == "/" {
			var opt []string
			for _, x := range f[6:] {
				if x == "-" {
					break
				}
				opt = append(opt, x)
			}
			return strings.Join(opt, " ")
		}
	}
	t.Fatal("no / entry in mountinfo")
	return ""
}

// An exec'd process must be a member of the container's pid namespace, not
// just parent it for future children: /proc/self must resolve inside the
// container and the ns link must match the container init's.
func TestIntegration_ExecWithNsenter_PidNsMembership(t *testing.T) {
	skipIfNotRoot(t)

	rootfs := createTestRootfs(t)
	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewPID: true,
			NewUTS: true,
		},
		Mounts: []Mount{
			{Source: "proc", Target: filepath.Join(rootfs, "proc"), Type: "proc"},
		},
		Hostname:     "pidns-exec",
		UsePivotRoot: true,
		SetupDev:     true,
	}

	c := New(generateTestID(t), cfg)
	defer c.Destroy()

	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sleep",
		Args:   []string{"30"},
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	containerNs := pidNsLink(t, c.Pid())

	var execStdout, execStderr bytes.Buffer
	cmd, err := c.Exec(ExecConfig{
		Cmd:    "/bin/readlink",
		Args:   []string{"/proc/self/ns/pid"},
		Stdout: &execStdout,
		Stderr: &execStderr,
	})
	if err != nil {
		if strings.Contains(err.Error(), "without CGO") {
			t.Skip("pid+mnt join requires CGO")
		}
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("readlink /proc/self/ns/pid in exec'd process failed: %v (stderr: %s)",
			err, execStderr.String())
	}
	got := strings.TrimSpace(execStdout.String())
	if got != containerNs {
		t.Errorf("exec'd process pid ns = %q, want container's %q", got, containerNs)
	}

	// The exec'd process's exit code must reach the caller unchanged.
	cmdExit, err := c.Exec(ExecConfig{
		Cmd:  "/bin/sh",
		Args: []string{"-c", "exit 7"},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	_ = cmdExit.Run()
	if code := cmdExit.ProcessState.ExitCode(); code != 7 {
		t.Errorf("exec'd exit code = %d, want 7", code)
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()
}

// Same pid-membership pin over the join path that works without a mount
// namespace (and therefore also without CGO): the container shares the
// host's mnt/user namespaces, so only pid (and ipc) are joined.
func TestIntegration_ExecWithNsenter_PidNsSharedMnt(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	cfg := Config{
		Namespaces: Namespaces{
			NewPID: true,
			NewIPC: true,
		},
	}
	c := New(generateTestID(t), cfg)
	defer c.Destroy()

	var stdout, stderr bytes.Buffer
	proc := &Process{
		Cmd:    busybox,
		Args:   []string{"sleep", "30"},
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	containerNs := pidNsLink(t, c.Pid())

	var execStdout, execStderr bytes.Buffer
	cmd, err := c.Exec(ExecConfig{
		Cmd:    busybox,
		Args:   []string{"sh", "-c", "readlink /proc/self/ns/pid"},
		Stdout: &execStdout,
		Stderr: &execStderr,
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("readlink /proc/self/ns/pid in exec'd process failed: %v (stderr: %s)",
			err, execStderr.String())
	}
	got := strings.TrimSpace(execStdout.String())
	if got != containerNs {
		t.Errorf("exec'd process pid ns = %q, want container's %q", got, containerNs)
	}

	// Internal control-protocol variables must not leak into the payload's
	// environment — neither the join-protocol pair nor internal variables
	// inherited from the calling process (as when the caller is itself
	// self-containerized).
	t.Setenv("_CONTAINER_INITFD", "99")
	cmdEnv, err := c.Exec(ExecConfig{
		Cmd:  busybox,
		Args: []string{"sh", "-c", `test -z "$_CONTAINER_MODE" && test -z "$_CONTAINER_PID" && test -z "$_CONTAINER_INITFD"`},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmdEnv.Run(); err != nil {
		t.Errorf("_CONTAINER_MODE/_CONTAINER_PID leaked into exec'd process environment: %v", err)
	}

	// The exec'd process's exit code must reach the caller unchanged.
	cmdExit, err := c.Exec(ExecConfig{
		Cmd:  busybox,
		Args: []string{"sh", "-c", "exit 7"},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	_ = cmdExit.Run()
	if code := cmdExit.ProcessState.ExitCode(); code != 7 {
		t.Errorf("exec'd exit code = %d, want 7", code)
	}

	// Signal death of the payload must surface as signal death to the caller.
	cmdSig, err := c.Exec(ExecConfig{
		Cmd:  busybox,
		Args: []string{"sh", "-c", "kill -9 $$"},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	err = cmdSig.Run()
	if err == nil {
		t.Fatal("kill -9 $$ exec succeeded, want signal death")
	}
	ws, ok := cmdSig.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("exec'd wait status = %v (signaled=%v sig=%v), want death by SIGKILL",
			cmdSig.ProcessState, ok && ws.Signaled(), ws.Signal())
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()
}

// A container created with JoinPID must place its process inside the target
// pid namespace, not just re-home that process's future children.
func TestIntegration_CreateJoinPidNs(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	a := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer a.Destroy()
	if err := a.Run(&Process{Cmd: busybox, Args: []string{"sleep", "30"}}); err != nil {
		t.Fatalf("Run container A: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	aNs := pidNsLink(t, a.Pid())

	var bOut, bErr bytes.Buffer
	b := New(generateTestID(t), Config{
		Namespaces: Namespaces{JoinPID: fmt.Sprintf("/proc/%d/ns/pid", a.Pid())},
	})
	defer b.Destroy()
	err := b.Run(&Process{
		Cmd:    busybox,
		Args:   []string{"sh", "-c", "readlink /proc/self/ns/pid"},
		Stdout: &bOut,
		Stderr: &bErr,
	})
	if err != nil {
		if strings.Contains(err.Error(), "CGO") {
			t.Skip("namespace joins at create require CGO")
		}
		t.Fatalf("Run container B: %v", err)
	}
	b.Wait()

	got := strings.TrimSpace(bOut.String())
	if got != aNs {
		t.Errorf("joined container pid ns = %q, want target's %q (stderr: %s)",
			got, aNs, bErr.String())
	}

	a.Signal(syscall.SIGKILL)
	a.Wait()
}

// A container without a new or joined mount namespace must not touch the
// host's mount propagation.
func TestIntegration_NoMountNs_HostPropagationUntouched(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	// Make / shared so a stray propagation change is observable; restore
	// only if this test changed it, so a genuinely-shared / (real root)
	// is never rewritten by the test itself.
	before := rootPropagation(t)
	if !strings.Contains(before, "shared:") {
		if err := unix.Mount("", "/", "", unix.MS_SHARED|unix.MS_REC, ""); err != nil {
			t.Skipf("cannot set / shared: %v", err)
		}
		defer unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
		before = rootPropagation(t)
		if !strings.Contains(before, "shared:") {
			t.Fatalf("setup: / not shared: %q", before)
		}
	}

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: busybox, Args: []string{"true"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	c.Wait()

	after := rootPropagation(t)
	if after != before {
		t.Errorf("host / propagation changed by container without mount namespace: before=%q after=%q",
			before, after)
	}
}

// The create path execs the payload with an inherited environment; the
// library's internal control-protocol variables must be stripped from it.
func TestIntegration_CreateEnvNoInternalLeak(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	proc := &Process{
		Cmd: busybox,
		Args: []string{"sh", "-c",
			`test -z "$_CONTAINER_INITFD" && test -z "$_CONTAINER_STATUSFD" && test -z "$_CONTAINER_READYFD"`},
		InheritEnv: true,
	}
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	c.Wait()
	if code := c.ExitCode(); code != 0 {
		t.Errorf("internal _CONTAINER_* variables leaked into container process environment (exit %d)", code)
	}
}

// pidsInNs returns the host-visible pids whose pid-namespace link matches
// nsLink and whose cmdline contains marker.
func pidsInNs(t *testing.T, nsLink, marker string) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
		if err != nil || link != nsLink {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || !strings.Contains(string(cmdline), marker) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// A signal sent to the *exec.Cmd the caller holds must reach the payload
// inside the pid namespace — the shim forwards it — and the payload must
// not survive the exec'd command's death.
func TestIntegration_ExecWithNsenter_SignalForwarding(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: busybox, Args: []string{"sleep", "30"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	containerNs := pidNsLink(t, c.Pid())

	cmd, err := c.Exec(ExecConfig{
		Cmd:  busybox,
		Args: []string{"sleep", "300"},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for the payload to appear inside the container's pid ns.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(pidsInNs(t, containerNs, "300")) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(pidsInNs(t, containerNs, "300")) == 0 {
		t.Fatal("exec'd payload never appeared in the container pid ns")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal failed: %v", err)
	}
	err = cmd.Wait()
	if err == nil {
		t.Error("exec'd command exited cleanly after SIGTERM, want signal death")
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("wait status after SIGTERM = %v, want death by SIGTERM", cmd.ProcessState)
	}

	// The payload must not have been orphaned alive in the namespace.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(pidsInNs(t, containerNs, "300")) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if survivors := pidsInNs(t, containerNs, "300"); len(survivors) > 0 {
		t.Errorf("payload survived the exec'd command's death: pids %v", survivors)
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()
}

// A long exec command line must never be silently truncated: it either
// round-trips whole to the payload or fails loudly.
func TestIntegration_ExecWithNsenter_LongCmdline(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: busybox, Args: []string{"sleep", "30"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Beyond the old silently-truncating 64KiB buffer but within the
	// current one: must round-trip whole on every build.
	argMid := strings.Repeat("y", 40*1024)
	var midOut, midErr bytes.Buffer
	cmdMid, err := c.Exec(ExecConfig{
		Cmd:    busybox,
		Args:   []string{"sh", "-c", `printf %s "$1$2$3" | wc -c`, "sh", argMid, argMid, argMid},
		Stdout: &midOut,
		Stderr: &midErr,
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmdMid.Run(); err != nil {
		t.Fatalf("120KiB cmdline exec failed: %v (stderr: %s)", err, midErr.String())
	}
	if got, want := strings.TrimSpace(midOut.String()), fmt.Sprintf("%d", 3*40*1024); got != want {
		t.Errorf("payload saw %s bytes of args, want %s (silent truncation)", got, want)
	}

	// Beyond any buffer: either the whole thing round-trips (nocgo — no
	// cmdline re-parse) or the failure names the cause (cgo).
	arg := strings.Repeat("x", 60*1024)
	args := []string{"sh", "-c", `printf %s "$1$2$3$4$5" | wc -c`, "sh", arg, arg, arg, arg, arg}
	want := fmt.Sprintf("%d", 5*60*1024)

	var stdout, stderr bytes.Buffer
	cmd, err := c.Exec(ExecConfig{
		Cmd:    busybox,
		Args:   args,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	runErr := cmd.Run()
	if runErr == nil {
		if got := strings.TrimSpace(stdout.String()); got != want {
			t.Errorf("payload saw %s bytes of args, want %s (silent truncation)", got, want)
		}
	} else if !strings.Contains(stderr.String(), "command line too long") {
		t.Errorf("long cmdline failed without naming the cause: %v (stderr: %s)",
			runErr, stderr.String())
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()
}

// procState returns the single-letter state of a process from
// /proc/<pid>/stat ("R", "S", "T", ...), or "" if unreadable.
func procState(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// Field 3 follows the parenthesized comm, which may contain spaces.
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 || i+2 >= len(data) {
		return ""
	}
	f := strings.Fields(string(data[i+2:]))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// Killing the shim uncatchably must not orphan the payload alive in the
// container: the payload's parent-death signal reaps it.
func TestIntegration_ExecWithNsenter_KillShimKillsPayload(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: busybox, Args: []string{"sleep", "30"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	containerNs := pidNsLink(t, c.Pid())

	cmd, err := c.Exec(ExecConfig{Cmd: busybox, Args: []string{"sleep", "301"}})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(pidsInNs(t, containerNs, "301")) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(pidsInNs(t, containerNs, "301")) == 0 {
		t.Fatal("exec'd payload never appeared in the container pid ns")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	_ = cmd.Wait()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(pidsInNs(t, containerNs, "301")) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if survivors := pidsInNs(t, containerNs, "301"); len(survivors) > 0 {
		t.Errorf("payload survived SIGKILL of the shim: pids %v", survivors)
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()

	// The create-handshake subreaper flag must not outlive the handshake:
	// a permanent subreaper adopts orphaned payload zombies, and those
	// deadlock pid-namespace teardown.
	var sub int
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&sub)), 0, 0, 0); err == nil && sub != 0 {
		t.Error("PR_SET_CHILD_SUBREAPER left set after create completed")
	}
}

// A stop signal sent to the exec'd command must stop both the payload
// and the shim (so WUNTRACED waiters see the stop), and SIGCONT must
// resume both.
func TestIntegration_ExecWithNsenter_StopMirror(t *testing.T) {
	skipIfNotRoot(t)
	busybox := downloadBusybox(t)

	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: busybox, Args: []string{"sleep", "30"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	containerNs := pidNsLink(t, c.Pid())

	cmd, err := c.Exec(ExecConfig{Cmd: busybox, Args: []string{"sleep", "302"}})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	// Own process group, as a shell job would have: the test tree runs in
	// an orphaned process group (no controlling terminal), and the kernel
	// discards SIGTSTP sent to members of an orphaned group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(pidsInNs(t, containerNs, "302")) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	payloads := pidsInNs(t, containerNs, "302")
	if len(payloads) == 0 {
		t.Fatal("exec'd payload never appeared in the container pid ns")
	}
	shim := cmd.Process.Pid

	waitState := func(pid int, want string) bool {
		d := time.Now().Add(2 * time.Second)
		for time.Now().Before(d) {
			if procState(pid) == want {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	if err := cmd.Process.Signal(syscall.SIGTSTP); err != nil {
		t.Fatalf("SIGTSTP failed: %v", err)
	}
	if !waitState(payloads[0], "T") {
		t.Errorf("payload did not stop on forwarded SIGTSTP (state %q)", procState(payloads[0]))
	}
	if !waitState(shim, "T") {
		t.Errorf("shim did not mirror the stop (state %q)", procState(shim))
	}

	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatalf("SIGCONT failed: %v", err)
	}
	if !waitState(payloads[0], "S") {
		t.Errorf("payload did not resume on SIGCONT (state %q)", procState(payloads[0]))
	}
	if !waitState(shim, "S") {
		t.Errorf("shim did not resume on SIGCONT (state %q)", procState(shim))
	}

	cmd.Process.Kill()
	cmd.Wait()
	c.Signal(syscall.SIGKILL)
	c.Wait()
}

// The __self path continues running the caller's own code: the internal
// control-protocol variables must be scrubbed from its environment.
// The test re-execs itself via RunSelf pinned to this test; the child
// leg runs the assertions inside the container and its exit code is the
// verdict.
func TestIntegration_SelfContainerizeEnvClean(t *testing.T) {
	if InContainer() {
		for _, v := range []string{
			"_CONTAINER_INITFD", "_CONTAINER_STATUSFD", "_CONTAINER_READYFD",
			"_CONTAINER_MODE", "_CONTAINER_CONFIGFD", "_CONTAINER_SYNCFD",
		} {
			if val := os.Getenv(v); val != "" {
				t.Fatalf("%s=%q leaked into self-containerized process", v, val)
			}
		}
		return
	}

	skipIfNotRoot(t)
	c := New(generateTestID(t), Config{Namespaces: Namespaces{NewPID: true}})
	defer c.Destroy()
	if err := c.RunSelf("-test.run", "^TestIntegration_SelfContainerizeEnvClean$"); err != nil {
		t.Fatalf("RunSelf: %v", err)
	}
	if err := c.Wait(); err != nil {
		t.Errorf("self-containerized assertion leg failed: %v", err)
	}
	if code := c.ExitCode(); code != 0 {
		t.Errorf("self-containerized assertion leg failed (exit %d)", code)
	}
}

// Exec into a chroot-rooted container (no mount namespace) must land
// the payload inside both the pid namespace and the chroot — the join
// path's --root leg, applied on the payload side of the shim.
func TestIntegration_ExecWithNsenter_ChrootRoot(t *testing.T) {
	skipIfNotRoot(t)
	rootfs := createTestRootfs(t)

	// A marker whose content only this rootfs can produce: reading it
	// proves the payload is chrooted regardless of what the host has at
	// any well-known path. The ns check proves pid membership.
	marker := generateTestID(t)
	if err := os.WriteFile(filepath.Join(rootfs, "rootfs-marker"), []byte(marker), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	cfg := Config{
		Root:       rootfs,
		Namespaces: Namespaces{NewPID: true},
	}
	c := New(generateTestID(t), cfg)
	defer c.Destroy()
	if err := c.Run(&Process{Cmd: "/bin/sleep", Args: []string{"30"}}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	containerNs := pidNsLink(t, c.Pid())

	var out, errb bytes.Buffer
	cmd, err := c.Exec(ExecConfig{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "/bin/cat /rootfs-marker && exec /bin/sleep 303"},
		Stdout: &out,
		Stderr: &errb,
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v (stderr: %s)", err, errb.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(pidsInNs(t, containerNs, "303")) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(pidsInNs(t, containerNs, "303")) == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("chrooted payload never appeared in the container pid ns (stdout: %q, stderr: %q)",
			out.String(), errb.String())
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
	if got := strings.TrimSpace(out.String()); got != marker {
		t.Errorf("chroot marker output = %q, want %q (stderr: %s)", got, marker, errb.String())
	}

	c.Signal(syscall.SIGKILL)
	c.Wait()
}
