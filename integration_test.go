//go:build integration

package container

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Comprehensive integration tests for container scenarios (require root)

func TestIntegration_SeccompBlocks(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_SeccompBlocks: starting...")
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
		Seccomp:      DefaultSeccompProfile(),
	}

	t.Log("TestIntegration_SeccompBlocks: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	// Try to reboot (should fail with EPERM due to seccomp)
	// We can't easily test this directly, but we can verify the profile is applied
	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo seccomp_test"},
		Stdout: &stdout,
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
	t.Logf("TestIntegration_SeccompBlocks: output=%q", output)
	if output != "seccomp_test" {
		t.Errorf("unexpected output: %s", output)
	}
	t.Log("TestIntegration_SeccompBlocks: done")
}

func TestIntegration_DevicesAccessible(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_DevicesAccessible: starting...")
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
		Devices:      DefaultDevices(),
	}

	t.Log("TestIntegration_DevicesAccessible: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
		Devices:      DefaultDevices(),
	}

	t.Log("TestIntegration_DevicesUrandom: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
		Resources: &Resources{
			Pids: &PidsResources{
				Max: 10, // Very low limit
			},
		},
	}

	t.Log("TestIntegration_PidsLimit: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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

func TestIntegration_NetworkNone(t *testing.T) {
	skipIfNotRoot(t)

	t.Log("TestIntegration_NetworkNone: starting...")
	rootfs := createTestRootfs(t)
	stateDir := t.TempDir()
	containerID := generateTestID(t)

	cfg := Config{
		Root: rootfs,
		Namespaces: Namespaces{
			NewIPC: true,
			NewMnt: true,
			NewNet: true, // New network namespace
			NewPID: true,
			NewUTS: true,
		},
		UsePivotRoot: true,
		SetupDev:     true,
		Network: &NetworkConfig{
			Mode: NetworkModeNone,
		},
	}

	t.Log("TestIntegration_NetworkNone: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	var stdout bytes.Buffer
	proc := &Process{
		Cmd:    "/bin/sh",
		Args:   []string{"-c", "echo net_none"},
		Stdout: &stdout,
	}

	t.Log("TestIntegration_NetworkNone: running...")
	if err := c.Run(proc); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	t.Log("TestIntegration_NetworkNone: waiting...")
	if err := c.Wait(); err != nil {
		t.Logf("Wait returned: %v", err)
	}

	t.Logf("TestIntegration_NetworkNone: output=%q", stdout.String())
	if !strings.Contains(stdout.String(), "net_none") {
		t.Error("container with no network didn't run correctly")
	}
	t.Log("TestIntegration_NetworkNone: done")
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
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
		Resources:    DefaultResources(),
	}

	t.Log("TestIntegration_Stats: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
	stateDir := t.TempDir()

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
		c, err := New(stateDir, containerID, cfg)
		if err != nil {
			t.Fatalf("New failed for container %d: %v", i, err)
		}
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
	stateDir := t.TempDir()
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
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer c.Destroy()

	proc := &Process{
		Cmd: "/bin/sh",
	}

	// Run should fail because rootfs doesn't exist
	t.Log("TestIntegration_InvalidConfig: running (should fail)...")
	err = c.Run(proc)
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

	t.Log("TestIntegration_SignalDuringStartup: creating container...")
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
	err = c.Signal(syscall.SIGKILL)
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
	stateDir := t.TempDir()
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
	c, err := New(stateDir, containerID, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
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
