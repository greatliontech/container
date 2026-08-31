package container

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInContainer(t *testing.T) {
	// Should be false by default.
	if InContainer() {
		t.Error("InContainer() should be false outside container")
	}

	// Set env and check.
	os.Setenv("_CONTAINER_INSIDE", "1")
	defer os.Unsetenv("_CONTAINER_INSIDE")

	if !InContainer() {
		t.Error("InContainer() should be true when _CONTAINER_INSIDE=1")
	}
}

func TestNsDiffers_SameNamespace(t *testing.T) {
	pid := fmt.Sprintf("%d", os.Getpid())
	// Our own namespace should not differ from itself.
	if nsDiffers(pid, "user") {
		t.Error("nsDiffers should be false for own user namespace")
	}
	if nsDiffers(pid, "mnt") {
		t.Error("nsDiffers should be false for own mount namespace")
	}
}

func TestNsDiffers_InvalidPid(t *testing.T) {
	// Non-existent PID should return false (can't determine).
	if nsDiffers("999999999", "user") {
		t.Error("nsDiffers should be false for non-existent PID")
	}
}

func TestGetNamespacePaths(t *testing.T) {
	paths := GetNamespacePaths(os.Getpid())

	// Every running process should have at least these namespaces.
	required := []string{"user", "mnt", "uts", "ipc", "net", "pid"}
	for _, ns := range required {
		if _, ok := paths[ns]; !ok {
			t.Errorf("GetNamespacePaths missing %q", ns)
		}
	}
}

func TestApplyRlimits(t *testing.T) {
	// Get current RLIMIT_NOFILE.
	var orig unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}

	// Set a lower soft limit (within current hard limit).
	newSoft := orig.Cur / 2
	if newSoft == 0 {
		newSoft = 64
	}
	limits := []Rlimit{
		{Type: unix.RLIMIT_NOFILE, Soft: newSoft, Hard: orig.Max},
	}

	if err := applyRlimits(limits); err != nil {
		t.Fatalf("applyRlimits: %v", err)
	}

	// Verify it was applied.
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != newSoft {
		t.Errorf("RLIMIT_NOFILE soft = %d, want %d", after.Cur, newSoft)
	}

	// Restore.
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &orig)
}

func TestApplyMaskPaths_NonexistentPaths(t *testing.T) {
	// Masking non-existent paths should silently skip them.
	err := applyMaskPaths([]string{"/nonexistent/path/1", "/nonexistent/path/2"})
	if err != nil {
		t.Errorf("applyMaskPaths with non-existent paths: %v", err)
	}
}

func TestApplyReadonlyPaths_NonexistentPaths(t *testing.T) {
	// Readonly on non-existent paths should silently skip them.
	err := applyReadonlyPaths([]string{"/nonexistent/path/1", "/nonexistent/path/2"})
	if err != nil {
		t.Errorf("applyReadonlyPaths with non-existent paths: %v", err)
	}
}

// A config asking for a new namespace and a join of the same type is
// contradictory — unshare would silently win — and must be rejected
// before any process is spawned.
func TestValidateRejectsNewPlusJoin(t *testing.T) {
	cfg := Config{Namespaces: Namespaces{NewPID: true, JoinPID: "/proc/1/ns/pid"}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate accepted NewPID+JoinPID")
	}
	if !strings.Contains(err.Error(), "pid") {
		t.Errorf("error %q does not name the namespace", err)
	}

	c := New("new-plus-join", cfg)
	if err := c.Run(&Process{Cmd: "/bin/true"}); err == nil {
		c.Wait()
		t.Fatal("Run accepted NewPID+JoinPID")
	}
}

// RootfsPropagation is mount-namespace-scoped state; without a new or
// joined mount namespace it must be rejected, not silently dropped.
func TestValidateRejectsPropagationWithoutMountNs(t *testing.T) {
	cfg := Config{RootfsPropagation: "slave"}
	if err := cfg.validate(); err == nil {
		t.Fatal("validate accepted RootfsPropagation without a mount namespace")
	}
	cfg = Config{RootfsPropagation: "slave", Namespaces: Namespaces{NewMnt: true}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate rejected RootfsPropagation with NewMnt: %v", err)
	}
	cfg = Config{RootfsPropagation: "slave", Namespaces: Namespaces{JoinMnt: "/proc/1/ns/mnt"}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate rejected RootfsPropagation with JoinMnt: %v", err)
	}
}
