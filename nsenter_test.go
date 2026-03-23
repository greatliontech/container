package container

import (
	"fmt"
	"os"
	"testing"
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
