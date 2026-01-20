package container

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const busyboxURL = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"

// skipIfNotRoot skips the test if not running as root
func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires root privileges")
	}
}

// skipIfNoCgroupV2 skips the test if cgroup v2 is not available
func skipIfNoCgroupV2(t *testing.T) {
	t.Helper()
	if !isCgroupV2() {
		t.Skip("test requires cgroup v2")
	}
}

// skipIfNoNetwork skips the test if network tests cannot be run
func skipIfNoNetwork(t *testing.T) {
	t.Helper()
	skipIfNotRoot(t)
	// Check if we can create network interfaces
	if _, err := os.Stat("/sys/class/net"); err != nil {
		t.Skip("test requires network support")
	}
}

// skipIfNoNftables skips the test if nftables is not available
func skipIfNoNftables(t *testing.T) {
	t.Helper()
	skipIfNotRoot(t)
	// Check if nftables is available
	if _, err := os.Stat("/proc/net/netfilter"); err != nil {
		t.Skip("test requires nftables support")
	}
}

// getBusyboxCacheDir returns the cache directory for busybox
func getBusyboxCacheDir() string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			cacheDir = "/tmp"
		} else {
			cacheDir = filepath.Join(home, ".cache")
		}
	}
	return filepath.Join(cacheDir, "container-tests")
}

// downloadBusybox downloads busybox binary if not cached
func downloadBusybox(t *testing.T) string {
	t.Helper()

	if runtime.GOARCH != "amd64" {
		t.Skip("busybox binary only available for amd64")
	}

	cacheDir := getBusyboxCacheDir()
	busyboxPath := filepath.Join(cacheDir, "busybox")

	// Check if already cached
	if info, err := os.Stat(busyboxPath); err == nil && info.Size() > 0 {
		return busyboxPath
	}

	// Create cache directory
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create cache directory: %v", err)
	}

	t.Logf("downloading busybox from %s", busyboxURL)

	resp, err := http.Get(busyboxURL)
	if err != nil {
		t.Fatalf("failed to download busybox: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to download busybox: HTTP %d", resp.StatusCode)
	}

	// Create temp file and download
	tmpFile, err := os.CreateTemp(cacheDir, "busybox-download-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		t.Fatalf("failed to download busybox: %v", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		t.Fatalf("failed to make busybox executable: %v", err)
	}

	// Move to final location
	if err := os.Rename(tmpPath, busyboxPath); err != nil {
		// Rename failed, try copy
		src, err := os.Open(tmpPath)
		if err != nil {
			t.Fatalf("failed to open temp busybox: %v", err)
		}
		defer src.Close()

		dst, err := os.OpenFile(busyboxPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			t.Fatalf("failed to create busybox: %v", err)
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			t.Fatalf("failed to copy busybox: %v", err)
		}
	}

	return busyboxPath
}

// createTestRootfs creates a minimal rootfs with busybox for testing
func createTestRootfs(t *testing.T) string {
	t.Helper()

	t.Log("createTestRootfs: downloading busybox...")
	busyboxPath := downloadBusybox(t)
	t.Log("createTestRootfs: busybox ready at", busyboxPath)

	t.Log("createTestRootfs: creating temp directory...")
	dir := t.TempDir()

	// Create directory structure
	t.Log("createTestRootfs: creating directory structure...")
	dirs := []string{
		"bin", "sbin", "usr/bin", "usr/sbin",
		"proc", "dev", "sys", "tmp", "etc", "root",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", d, err)
		}
	}

	// Copy busybox
	t.Log("createTestRootfs: copying busybox...")
	bbDst := filepath.Join(dir, "bin", "busybox")
	if err := copyFile(busyboxPath, bbDst); err != nil {
		t.Fatalf("failed to copy busybox: %v", err)
	}
	if err := os.Chmod(bbDst, 0755); err != nil {
		t.Fatalf("failed to chmod busybox: %v", err)
	}

	// Create symlinks for common commands
	t.Log("createTestRootfs: creating symlinks...")
	cmds := []string{"sh", "cat", "echo", "sleep", "ls", "ps", "id", "hostname", "mkdir", "rm", "true", "false", "test", "head", "tail", "pwd"}
	for _, cmd := range cmds {
		linkPath := filepath.Join(dir, "bin", cmd)
		if err := os.Symlink("busybox", linkPath); err != nil {
			t.Fatalf("failed to create symlink for %s: %v", cmd, err)
		}
	}

	// Create /etc/passwd and /etc/group for id command
	t.Log("createTestRootfs: creating etc files...")
	passwd := "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n"
	if err := os.WriteFile(filepath.Join(dir, "etc", "passwd"), []byte(passwd), 0644); err != nil {
		t.Fatalf("failed to create /etc/passwd: %v", err)
	}

	group := "root:x:0:\nnobody:x:65534:\n"
	if err := os.WriteFile(filepath.Join(dir, "etc", "group"), []byte(group), 0644); err != nil {
		t.Fatalf("failed to create /etc/group: %v", err)
	}

	t.Log("createTestRootfs: rootfs ready at", dir)
	return dir
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

// waitForCondition waits for a condition to become true
func waitForCondition(t *testing.T, cond func() bool, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// waitForFile waits for a file to exist
func waitForFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	return waitForCondition(t, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, timeout)
}

// generateTestID generates a unique test ID
func generateTestID(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	h.Write([]byte(t.Name()))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return fmt.Sprintf("test-%x", h.Sum(nil)[:8])
}

// requireRoot fails the test if not running as root
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatal("test requires root privileges")
	}
}

// fileContains checks if a file contains a string
func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
