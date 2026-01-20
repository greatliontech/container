package container

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Unit tests for cgroups (no root required)

func TestDefaultResources(t *testing.T) {
	resources := DefaultResources()

	if resources == nil {
		t.Fatal("DefaultResources returned nil")
	}

	// Should have pids limit set
	if resources.Pids == nil {
		t.Fatal("DefaultResources should set Pids")
	}

	// Verify pids.max is reasonable (prevents fork bombs)
	if resources.Pids.Max != 1024 {
		t.Errorf("Pids.Max = %d, want 1024", resources.Pids.Max)
	}

	// Memory should not be set by default
	if resources.Memory != nil {
		t.Error("DefaultResources should not set Memory")
	}

	// CPU should not be set by default
	if resources.CPU != nil {
		t.Error("DefaultResources should not set CPU")
	}

	// IO should not be set by default
	if resources.IO != nil {
		t.Error("DefaultResources should not set IO")
	}
}

func TestIsCgroupV2(t *testing.T) {
	// This test just verifies the function runs without panicking
	// The result depends on the system configuration
	result := isCgroupV2()

	// Check /proc/mounts for cgroup2 to verify our detection
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		t.Skip("cannot read /proc/mounts")
	}

	hasCgroupV2 := strings.Contains(string(data), "cgroup2")
	if result != hasCgroupV2 {
		t.Errorf("isCgroupV2() = %v, but /proc/mounts indicates %v", result, hasCgroupV2)
	}
}

func TestResourcesStruct(t *testing.T) {
	// Test Resources struct can be properly created
	resources := Resources{
		Memory: &MemoryResources{
			Max:     1024 * 1024 * 1024, // 1GB
			High:    768 * 1024 * 1024,  // 768MB
			SwapMax: 0,                  // No swap
		},
		CPU: &CPUResources{
			Quota:  50000,
			Period: 100000,
			Weight: 100,
			Cpus:   "0-1",
			Mems:   "0",
		},
		Pids: &PidsResources{
			Max: 100,
		},
		IO: &IOResources{
			Weight: 100,
			Max:    map[string]string{"8:0": "rbps=1048576"},
		},
	}

	if resources.Memory.Max != 1024*1024*1024 {
		t.Errorf("Memory.Max = %d, want 1GB", resources.Memory.Max)
	}
	if resources.Memory.High != 768*1024*1024 {
		t.Errorf("Memory.High = %d, want 768MB", resources.Memory.High)
	}
	if resources.Memory.SwapMax != 0 {
		t.Errorf("Memory.SwapMax = %d, want 0", resources.Memory.SwapMax)
	}

	if resources.CPU.Quota != 50000 {
		t.Errorf("CPU.Quota = %d, want 50000", resources.CPU.Quota)
	}
	if resources.CPU.Period != 100000 {
		t.Errorf("CPU.Period = %d, want 100000", resources.CPU.Period)
	}
	if resources.CPU.Weight != 100 {
		t.Errorf("CPU.Weight = %d, want 100", resources.CPU.Weight)
	}
	if resources.CPU.Cpus != "0-1" {
		t.Errorf("CPU.Cpus = %s, want 0-1", resources.CPU.Cpus)
	}
	if resources.CPU.Mems != "0" {
		t.Errorf("CPU.Mems = %s, want 0", resources.CPU.Mems)
	}

	if resources.Pids.Max != 100 {
		t.Errorf("Pids.Max = %d, want 100", resources.Pids.Max)
	}

	if resources.IO.Weight != 100 {
		t.Errorf("IO.Weight = %d, want 100", resources.IO.Weight)
	}
}

func TestMemoryResourcesStruct(t *testing.T) {
	tests := []struct {
		name    string
		max     int64
		high    int64
		swapMax int64
	}{
		{
			name:    "unlimited",
			max:     -1,
			high:    -1,
			swapMax: -1,
		},
		{
			name:    "limited",
			max:     1024 * 1024 * 1024,
			high:    512 * 1024 * 1024,
			swapMax: 256 * 1024 * 1024,
		},
		{
			name:    "no swap",
			max:     1024 * 1024 * 1024,
			high:    -1,
			swapMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := MemoryResources{
				Max:     tt.max,
				High:    tt.high,
				SwapMax: tt.swapMax,
			}

			if mem.Max != tt.max {
				t.Errorf("Max = %d, want %d", mem.Max, tt.max)
			}
			if mem.High != tt.high {
				t.Errorf("High = %d, want %d", mem.High, tt.high)
			}
			if mem.SwapMax != tt.swapMax {
				t.Errorf("SwapMax = %d, want %d", mem.SwapMax, tt.swapMax)
			}
		})
	}
}

func TestCPUResourcesStruct(t *testing.T) {
	cpu := CPUResources{
		Quota:  25000,
		Period: 100000,
		Weight: 50,
		Cpus:   "0,2,4",
		Mems:   "0-1",
	}

	// 25% of one CPU
	cpuPercent := float64(cpu.Quota) / float64(cpu.Period) * 100
	if cpuPercent != 25.0 {
		t.Errorf("CPU percentage = %.2f%%, want 25%%", cpuPercent)
	}
}

func TestPidsResourcesStruct(t *testing.T) {
	pids := PidsResources{Max: 512}
	if pids.Max != 512 {
		t.Errorf("Max = %d, want 512", pids.Max)
	}

	// Test unlimited
	pidsUnlimited := PidsResources{Max: -1}
	if pidsUnlimited.Max != -1 {
		t.Errorf("Unlimited Max = %d, want -1", pidsUnlimited.Max)
	}
}

func TestIOResourcesStruct(t *testing.T) {
	io := IOResources{
		Weight: 200,
		Max: map[string]string{
			"8:0": "rbps=1048576 wbps=1048576",
			"8:1": "riops=1000 wiops=1000",
		},
	}

	if io.Weight != 200 {
		t.Errorf("Weight = %d, want 200", io.Weight)
	}
	if len(io.Max) != 2 {
		t.Errorf("Max length = %d, want 2", len(io.Max))
	}
}

func TestCgroupErrors(t *testing.T) {
	// Test error constants
	if ErrCgroupV2NotMounted == nil {
		t.Error("ErrCgroupV2NotMounted should not be nil")
	}
	if ErrCgroupNotFound == nil {
		t.Error("ErrCgroupNotFound should not be nil")
	}
	if ErrControllerNotEnabled == nil {
		t.Error("ErrControllerNotEnabled should not be nil")
	}

	// Verify error messages
	if !strings.Contains(ErrCgroupV2NotMounted.Error(), "cgroup") {
		t.Error("ErrCgroupV2NotMounted message should mention cgroup")
	}
	if !strings.Contains(ErrCgroupNotFound.Error(), "not found") {
		t.Error("ErrCgroupNotFound message should mention not found")
	}
}

func TestCgroupStatsStruct(t *testing.T) {
	stats := CgroupStats{
		Memory: &MemoryStats{
			Current: 1024 * 1024,
			Peak:    2048 * 1024,
		},
		CPU: &CPUStats{
			UsageUsec: 1000000,
		},
		Pids: &PidsStats{
			Current: 5,
		},
	}

	if stats.Memory.Current != 1024*1024 {
		t.Errorf("Memory.Current = %d, want 1MB", stats.Memory.Current)
	}
	if stats.Memory.Peak != 2048*1024 {
		t.Errorf("Memory.Peak = %d, want 2MB", stats.Memory.Peak)
	}
	if stats.CPU.UsageUsec != 1000000 {
		t.Errorf("CPU.UsageUsec = %d, want 1000000", stats.CPU.UsageUsec)
	}
	if stats.Pids.Current != 5 {
		t.Errorf("Pids.Current = %d, want 5", stats.Pids.Current)
	}
}

// Integration tests for cgroups (require root)
// These tests require the "integration" build tag to run:
// go test -tags=integration ./...

func TestCgroup_Create(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	// Verify cgroup directory was created
	cgPath := cg.Path()
	if !dirExists(cgPath) {
		t.Errorf("cgroup directory not created: %s", cgPath)
	}

	// Verify it's in the right location
	expectedPath := filepath.Join(cgroupV2Root, cgName)
	if cgPath != expectedPath {
		t.Errorf("cgroup path = %s, want %s", cgPath, expectedPath)
	}
}

func TestCgroup_ApplyMemory(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	resources := &Resources{
		Memory: &MemoryResources{
			Max:  512 * 1024 * 1024, // 512MB
			High: 256 * 1024 * 1024, // 256MB
		},
	}

	if err := cg.Apply(resources); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify memory.max
	maxPath := filepath.Join(cg.Path(), "memory.max")
	data, err := os.ReadFile(maxPath)
	if err != nil {
		t.Fatalf("failed to read memory.max: %v", err)
	}

	maxVal := strings.TrimSpace(string(data))
	expectedMax := strconv.FormatInt(resources.Memory.Max, 10)
	if maxVal != expectedMax {
		t.Errorf("memory.max = %s, want %s", maxVal, expectedMax)
	}

	// Verify memory.high
	highPath := filepath.Join(cg.Path(), "memory.high")
	data, err = os.ReadFile(highPath)
	if err != nil {
		t.Fatalf("failed to read memory.high: %v", err)
	}

	highVal := strings.TrimSpace(string(data))
	expectedHigh := strconv.FormatInt(resources.Memory.High, 10)
	if highVal != expectedHigh {
		t.Errorf("memory.high = %s, want %s", highVal, expectedHigh)
	}
}

func TestCgroup_ApplyCPU(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	resources := &Resources{
		CPU: &CPUResources{
			Quota:  50000,
			Period: 100000,
			Weight: 100,
		},
	}

	if err := cg.Apply(resources); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify cpu.max
	maxPath := filepath.Join(cg.Path(), "cpu.max")
	data, err := os.ReadFile(maxPath)
	if err != nil {
		t.Fatalf("failed to read cpu.max: %v", err)
	}

	maxVal := strings.TrimSpace(string(data))
	expectedMax := "50000 100000"
	if maxVal != expectedMax {
		t.Errorf("cpu.max = %s, want %s", maxVal, expectedMax)
	}

	// Verify cpu.weight
	weightPath := filepath.Join(cg.Path(), "cpu.weight")
	data, err = os.ReadFile(weightPath)
	if err != nil {
		t.Fatalf("failed to read cpu.weight: %v", err)
	}

	weightVal := strings.TrimSpace(string(data))
	if weightVal != "100" {
		t.Errorf("cpu.weight = %s, want 100", weightVal)
	}
}

func TestCgroup_ApplyPids(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	resources := &Resources{
		Pids: &PidsResources{
			Max: 100,
		},
	}

	if err := cg.Apply(resources); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify pids.max
	maxPath := filepath.Join(cg.Path(), "pids.max")
	data, err := os.ReadFile(maxPath)
	if err != nil {
		t.Fatalf("failed to read pids.max: %v", err)
	}

	maxVal := strings.TrimSpace(string(data))
	if maxVal != "100" {
		t.Errorf("pids.max = %s, want 100", maxVal)
	}
}

func TestCgroup_AddProcess(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	// Add current process to cgroup
	pid := os.Getpid()
	if err := cg.AddProcess(pid); err != nil {
		t.Fatalf("AddProcess failed: %v", err)
	}

	// Verify process is in cgroup
	procs, err := cg.Processes()
	if err != nil {
		t.Fatalf("Processes failed: %v", err)
	}

	found := false
	for _, p := range procs {
		if p == pid {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("PID %d not found in cgroup.procs", pid)
	}
}

func TestCgroup_Stats(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	// Add current process to get some stats
	if err := cg.AddProcess(os.Getpid()); err != nil {
		t.Fatalf("AddProcess failed: %v", err)
	}

	stats, err := cg.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats == nil {
		t.Fatal("Stats returned nil")
	}

	// Memory stats should be available
	if stats.Memory == nil {
		t.Log("Memory stats not available (might be expected on some systems)")
	} else {
		// Current should be > 0 since a process is in the cgroup
		if stats.Memory.Current == 0 {
			t.Log("Memory.Current is 0 (process might not have allocated memory yet)")
		}
	}

	// Pids stats should show at least one process
	if stats.Pids == nil {
		t.Log("Pids stats not available (might be expected on some systems)")
	} else if stats.Pids.Current == 0 {
		t.Error("Pids.Current should be > 0")
	}
}

func TestCgroup_Delete(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}

	cgPath := cg.Path()

	// Verify cgroup exists
	if !dirExists(cgPath) {
		t.Fatal("cgroup directory should exist")
	}

	// Delete the cgroup
	if err := cg.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify cgroup is removed
	if dirExists(cgPath) {
		t.Error("cgroup directory should be removed after Delete")
	}
}

func TestLoadCgroup(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	cgName := "test-container-" + generateTestID(t)

	// Create cgroup
	cg, err := NewCgroup(cgName)
	if err != nil {
		t.Fatalf("NewCgroup failed: %v", err)
	}
	defer cg.Delete()

	// Load the existing cgroup
	loaded, err := LoadCgroup(cgName)
	if err != nil {
		t.Fatalf("LoadCgroup failed: %v", err)
	}

	if loaded.Path() != cg.Path() {
		t.Errorf("loaded path = %s, want %s", loaded.Path(), cg.Path())
	}
}

func TestLoadCgroup_NotFound(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoCgroupV2(t)

	_, err := LoadCgroup("nonexistent-cgroup-12345")
	if err != ErrCgroupNotFound {
		t.Errorf("LoadCgroup error = %v, want ErrCgroupNotFound", err)
	}
}
