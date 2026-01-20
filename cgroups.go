package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	cgroupV2Root = "/sys/fs/cgroup"
)

var (
	ErrCgroupV2NotMounted   = errors.New("cgroup v2 not mounted")
	ErrCgroupNotFound       = errors.New("cgroup not found")
	ErrControllerNotEnabled = errors.New("controller not enabled")
)

// Resources defines resource limits for a container using cgroups v2
type Resources struct {
	// Memory limits
	Memory *MemoryResources

	// CPU limits
	CPU *CPUResources

	// Process limits
	Pids *PidsResources

	// I/O limits
	IO *IOResources
}

// MemoryResources defines memory limits
type MemoryResources struct {
	// Max is the hard memory limit in bytes (memory.max)
	// Use -1 for unlimited
	Max int64

	// High is the memory throttling threshold in bytes (memory.high)
	// When exceeded, processes are throttled and put under heavy reclaim pressure
	// Use -1 for unlimited
	High int64

	// SwapMax is the swap limit in bytes (memory.swap.max)
	// Use -1 for unlimited, 0 to disable swap
	SwapMax int64
}

// CPUResources defines CPU limits
type CPUResources struct {
	// Max is the CPU bandwidth limit as "quota period" (cpu.max)
	// quota is in microseconds, period is typically 100000 (100ms)
	// e.g., "50000 100000" limits to 50% of one CPU
	// Use "max 100000" for unlimited
	Quota  int64
	Period uint64

	// Weight is the CPU weight for fair scheduling (cpu.weight)
	// Range: 1-10000, default 100
	Weight uint64

	// Cpus is the set of CPUs the container can use (cpuset.cpus)
	// e.g., "0-3" or "0,2,4"
	Cpus string

	// Mems is the set of memory nodes the container can use (cpuset.mems)
	// e.g., "0-1" or "0"
	Mems string
}

// PidsResources defines process limits
type PidsResources struct {
	// Max is the maximum number of processes (pids.max)
	// Use -1 for unlimited
	Max int64
}

// IOResources defines I/O limits
type IOResources struct {
	// Weight is the I/O weight for fair scheduling (io.weight)
	// Range: 1-10000, default 100
	Weight uint64

	// Max specifies per-device I/O limits (io.max)
	// Key is "major:minor", value is the limit string
	// e.g., "8:0": "rbps=1048576 wbps=1048576 riops=1000 wiops=1000"
	Max map[string]string
}

// Cgroup represents a cgroup v2 control group
type Cgroup struct {
	path string
	name string
}

// isCgroupV2 checks if cgroup v2 is mounted
func isCgroupV2() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "cgroup2")
}

// getEnabledControllers returns the list of enabled controllers
func getEnabledControllers(cgroupPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	controllers := strings.Fields(strings.TrimSpace(string(data)))
	return controllers, nil
}

// enableControllers enables the specified controllers in a cgroup
func enableControllers(cgroupPath string, controllers []string) error {
	subtreeControl := filepath.Join(cgroupPath, "cgroup.subtree_control")
	for _, c := range controllers {
		if err := os.WriteFile(subtreeControl, []byte("+"+c), 0644); err != nil {
			// Ignore errors for controllers that are already enabled or not available
			continue
		}
	}
	return nil
}

// NewCgroup creates a new cgroup for the container
func NewCgroup(name string) (*Cgroup, error) {
	if !isCgroupV2() {
		return nil, ErrCgroupV2NotMounted
	}

	cgroupPath := filepath.Join(cgroupV2Root, name)

	// Create the cgroup directory
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}

	// Enable controllers in the parent cgroup
	parentPath := filepath.Dir(cgroupPath)
	controllers, err := getEnabledControllers(parentPath)
	if err != nil {
		// Try to get controllers from root if parent fails
		controllers, _ = getEnabledControllers(cgroupV2Root)
	}
	if len(controllers) > 0 {
		enableControllers(parentPath, controllers)
	}

	return &Cgroup{
		path: cgroupPath,
		name: name,
	}, nil
}

// LoadCgroup loads an existing cgroup
func LoadCgroup(name string) (*Cgroup, error) {
	cgroupPath := filepath.Join(cgroupV2Root, name)
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return nil, ErrCgroupNotFound
	}
	return &Cgroup{
		path: cgroupPath,
		name: name,
	}, nil
}

// Path returns the cgroup path
func (c *Cgroup) Path() string {
	return c.path
}

// AddProcess adds a process to the cgroup
func (c *Cgroup) AddProcess(pid int) error {
	return os.WriteFile(filepath.Join(c.path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)
}

// Apply applies the resource limits to the cgroup
func (c *Cgroup) Apply(resources *Resources) error {
	if resources == nil {
		return nil
	}

	if resources.Memory != nil {
		if err := c.applyMemory(resources.Memory); err != nil {
			return fmt.Errorf("apply memory: %w", err)
		}
	}

	if resources.CPU != nil {
		if err := c.applyCPU(resources.CPU); err != nil {
			return fmt.Errorf("apply cpu: %w", err)
		}
	}

	if resources.Pids != nil {
		if err := c.applyPids(resources.Pids); err != nil {
			return fmt.Errorf("apply pids: %w", err)
		}
	}

	if resources.IO != nil {
		if err := c.applyIO(resources.IO); err != nil {
			return fmt.Errorf("apply io: %w", err)
		}
	}

	return nil
}

func (c *Cgroup) applyMemory(mem *MemoryResources) error {
	if mem.Max != 0 {
		val := "max"
		if mem.Max > 0 {
			val = strconv.FormatInt(mem.Max, 10)
		}
		if err := c.writeFile("memory.max", val); err != nil {
			return err
		}
	}

	if mem.High != 0 {
		val := "max"
		if mem.High > 0 {
			val = strconv.FormatInt(mem.High, 10)
		}
		if err := c.writeFile("memory.high", val); err != nil {
			return err
		}
	}

	if mem.SwapMax != 0 {
		val := "max"
		if mem.SwapMax >= 0 {
			val = strconv.FormatInt(mem.SwapMax, 10)
		}
		if err := c.writeFile("memory.swap.max", val); err != nil {
			// Swap controller might not be enabled
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	return nil
}

func (c *Cgroup) applyCPU(cpu *CPUResources) error {
	if cpu.Quota != 0 || cpu.Period != 0 {
		quota := "max"
		if cpu.Quota > 0 {
			quota = strconv.FormatInt(cpu.Quota, 10)
		}
		period := uint64(100000) // default 100ms
		if cpu.Period > 0 {
			period = cpu.Period
		}
		val := fmt.Sprintf("%s %d", quota, period)
		if err := c.writeFile("cpu.max", val); err != nil {
			return err
		}
	}

	if cpu.Weight > 0 {
		if err := c.writeFile("cpu.weight", strconv.FormatUint(cpu.Weight, 10)); err != nil {
			return err
		}
	}

	if cpu.Cpus != "" {
		if err := c.writeFile("cpuset.cpus", cpu.Cpus); err != nil {
			// cpuset controller might not be enabled
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	if cpu.Mems != "" {
		if err := c.writeFile("cpuset.mems", cpu.Mems); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	return nil
}

func (c *Cgroup) applyPids(pids *PidsResources) error {
	if pids.Max != 0 {
		val := "max"
		if pids.Max > 0 {
			val = strconv.FormatInt(pids.Max, 10)
		}
		if err := c.writeFile("pids.max", val); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cgroup) applyIO(io *IOResources) error {
	if io.Weight > 0 {
		// io.weight format: "default <weight>" or "<major>:<minor> <weight>"
		if err := c.writeFile("io.weight", fmt.Sprintf("default %d", io.Weight)); err != nil {
			// io controller might not be enabled
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	if len(io.Max) > 0 {
		for device, limit := range io.Max {
			val := fmt.Sprintf("%s %s", device, limit)
			if err := c.writeFile("io.max", val); err != nil {
				if !os.IsNotExist(err) {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Cgroup) writeFile(name, value string) error {
	return os.WriteFile(filepath.Join(c.path, name), []byte(value), 0644)
}

// Delete removes the cgroup
// All processes must be moved out first
func (c *Cgroup) Delete() error {
	// First move all processes to parent cgroup
	procs, err := c.Processes()
	if err != nil {
		return err
	}

	if len(procs) > 0 {
		parentProcs := filepath.Join(filepath.Dir(c.path), "cgroup.procs")
		for _, pid := range procs {
			os.WriteFile(parentProcs, []byte(strconv.Itoa(pid)), 0644)
		}
	}

	return os.Remove(c.path)
}

// Processes returns the list of PIDs in the cgroup
func (c *Cgroup) Processes() ([]int, error) {
	f, err := os.Open(filepath.Join(c.path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pids []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pid, err := strconv.Atoi(scanner.Text())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, scanner.Err()
}

// Stat returns current resource usage statistics
type CgroupStats struct {
	Memory *MemoryStats
	CPU    *CPUStats
	Pids   *PidsStats
}

type MemoryStats struct {
	Current uint64 // Current memory usage in bytes
	Peak    uint64 // Peak memory usage in bytes
}

type CPUStats struct {
	UsageUsec uint64 // Total CPU time consumed in microseconds
}

type PidsStats struct {
	Current uint64 // Current number of processes
}

// Stats returns current resource usage
func (c *Cgroup) Stats() (*CgroupStats, error) {
	stats := &CgroupStats{}

	// Memory stats
	if current, err := c.readUint64("memory.current"); err == nil {
		if peak, err := c.readUint64("memory.peak"); err == nil {
			stats.Memory = &MemoryStats{
				Current: current,
				Peak:    peak,
			}
		}
	}

	// CPU stats
	if data, err := os.ReadFile(filepath.Join(c.path, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "usage_usec") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						stats.CPU = &CPUStats{UsageUsec: val}
					}
				}
				break
			}
		}
	}

	// Pids stats
	if current, err := c.readUint64("pids.current"); err == nil {
		stats.Pids = &PidsStats{Current: current}
	}

	return stats, nil
}

func (c *Cgroup) readUint64(name string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(c.path, name))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// DefaultResources returns a reasonable default resource configuration
func DefaultResources() *Resources {
	return &Resources{
		Pids: &PidsResources{
			Max: 1024, // Prevent fork bombs
		},
	}
}
