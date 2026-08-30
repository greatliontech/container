package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
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
	Memory *MemoryResources
	CPU    *CPUResources
	Pids   *PidsResources
	IO     *IOResources
	// Unified is a map of raw cgroup v2 key-value pairs to write directly.
	Unified map[string]string
}

// MemoryResources defines memory limits
type MemoryResources struct {
	// Max is the hard memory limit in bytes (memory.max)
	Max int64
	// High is the memory throttling threshold in bytes (memory.high)
	High int64
	// SwapMax is the swap limit in bytes (memory.swap.max)
	SwapMax int64
	// DisableOOMKiller enables group OOM killing (memory.oom.group)
	DisableOOMKiller bool
}

// CPUResources defines CPU limits
type CPUResources struct {
	Quota  int64  // CPU bandwidth quota in usecs (cpu.max)
	Period uint64 // CPU bandwidth period in usecs (cpu.max)
	Burst  uint64 // CPU burst limit in usecs (cpu.max.burst)
	Weight uint64 // CPU weight for fair scheduling (cpu.weight), 1-10000
	Cpus   string // CPUs to use (cpuset.cpus), e.g. "0-3"
	Mems   string // Memory nodes to use (cpuset.mems), e.g. "0-1"
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
		if err := os.WriteFile(subtreeControl, []byte("+"+c), 0o644); err != nil {
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

	// Create the cgroup directory; without privilege at the cgroup-fs
	// root, fall back to the caller's own delegated subtree (the
	// rootless case: systemd user sessions delegate a subtree under
	// user@.service, where mkdir is permitted).
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		if !errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("create cgroup: %w", err)
		}
		self, selfErr := selfCgroupDir()
		if selfErr != nil {
			return nil, fmt.Errorf("create cgroup: %w (and no delegated subtree: %v)", err, selfErr)
		}
		cgroupPath = filepath.Join(self, filepath.Base(name))
		if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
			return nil, fmt.Errorf("create cgroup in delegated subtree: %w", err)
		}
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

	return &Cgroup{path: cgroupPath}, nil
}

// LoadCgroup loads an existing cgroup
func LoadCgroup(name string) (*Cgroup, error) {
	cgroupPath := filepath.Join(cgroupV2Root, name)
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return nil, ErrCgroupNotFound
	}
	return &Cgroup{path: cgroupPath}, nil
}

// Path returns the cgroup path
func (c *Cgroup) Path() string {
	return c.path
}

// AddProcess adds a process to the cgroup
func (c *Cgroup) AddProcess(pid int) error {
	return os.WriteFile(filepath.Join(c.path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
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

	for key, val := range resources.Unified {
		if err := c.writeFile(key, val); err != nil {
			return fmt.Errorf("unified %s: %w", key, err)
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
			if !os.IsNotExist(err) {
				return err
			}
		}
	}

	if mem.DisableOOMKiller {
		if err := c.writeFile("memory.oom.group", "1"); err != nil {
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

	if cpu.Burst > 0 {
		if err := c.writeFile("cpu.max.burst", strconv.FormatUint(cpu.Burst, 10)); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
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
	return os.WriteFile(filepath.Join(c.path, name), []byte(value), 0o644)
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
			os.WriteFile(parentProcs, []byte(strconv.Itoa(pid)), 0o644)
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

// CgroupStats returns current resource usage statistics
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

// NotifyOOM returns a channel that receives a value when an OOM kill occurs
// in this cgroup. The channel is closed when the cgroup becomes empty
// (all processes exited) without OOM, or on error.
//
// Uses inotify to watch memory.events and cgroup.events (cgroups v2).
func (c *Cgroup) NotifyOOM() (<-chan struct{}, error) {
	fd, err := unix.InotifyInit()
	if err != nil {
		return nil, fmt.Errorf("inotify init: %w", err)
	}

	memEventsPath := filepath.Join(c.path, "memory.events")
	memWd, err := unix.InotifyAddWatch(fd, memEventsPath, unix.IN_MODIFY)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inotify watch memory.events: %w", err)
	}

	cgEventsPath := filepath.Join(c.path, "cgroup.events")
	cgWd, err := unix.InotifyAddWatch(fd, cgEventsPath, unix.IN_MODIFY)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inotify watch cgroup.events: %w", err)
	}

	ch := make(chan struct{})
	go func() {
		var buf [unix.SizeofInotifyEvent + unix.PathMax + 1]byte
		defer func() {
			unix.Close(fd)
			close(ch)
		}()

		for {
			n, err := unix.Read(fd, buf[:])
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if n < unix.SizeofInotifyEvent {
				return
			}

			var offset uint32
			for offset <= uint32(n-unix.SizeofInotifyEvent) {
				raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
				offset += unix.SizeofInotifyEvent + raw.Len

				if raw.Mask&unix.IN_MODIFY == 0 {
					continue
				}

				switch int(raw.Wd) {
				case memWd:
					if readCgroupKeyUint64(memEventsPath, "oom_kill") > 0 {
						ch <- struct{}{}
					}
				case cgWd:
					if readCgroupKeyUint64(cgEventsPath, "populated") == 0 {
						return
					}
				}
			}
		}
	}()
	return ch, nil
}

// readCgroupKeyUint64 reads a key-value pair from a cgroup file.
// Returns 0 on any error.
func readCgroupKeyUint64(path, key string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == key {
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			return val
		}
	}
	return 0
}

// DefaultResources returns a reasonable default resource configuration
func DefaultResources() *Resources {
	return &Resources{
		Pids: &PidsResources{
			Max: 1024, // Prevent fork bombs
		},
	}
}

// selfCgroupDir returns the calling process's cgroup directory — the
// root of whatever subtree is delegated to it.
func selfCgroupDir() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		// cgroup v2: "0::<path>"
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupV2Root, rest), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}
