package container

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// initData is the JSON payload sent over the init pipe to the Go child handler.
type initData struct {
	Config  Config   `json:"config"`
	Process *Process `json:"process,omitempty"`
}

// InContainer returns true if the current process is running inside
// a container created via SelfContainerize or RunSelf.
func InContainer() bool {
	return os.Getenv("_CONTAINER_INSIDE") == "1"
}

// --- Child handlers ---

// nsenterCreateHandler is the Go-side handler for __container subcommand.
// It reads config from the init pipe, applies container setup, and execs the target.
func nsenterCreateHandler() {
	fd := getenvFd("_CONTAINER_INITFD")
	f := os.NewFile(uintptr(fd), "init-pipe")
	defer f.Close()

	var data initData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: decode init data: %v\n", err)
		os.Exit(1)
	}

	if err := containerSetup(&data.Config); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: container setup: %v\n", err)
		os.Exit(1)
	}

	if data.Process == nil {
		fmt.Fprintf(os.Stderr, "nsenter: no process in init data\n")
		os.Exit(1)
	}

	// Console/PTY — allocate after pivot_root (uses container's /dev/pts).
	// Console socket fd is passed via _CONTAINER_CONSOLEFD env var.
	if consoleFdStr := os.Getenv("_CONTAINER_CONSOLEFD"); consoleFdStr != "" {
		consoleFd := getenvFd("_CONTAINER_CONSOLEFD")
		var h, w uint
		if data.Process != nil {
			h, w = data.Process.ConsoleHeight, data.Process.ConsoleWidth
		}
		if err := setupConsole(consoleFd, h, w); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: console setup: %v\n", err)
			os.Exit(1)
		}
	}

	// Create/Start separation: signal "setup done", then block until Start().
	if statusFdStr := os.Getenv("_CONTAINER_STATUSFD"); statusFdStr != "" {
		statusFd := getenvFd("_CONTAINER_STATUSFD")
		readyFd := getenvFd("_CONTAINER_READYFD")

		statusF := os.NewFile(uintptr(statusFd), "status-pipe")
		readyF := os.NewFile(uintptr(readyFd), "ready-pipe")

		// Tell parent: "setup done".
		if _, err := statusF.Write([]byte{0}); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: write status: %v\n", err)
			os.Exit(1)
		}
		statusF.Close()

		// Block until parent calls Start().
		var buf [1]byte
		if _, err := readyF.Read(buf[:]); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: read ready: %v\n", err)
			os.Exit(1)
		}
		readyF.Close()
	}

	p := data.Process

	if p.Umask != nil {
		syscall.Umask(int(*p.Umask))
	}

	if p.WorkDir != "" {
		if err := syscall.Chdir(p.WorkDir); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chdir %s: %v\n", p.WorkDir, err)
			os.Exit(1)
		}
	}

	env := buildEnv(p)
	cmd := p.Cmd
	if !filepath.IsAbs(cmd) {
		resolved, err := lookPath(cmd, env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: lookpath %s: %v\n", cmd, err)
			os.Exit(1)
		}
		cmd = resolved
	}

	if err := syscall.Exec(cmd, append([]string{p.Cmd}, p.Args...), env); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: exec %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// nsenterSelfHandler is the Go-side handler for __self subcommand.
// It reads config from the init pipe, applies container setup, then returns
// to main() so the caller's code continues running as PID 1.
func nsenterSelfHandler() {
	fd := getenvFd("_CONTAINER_INITFD")
	f := os.NewFile(uintptr(fd), "init-pipe")

	var data initData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "nsenter: decode init data: %v\n", err)
		os.Exit(1)
	}
	f.Close()

	if err := containerSetup(&data.Config); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: container setup: %v\n", err)
		os.Exit(1)
	}

	// The caller's code continues in this process: scrub the internal
	// control-protocol variables so neither it nor its children see them.
	unsetInternalEnv()
	os.Setenv("_CONTAINER_INSIDE", "1")

	// Strip __self from args so main() sees the original arguments.
	if len(os.Args) > 1 && os.Args[1] == "__self" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
}

// --- Shared setup ---

// containerSetup applies container configuration after namespace setup.
// This runs in the child process after namespaces have been created/joined.
//
// Order matters:
//  1. Mounts and sysctl (need host /proc before pivot_root)
//  2. pivot_root / chroot
//  3. Masked and readonly paths (after pivot_root, paths are container-relative)
//  4. Capabilities and rlimits
//  5. Seccomp (last — may block capability/rlimit syscalls)
func containerSetup(cfg *Config) error {
	// OOM score adjustment — must happen before capabilities are dropped
	// and before PR_SET_DUMPABLE is cleared.
	if cfg.OOMScoreAdj != nil {
		if err := os.WriteFile("/proc/self/oom_score_adj", []byte(fmt.Sprintf("%d", *cfg.OOMScoreAdj)), 0644); err != nil {
			return fmt.Errorf("oom_score_adj: %w", err)
		}
	}

	// Mount propagation is namespace-scoped state: touch it only when the
	// container has its own (new or joined) mount namespace — otherwise
	// the change would apply to the host's mount namespace.
	if cfg.Namespaces.NewMnt || cfg.Namespaces.JoinMnt != "" {
		propagation := unix.MS_PRIVATE | unix.MS_REC
		switch cfg.RootfsPropagation {
		case "slave", "rslave":
			propagation = unix.MS_SLAVE | unix.MS_REC
		case "shared", "rshared":
			propagation = unix.MS_SHARED | unix.MS_REC
		}
		if err := unix.Mount("", "/", "", uintptr(propagation), ""); err != nil {
			return fmt.Errorf("mount propagation: %w", err)
		}
	}

	for _, m := range cfg.Mounts {
		if err := syscall.Mount(m.Source, m.Target, m.Type, m.Flags, m.Data); err != nil {
			return fmt.Errorf("mount %s -> %s: %w", m.Source, m.Target, err)
		}
	}

	if cfg.Hostname != "" {
		if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
			return fmt.Errorf("sethostname: %w", err)
		}
	}

	if cfg.Domainname != "" {
		if err := unix.Setdomainname([]byte(cfg.Domainname)); err != nil {
			return fmt.Errorf("setdomainname: %w", err)
		}
	}

	// Sysctl before pivot_root — needs host /proc/sys.
	if err := applySysctl(cfg.Sysctl); err != nil {
		return fmt.Errorf("sysctl: %w", err)
	}

	if cfg.SetupDev {
		if err := setupDev(cfg.Root, cfg.Devices); err != nil {
			return fmt.Errorf("setup dev: %w", err)
		}
	}

	if cfg.Root != "" {
		if cfg.UsePivotRoot {
			if err := pivotRoot(cfg.Root); err != nil {
				return fmt.Errorf("pivot_root: %w", err)
			}
		} else {
			if err := syscall.Chroot(cfg.Root); err != nil {
				return fmt.Errorf("chroot: %w", err)
			}
			if err := syscall.Chdir("/"); err != nil {
				return fmt.Errorf("chdir: %w", err)
			}
		}
	}

	if cfg.ReadonlyRoot {
		if err := unix.Mount("", "/", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC|lockedMountFlags("/"), ""); err != nil {
			return fmt.Errorf("readonly root: %w", err)
		}
	}

	// Masked and readonly paths after pivot_root (paths are now container-relative).
	if err := applyMaskPaths(cfg.MaskPaths); err != nil {
		return fmt.Errorf("mask paths: %w", err)
	}
	if err := applyReadonlyPaths(cfg.ReadonlyPaths); err != nil {
		return fmt.Errorf("readonly paths: %w", err)
	}

	if cfg.Capabilities != nil {
		if err := applyCapabilities(cfg.Capabilities); err != nil {
			return fmt.Errorf("capabilities: %w", err)
		}
	}

	if err := applyRlimits(cfg.Rlimits); err != nil {
		return fmt.Errorf("rlimits: %w", err)
	}

	if cfg.NoNewPrivileges && cfg.Seccomp == nil {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("no_new_privs: %w", err)
		}
	}

	if cfg.Seccomp != nil {
		if err := applySeccomp(cfg.Seccomp); err != nil {
			return fmt.Errorf("seccomp: %w", err)
		}
	}

	return nil
}

// applySysctl writes kernel parameters to /proc/sys.
func applySysctl(params map[string]string) error {
	for key, value := range params {
		path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

// applyRlimits sets POSIX resource limits.
func applyRlimits(limits []Rlimit) error {
	for _, rl := range limits {
		if err := unix.Setrlimit(rl.Type, &unix.Rlimit{
			Cur: rl.Soft,
			Max: rl.Hard,
		}); err != nil {
			return fmt.Errorf("setrlimit type %d: %w", rl.Type, err)
		}
	}
	return nil
}

// applyMaskPaths masks paths by bind-mounting /dev/null (files) or
// a read-only tmpfs (directories) over them.
func applyMaskPaths(paths []string) error {
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue // Path doesn't exist, skip.
		}
		if fi.IsDir() {
			if err := unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY, ""); err != nil {
				continue // Best-effort.
			}
		} else {
			if err := unix.Mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
				continue // Best-effort.
			}
		}
	}
	return nil
}

// applyReadonlyPaths remounts paths as read-only. A path that does
// not exist is skipped — the config lists paths to protect where
// present — but a path that exists and cannot be made read-only fails
// the run: silently leaving a configured path writable would report
// an isolation the container does not have.
func applyReadonlyPaths(paths []string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue // Path doesn't exist, skip.
		}
		// Bind mount to self.
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("readonly path %s: self-bind: %w", p, err)
		}
		// Remount as readonly.
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC|lockedMountFlags(p), ""); err != nil {
			return fmt.Errorf("readonly path %s: remount: %w", p, err)
		}
	}
	return nil
}

// --- Helpers ---

func buildEnv(p *Process) []string {
	var env []string
	if p.InheritEnv {
		env = stripInternalEnv(os.Environ())
	}
	if len(p.Env) > 0 {
		env = append(env, p.Env...)
	}
	return env
}

// unsetInternalEnv removes the library's internal control-protocol
// variables from the current process environment; _CONTAINER_INSIDE
// stays, as the public in-container marker read by InContainer.
func unsetInternalEnv() {
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(name, "_CONTAINER_") && name != "_CONTAINER_INSIDE" {
			os.Unsetenv(name)
		}
	}
}

// stripInternalEnv removes the library's internal control-protocol
// variables (_CONTAINER_*) from env so they never leak into a payload's
// environment. _CONTAINER_INSIDE stays: it is the public in-container
// marker read by InContainer.
func stripInternalEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "_CONTAINER_") && !strings.HasPrefix(kv, "_CONTAINER_INSIDE=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func getenvFd(name string) int {
	val := os.Getenv(name)
	if val == "" {
		fmt.Fprintf(os.Stderr, "nsenter: %s not set\n", name)
		os.Exit(1)
	}
	var fd int
	if _, err := fmt.Sscanf(val, "%d", &fd); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: invalid %s: %s\n", name, val)
		os.Exit(1)
	}
	return fd
}

// nsDiffers returns true if the target process is in a different namespace.
func nsDiffers(pidStr, nsName string) bool {
	selfPath := fmt.Sprintf("/proc/self/ns/%s", nsName)
	targetPath := fmt.Sprintf("/proc/%s/ns/%s", pidStr, nsName)

	selfLink, err1 := os.Readlink(selfPath)
	targetLink, err2 := os.Readlink(targetPath)
	if err1 != nil || err2 != nil {
		return false
	}
	return selfLink != targetLink
}

// lockedMountFlags returns the mount flags a read-only remount of path
// must repeat inside a user namespace: the kernel locks a mount's
// nosuid/nodev/noexec and atime attributes when the namespace cannot
// see their origin, and a remount that drops a locked flag fails with
// EPERM. Reading them from statfs keeps the remount faithful to
// whatever the host mounted. statfs exposes no strictatime bit, so a
// mount locked strictatime is the one case this cannot repeat: its
// remount still fails cleanly with EPERM rather than weakening the
// lock.
func lockedMountFlags(path string) uintptr {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return 0
	}
	var flags uintptr
	if sfs.Flags&unix.ST_NOSUID != 0 {
		flags |= unix.MS_NOSUID
	}
	if sfs.Flags&unix.ST_NODEV != 0 {
		flags |= unix.MS_NODEV
	}
	if sfs.Flags&unix.ST_NOEXEC != 0 {
		flags |= unix.MS_NOEXEC
	}
	if sfs.Flags&unix.ST_NOATIME != 0 {
		flags |= unix.MS_NOATIME
	}
	if sfs.Flags&unix.ST_NODIRATIME != 0 {
		flags |= unix.MS_NODIRATIME
	}
	if sfs.Flags&unix.ST_RELATIME != 0 {
		flags |= unix.MS_RELATIME
	}
	return flags
}

// applyCgroupClone creates the container's cgroup up front and makes
// cmd clone directly into it (CLONE_INTO_CGROUP): bounds hold from
// the first instruction and no post-start migration is needed —
// rootless setups cannot migrate across the delegation boundary
// anyway. Both start paths call it immediately before Start.
func (c *Container) applyCgroupClone(cmd *exec.Cmd) (closeFD func(), err error) {
	fd, err := c.preStartCgroup()
	if err != nil {
		if c.cfg.CgroupsRequired {
			return nil, err
		}
		slog.Warn("failed to create cgroup, running without resource limits", "error", err)
		return func() {}, nil
	}
	if fd < 0 {
		return func() {}, nil
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = fd
	return func() { syscall.Close(fd) }, nil
}
