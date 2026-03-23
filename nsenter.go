package container

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Sync protocol messages — must match C enum in nsenter.c.
const (
	syncUsermapReq byte = 0x01
	syncUsermapAck byte = 0x02
	syncChildPid   byte = 0x03
	syncReady      byte = 0x04
)

// nsenterCConfig is the binary config struct sent to the C constructor.
// Must match struct nsenter_config in nsenter.c (packed layout).
type nsenterCConfig struct {
	CloneFlags uint32
	SelfMap    uint8
	UID        uint32
	GID        uint32
	JoinCount  uint32
}

// nsJoinEntry is the binary header for a namespace join entry.
// Must match struct ns_join in nsenter.c (packed layout).
type nsJoinEntry struct {
	Flag    uint32
	PathLen uint32
}

// nsJoinSpec describes a namespace to join via setns.
type nsJoinSpec struct {
	Flag uint32
	Path string
}

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

// --- Config serialization ---

// writeNsenterCConfig writes the binary config for the C constructor.
func writeNsenterCConfig(w io.Writer, cfg *nsenterCConfig, joins []nsJoinSpec) error {
	if err := binary.Write(w, binary.LittleEndian, cfg); err != nil {
		return fmt.Errorf("write config header: %w", err)
	}
	for _, j := range joins {
		entry := nsJoinEntry{
			Flag:    j.Flag,
			PathLen: uint32(len(j.Path)),
		}
		if err := binary.Write(w, binary.LittleEndian, &entry); err != nil {
			return fmt.Errorf("write join entry: %w", err)
		}
		if _, err := w.Write([]byte(j.Path)); err != nil {
			return fmt.Errorf("write join path: %w", err)
		}
	}
	return nil
}

// buildJoinSpecs converts Namespaces join paths into nsJoinSpec entries.
func buildJoinSpecs(ns *Namespaces) []nsJoinSpec {
	var specs []nsJoinSpec
	add := func(flag uint32, path string) {
		if path != "" {
			specs = append(specs, nsJoinSpec{Flag: flag, Path: path})
		}
	}
	add(syscall.CLONE_NEWUSER, ns.JoinUser)
	add(syscall.CLONE_NEWNS, ns.JoinMnt)
	add(syscall.CLONE_NEWUTS, ns.JoinUTS)
	add(syscall.CLONE_NEWIPC, ns.JoinIPC)
	add(syscall.CLONE_NEWNET, ns.JoinNet)
	add(syscall.CLONE_NEWPID, ns.JoinPID)
	return specs
}

// --- Sync protocol ---

func readSyncMsg(conn *net.UnixConn) (byte, error) {
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n == 0 && err != nil {
		return 0, io.EOF
	}
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func readSyncPid(conn *net.UnixConn) (int, error) {
	var buf [4]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint32(buf[:])), nil
}

func writeSyncMsg(conn *net.UnixConn, msg byte) error {
	_, err := conn.Write([]byte{msg})
	return err
}

// runParentSync runs the sync protocol from the parent side.
// Returns the PID of the actual container process (grandchild if fork, child otherwise).
func runParentSync(conn *net.UnixConn, childPid int, cfg *Config) (int, error) {
	for {
		msg, err := readSyncMsg(conn)
		if err == io.EOF {
			// No sync messages — child is the container process.
			return childPid, nil
		}
		if err != nil {
			return 0, fmt.Errorf("sync read: %w", err)
		}

		switch msg {
		case syncUsermapReq:
			if err := writeUIDMapping(childPid, cfg); err != nil {
				return 0, err
			}
			if err := writeSyncMsg(conn, syncUsermapAck); err != nil {
				return 0, fmt.Errorf("sync write ack: %w", err)
			}

		case syncChildPid:
			pid, err := readSyncPid(conn)
			if err != nil {
				return 0, fmt.Errorf("read grandchild pid: %w", err)
			}
			if err := writeSyncMsg(conn, syncReady); err != nil {
				return 0, fmt.Errorf("sync write ready: %w", err)
			}
			return pid, nil

		default:
			return 0, fmt.Errorf("unexpected sync message: 0x%02x", msg)
		}
	}
}

// --- UID/GID mapping ---

// writeUIDMapping writes UID/GID mappings for a child process from the parent.
func writeUIDMapping(pid int, cfg *Config) error {
	// Deny setgroups by default (required for unprivileged gid_map writes,
	// safe default for privileged too).
	setgroupsPath := fmt.Sprintf("/proc/%d/setgroups", pid)
	_ = os.WriteFile(setgroupsPath, []byte("deny"), 0600)

	// Write uid_map.
	uidMapPath := fmt.Sprintf("/proc/%d/uid_map", pid)
	var uidMap strings.Builder
	for _, m := range cfg.UidMappings {
		fmt.Fprintf(&uidMap, "%d %d %d\n", m.ContainerID, m.HostID, m.Size)
	}
	if err := os.WriteFile(uidMapPath, []byte(uidMap.String()), 0600); err != nil {
		return fmt.Errorf("write uid_map: %w", err)
	}

	// Write gid_map.
	gidMapPath := fmt.Sprintf("/proc/%d/gid_map", pid)
	var gidMap strings.Builder
	for _, m := range cfg.GidMappings {
		fmt.Fprintf(&gidMap, "%d %d %d\n", m.ContainerID, m.HostID, m.Size)
	}
	if err := os.WriteFile(gidMapPath, []byte(gidMap.String()), 0600); err != nil {
		return fmt.Errorf("write gid_map: %w", err)
	}

	return nil
}

// --- Socketpair helper ---

// newSyncSocketpair creates a unix socketpair for the sync protocol.
// Returns (parent, child) connections.
func newSyncSocketpair() (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "sync-parent")
	childFile := os.NewFile(uintptr(fds[1]), "sync-child")

	// Clear CLOEXEC on child fd so it's inherited.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fds[1]), syscall.F_SETFD, 0); errno != 0 {
		parentFile.Close()
		childFile.Close()
		return nil, nil, fmt.Errorf("fcntl: %w", errno)
	}

	parentConn, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		childFile.Close()
		return nil, nil, fmt.Errorf("FileConn: %w", err)
	}

	return parentConn.(*net.UnixConn), childFile, nil
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

	p := data.Process

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

	os.Setenv("_CONTAINER_INSIDE", "1")

	// Strip __self from args so main() sees the original arguments.
	if len(os.Args) > 1 && os.Args[1] == "__self" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
}

// nsenterJoinHandler is the Go-side handler for __nsenter subcommand.
//
// With CGO: the C constructor already joined namespaces and exec'd — this
// function is never reached.
//
// Without CGO (pure Go): this handler joins safe namespaces (uts, ipc, net, pid)
// via setns, errors if user or mount namespace differs, then execs.
func nsenterJoinHandler() {
	if !builtinNsenter {
		// Pure Go path: join namespaces from Go.
		pidStr := os.Getenv("_CONTAINER_PID")
		if pidStr != "" {
			if err := joinNamespacesPureGo(pidStr); err != nil {
				fmt.Fprintf(os.Stderr, "nsenter: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Parse: __nsenter [--root=X] [--wd=X] -- cmd args...
	args := os.Args[2:]

	var root, wd string
	cmdStart := -1

	for i, arg := range args {
		if arg == "--" {
			cmdStart = i + 1
			break
		}
		if strings.HasPrefix(arg, "--root=") {
			root = strings.TrimPrefix(arg, "--root=")
		} else if strings.HasPrefix(arg, "--wd=") {
			wd = strings.TrimPrefix(arg, "--wd=")
		}
	}

	if cmdStart < 0 || cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "nsenter: no command specified\n")
		os.Exit(1)
	}

	if root != "" {
		if err := syscall.Chroot(root); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chroot %s: %v\n", root, err)
			os.Exit(1)
		}
		if err := syscall.Chdir("/"); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chdir /: %v\n", err)
			os.Exit(1)
		}
	}

	if wd != "" {
		if err := syscall.Chdir(wd); err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: chdir %s: %v\n", wd, err)
			os.Exit(1)
		}
	}

	cmdPath := args[cmdStart]
	cmdArgs := args[cmdStart:]
	env := os.Environ()

	if err := syscall.Exec(cmdPath, cmdArgs, env); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: exec %s: %v\n", cmdPath, err)
		os.Exit(1)
	}
}

// joinNamespacesPureGo joins namespaces that are safe from Go (uts, ipc, net, pid).
// Returns an error if the target's user or mount namespace differs from ours
// (these require single-threaded setns, which Go cannot provide).
func joinNamespacesPureGo(pidStr string) error {
	runtime.LockOSThread()

	// Check user namespace — must be the same (can't setns from multi-threaded Go).
	if nsDiffers(pidStr, "user") {
		return fmt.Errorf("cannot join user namespace without CGO (requires single-threaded setns)")
	}

	// Check mount namespace — must be the same.
	if nsDiffers(pidStr, "mnt") {
		return fmt.Errorf("cannot join mount namespace without CGO (requires single-threaded setns)")
	}

	// Join namespaces that are safe from Go.
	safeNs := []struct {
		name string
		flag int
	}{
		{"uts", unix.CLONE_NEWUTS},
		{"ipc", unix.CLONE_NEWIPC},
		{"net", unix.CLONE_NEWNET},
		{"pid", unix.CLONE_NEWPID},
	}

	for _, ns := range safeNs {
		if !nsDiffers(pidStr, ns.name) {
			continue
		}
		nsPath := fmt.Sprintf("/proc/%s/ns/%s", pidStr, ns.name)
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue // Namespace doesn't exist, skip.
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			return fmt.Errorf("setns %s: %w", ns.name, err)
		}
		unix.Close(fd)
	}

	return nil
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

// --- Shared setup ---

// containerSetup applies container configuration after namespace setup.
// This runs in the child process after namespaces have been created/joined.
func containerSetup(cfg *Config) error {
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("mount private: %w", err)
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

	if cfg.Capabilities != nil {
		if err := applyCapabilities(cfg.Capabilities); err != nil {
			return fmt.Errorf("capabilities: %w", err)
		}
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

// --- Helpers ---

func buildEnv(p *Process) []string {
	var env []string
	if p.InheritEnv {
		env = os.Environ()
	}
	if len(p.Env) > 0 {
		env = append(env, p.Env...)
	}
	return env
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
