//go:build cgo

package container

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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

// startChild launches the child via the C constructor (pipes + sync protocol).
func (c *Container) startChild(subcommand string, p *Process, extraArgs []string, rp *readyPipes) (int, error) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("prctl child subreaper: %w", err)
	}

	// CGO-specific pipes: C config + sync socketpair.
	configR, configW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("config pipe: %w", err)
	}
	initR, initW, err := os.Pipe()
	if err != nil {
		configR.Close()
		configW.Close()
		return 0, fmt.Errorf("init pipe: %w", err)
	}
	syncParent, syncChild, err := newSyncSocketpair()
	if err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		return 0, fmt.Errorf("sync socketpair: %w", err)
	}

	args := []string{subcommand}
	args = append(args, extraArgs...)

	cmd := exec.Command("/proc/self/exe", args...)
	extraFiles := []*os.File{configR, syncChild, initR}
	fdOffset := 3 + len(extraFiles)
	env := append(os.Environ(),
		"_CONTAINER_MODE=setup",
		fmt.Sprintf("_CONTAINER_CONFIGFD=%d", 3+0),
		fmt.Sprintf("_CONTAINER_SYNCFD=%d", 3+1),
		fmt.Sprintf("_CONTAINER_INITFD=%d", 3+2),
	)

	// Shared: ready pipes + console socket.
	consoleParent, err := addChildPipes(&extraFiles, &env, fdOffset, p, rp)
	if err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		syncParent.Close()
		syncChild.Close()
		return 0, err
	}

	cmd.ExtraFiles = extraFiles
	cmd.Env = env

	closeCgroupFD, err := c.applyCgroupClone(cmd)
	if err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		syncParent.Close()
		syncChild.Close()
		return 0, err
	}
	defer closeCgroupFD()

	if err := c.setupStdio(cmd, p); err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		syncParent.Close()
		syncChild.Close()
		return 0, err
	}

	c.cmd = cmd

	if err := cmd.Start(); err != nil {
		configR.Close()
		configW.Close()
		initR.Close()
		initW.Close()
		syncParent.Close()
		syncChild.Close()
		return 0, fmt.Errorf("start child: %w", err)
	}

	configR.Close()
	syncChild.Close()
	initR.Close()

	// CGO-specific: write C config binary.
	cConfig := &nsenterCConfig{
		CloneFlags: uint32(c.cfg.Namespaces.CloneFlags()),
	}
	if c.cfg.Namespaces.NewUser && isSingleMapping(c.cfg.UidMappings, c.cfg.GidMappings) {
		cConfig.SelfMap = 1
		if len(c.cfg.UidMappings) > 0 {
			cConfig.UID = uint32(c.cfg.UidMappings[0].HostID)
		}
		if len(c.cfg.GidMappings) > 0 {
			cConfig.GID = uint32(c.cfg.GidMappings[0].HostID)
		}
	}
	joins := buildJoinSpecs(&c.cfg.Namespaces)
	cConfig.JoinCount = uint32(len(joins))

	if err := writeNsenterCConfig(configW, cConfig, joins); err != nil {
		configW.Close()
		initW.Close()
		syncParent.Close()
		return 0, fmt.Errorf("write C config: %w", err)
	}
	configW.Close()

	// Shared: write init data JSON + receive console.
	if err := c.finishChildStart(initW, p, consoleParent); err != nil {
		syncParent.Close()
		return 0, err
	}

	// CGO-specific: sync protocol.
	containerPid, err := runParentSync(syncParent, cmd.Process.Pid, &c.cfg)
	syncParent.Close()
	if err != nil {
		return 0, fmt.Errorf("sync protocol: %w", err)
	}

	return containerPid, nil
}

// ExecWithNsenter enters all namespaces of the target process and executes a command.
// With CGO, the C constructor handles namespace joining and exec.
func ExecWithNsenter(pid int, config ExecConfig) (*exec.Cmd, error) {
	return execReexec(pid, config)
}

// nsenterJoinHandler is a stub — the C constructor handles join mode
// entirely (setns + exec) and never returns to Go.
func nsenterJoinHandler() {}

// --- CGO-only helpers ---

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
	add(uint32(unix.CLONE_NEWCGROUP), ns.JoinCgroup)
	add(uint32(unix.CLONE_NEWTIME), ns.JoinTime)
	return specs
}

func isSingleMapping(uid, gid []syscall.SysProcIDMap) bool {
	return len(uid) == 1 && uid[0].Size == 1 &&
		len(gid) == 1 && gid[0].Size == 1
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

func runParentSync(conn *net.UnixConn, childPid int, cfg *Config) (int, error) {
	for {
		msg, err := readSyncMsg(conn)
		if err == io.EOF {
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

func writeUIDMapping(pid int, cfg *Config) error {
	setgroupsPath := fmt.Sprintf("/proc/%d/setgroups", pid)
	_ = os.WriteFile(setgroupsPath, []byte("deny"), 0600)

	uidMapPath := fmt.Sprintf("/proc/%d/uid_map", pid)
	var uidMap strings.Builder
	for _, m := range cfg.UidMappings {
		fmt.Fprintf(&uidMap, "%d %d %d\n", m.ContainerID, m.HostID, m.Size)
	}
	if err := os.WriteFile(uidMapPath, []byte(uidMap.String()), 0600); err != nil {
		return fmt.Errorf("write uid_map: %w", err)
	}

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

func newSyncSocketpair() (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "sync-parent")
	childFile := os.NewFile(uintptr(fds[1]), "sync-child")

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
