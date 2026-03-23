package container

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// NewConsoleSocketPair creates a socketpair for console fd passing.
// The caller keeps `parent` and passes `child` to Process.ConsoleSocket.
// After the container starts, call ReceiveConsole(parent) to get the master PTY fd.
func NewConsoleSocketPair() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "console-parent"),
		os.NewFile(uintptr(fds[1]), "console-child"), nil
}

// ReceiveConsole receives the master PTY fd from the container child
// over a console socketpair. Pass the parent end from NewConsoleSocketPair().
func ReceiveConsole(sock *os.File) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))

	_, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return nil, fmt.Errorf("recvmsg: %w", err)
	}

	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parse cmsg: %w", err)
	}

	for _, scm := range scms {
		fds, err := unix.ParseUnixRights(&scm)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return os.NewFile(uintptr(fds[0]), "console-master"), nil
		}
	}

	return nil, fmt.Errorf("no fd received from console socket")
}

// setupConsole allocates a PTY inside the container, sends the master fd
// to the parent via the console socket fd, and dups the slave to stdio.
//
// This must be called after pivot_root (so /dev/pts is the container's)
// and before exec.
func setupConsole(socketFd int, height, width uint) error {
	// Open PTY master.
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/ptmx: %w", err)
	}

	if err := unlockpt(master); err != nil {
		master.Close()
		return fmt.Errorf("unlockpt: %w", err)
	}

	slavePath, err := ptsname(master)
	if err != nil {
		master.Close()
		return fmt.Errorf("ptsname: %w", err)
	}

	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return fmt.Errorf("open slave %s: %w", slavePath, err)
	}

	// Set terminal size.
	if height > 0 || width > 0 {
		ws := unix.Winsize{Row: uint16(height), Col: uint16(width)}
		_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &ws)
	}

	// Send master fd to parent via SCM_RIGHTS.
	rights := unix.UnixRights(int(master.Fd()))
	if err := unix.Sendmsg(socketFd, []byte{0}, rights, nil, 0); err != nil {
		master.Close()
		slave.Close()
		return fmt.Errorf("sendmsg console fd: %w", err)
	}
	master.Close()

	// Session leader + controlling terminal.
	if _, err := unix.Setsid(); err != nil && err != unix.EPERM {
		slave.Close()
		return fmt.Errorf("setsid: %w", err)
	}
	if err := unix.IoctlSetInt(int(slave.Fd()), unix.TIOCSCTTY, 0); err != nil {
		slave.Close()
		return fmt.Errorf("TIOCSCTTY: %w", err)
	}

	// Dup slave to stdin/stdout/stderr.
	for _, fd := range []int{0, 1, 2} {
		if err := unix.Dup3(int(slave.Fd()), fd, 0); err != nil {
			slave.Close()
			return fmt.Errorf("dup3 fd %d: %w", fd, err)
		}
	}
	slave.Close()

	return nil
}

func ptsname(master *os.File) (string, error) {
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

func unlockpt(master *os.File) error {
	return unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0)
}
