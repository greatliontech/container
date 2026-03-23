package container

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// setupConsole allocates a PTY inside the container, sends the master fd
// to the parent via the console socket, and dups the slave to stdio.
// If height/width are non-zero, the terminal size is set.
//
// This must be called after pivot_root (so /dev/pts is the container's)
// and before exec.
func setupConsole(socketPath string, height, width uint) error {
	// Open PTY master.
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/ptmx: %w", err)
	}

	// Unlock slave.
	if err := unlockpt(master); err != nil {
		master.Close()
		return fmt.Errorf("unlockpt: %w", err)
	}

	// Get slave path.
	slavePath, err := ptsname(master)
	if err != nil {
		master.Close()
		return fmt.Errorf("ptsname: %w", err)
	}

	// Open slave.
	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return fmt.Errorf("open slave %s: %w", slavePath, err)
	}

	// Set terminal size if specified.
	if height > 0 || width > 0 {
		ws := unix.Winsize{Row: uint16(height), Col: uint16(width)}
		_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &ws)
	}

	// Send master fd to parent via console socket.
	if err := sendFd(socketPath, master); err != nil {
		master.Close()
		slave.Close()
		return fmt.Errorf("send console fd: %w", err)
	}
	master.Close()

	// Make this process the session leader and set controlling terminal.
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

// ReceiveConsole listens on a Unix socket and receives the master PTY fd
// from the container child. Returns the master as an *os.File.
func ReceiveConsole(socketPath string) (*os.File, error) {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socketPath, err)
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()

	uc := conn.(*net.UnixConn)
	f, err := uc.File()
	if err != nil {
		return nil, fmt.Errorf("conn file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))

	_, oobn, _, _, err := unix.Recvmsg(int(f.Fd()), buf, oob, 0)
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

// sendFd connects to a Unix socket and sends a file descriptor via SCM_RIGHTS.
func sendFd(socketPath string, f *os.File) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	uc := conn.(*net.UnixConn)
	ucf, err := uc.File()
	if err != nil {
		return err
	}
	defer ucf.Close()

	rights := unix.UnixRights(int(f.Fd()))
	return unix.Sendmsg(int(ucf.Fd()), []byte{0}, rights, nil, 0)
}

// ptsname returns the slave PTY path for a master fd.
func ptsname(master *os.File) (string, error) {
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

// unlockpt unlocks a slave PTY.
func unlockpt(master *os.File) error {
	return unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0)
}
