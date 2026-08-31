//go:build !cgo

package container

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// startChild launches the child using SysProcAttr.Cloneflags (no CGO).
func (c *Container) startChild(subcommand string, p *Process, extraArgs []string, rp *readyPipes) (int, error) {
	if err := c.cfg.validate(); err != nil {
		return 0, err
	}
	// The create path applies namespaces via clone flags alone; without
	// the CGO constructor it cannot setns into existing namespaces. A
	// config naming joins would otherwise run silently unjoined.
	if c.cfg.Namespaces.hasJoins() {
		return 0, fmt.Errorf("joining existing namespaces at create requires CGO")
	}

	initR, initW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("init pipe: %w", err)
	}

	args := []string{subcommand}
	args = append(args, extraArgs...)

	cmd := exec.Command("/proc/self/exe", args...)
	extraFiles := []*os.File{initR}
	fdOffset := 3 + len(extraFiles)
	env := append(os.Environ(),
		fmt.Sprintf("_CONTAINER_INITFD=%d", 3+0),
	)

	// Shared: ready pipes + console socket.
	consoleParent, err := addChildPipes(&extraFiles, &env, fdOffset, p, rp)
	if err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}

	cmd.ExtraFiles = extraFiles
	cmd.Env = env

	// Pure Go: namespaces via clone flags at fork time.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  c.cfg.Namespaces.CloneFlags(),
		UidMappings: c.cfg.UidMappings,
		GidMappings: c.cfg.GidMappings,
	}
	closeCgroupFD, err := c.applyCgroupClone(cmd)
	if err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}
	defer closeCgroupFD()

	if err := c.setupStdio(cmd, p); err != nil {
		initR.Close()
		initW.Close()
		return 0, err
	}

	c.cmd = cmd

	if err := cmd.Start(); err != nil {
		initW.Close()
		return 0, fmt.Errorf("start child: %w", err)
	}

	initR.Close()

	// Shared: write init data JSON + receive console.
	if err := c.finishChildStart(initW, p, consoleParent); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}

// ExecWithNsenter enters namespaces of the target process and executes a command.
// Without CGO, returns an error if the target has a different user or mount
// namespace (these require single-threaded setns).
func ExecWithNsenter(pid int, config ExecConfig) (*exec.Cmd, error) {
	pidStr := fmt.Sprintf("%d", pid)
	if nsDiffers(pidStr, "user") {
		return nil, fmt.Errorf("cannot join user namespace without CGO (requires single-threaded setns)")
	}
	if nsDiffers(pidStr, "mnt") {
		return nil, fmt.Errorf("cannot join mount namespace without CGO (requires single-threaded setns)")
	}
	return execReexec(pid, config)
}

// nsenterJoinHandler joins safe namespaces from Go, then execs.
func nsenterJoinHandler() {
	joinedPid := false
	pidStr := os.Getenv("_CONTAINER_PID")
	if pidStr != "" {
		var err error
		joinedPid, err = joinNamespacesPureGo(pidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: %v\n", err)
			os.Exit(1)
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

	cmdPath := args[cmdStart]
	cmdArgs := args[cmdStart:]

	// Drop only the join-protocol variables this process was handed —
	// the inherited environment was already stripped by execReexec, and
	// a caller-supplied ExecConfig.Env passes through untouched.
	os.Unsetenv("_CONTAINER_MODE")
	os.Unsetenv("_CONTAINER_PID")
	env := os.Environ()

	if joinedPid {
		// The chroot happens in stage 2, on the payload side of the
		// spawn: the shim must keep the original root so its
		// /proc/self/exe re-exec stays resolvable — a chroot without
		// /proc mounted inside would break it. Mirrors the C shim,
		// where the fork precedes the chroot.
		runPayloadInPidNs(root, wd, cmdPath, cmdArgs, env)
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

	if err := syscall.Exec(cmdPath, cmdArgs, env); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: exec %s: %v\n", cmdPath, err)
		os.Exit(1)
	}
}

// joinNamespacesPureGo joins namespaces that are safe from Go (uts, ipc,
// net, pid, cgroup, time). Returns whether a pid namespace was joined —
// setns(CLONE_NEWPID) re-homes only future children, so the caller must
// fork before the payload runs. The calling goroutine stays locked to
// the setns'd thread; children created by that thread land in the joined
// namespaces.
func joinNamespacesPureGo(pidStr string) (joinedPid bool, err error) {
	runtime.LockOSThread()

	safeNs := []struct {
		name string
		flag int
	}{
		{"uts", unix.CLONE_NEWUTS},
		{"ipc", unix.CLONE_NEWIPC},
		{"net", unix.CLONE_NEWNET},
		{"pid", unix.CLONE_NEWPID},
		{"cgroup", unix.CLONE_NEWCGROUP},
		{"time", unix.CLONE_NEWTIME},
	}

	for _, ns := range safeNs {
		if !nsDiffers(pidStr, ns.name) {
			continue
		}
		nsPath := fmt.Sprintf("/proc/%s/ns/%s", pidStr, ns.name)
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			return joinedPid, fmt.Errorf("setns %s: %w", ns.name, err)
		}
		unix.Close(fd)
		if ns.flag == unix.CLONE_NEWPID {
			joinedPid = true
		}
	}

	return joinedPid, nil
}

// runPayloadInPidNs spawns the payload as a child of the current process
// and mirrors its exit; it never returns. A task joins a pid namespace
// only through fork — setns(CLONE_NEWPID) re-homes future children,
// never the caller — so the current process stays in its original pid
// namespace as a transparent shim: signals sent to it are forwarded to
// the payload, the payload's exit code becomes the shim's, and death by
// signal is re-raised so the caller observes the same wait status.
//
// The payload is spawned through a __nsexec stage of this same binary
// (see nsenterStage2Handler) so a parent-death signal can be armed
// inside the namespace; the shim's goroutine stays locked to the thread
// that called setns — children created by that thread land in the
// joined namespaces. root and wd are applied by stage 2, on the payload
// side.
func runPayloadInPidNs(root, wd, cmdPath string, cmdArgs, env []string) {
	// Subscribe before the payload exists: a signal landing in the
	// spawn window queues in sigc instead of taking its default
	// disposition, and is forwarded once the loop drains it.
	sigc := make(chan os.Signal, 64)
	signal.Notify(sigc)

	// Liveness pipe for stage 2's arming race; see nsenterStage2Handler.
	liveR, liveW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: liveness pipe: %v\n", err)
		os.Exit(1)
	}

	cmd := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: append([]string{"/proc/self/exe", "__nsexec",
			"--root=" + root, "--wd=" + wd, cmdPath, "--"}, cmdArgs...),
		Env:        env,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{liveR},
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: start payload: %v\n", err)
		os.Exit(1)
	}
	liveR.Close()

	go func() {
		for s := range sigc {
			sig, ok := s.(syscall.Signal)
			if !ok || sig == syscall.SIGCHLD {
				continue
			}
			_ = cmd.Process.Signal(sig)
			switch sig {
			case syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
				// Mirror the stop so waiters see the shim stopped
				// too; the eventual SIGCONT resumes the shim first
				// and is then forwarded by this loop.
				_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
			}
		}
	}()

	_ = cmd.Wait()
	// Last use of liveW, deliberately this late: keeping the *os.File
	// reachable for the payload's whole lifetime is what holds its EOF
	// signal back — the os.File finalizer would otherwise close the
	// write end as soon as the GC noticed it was dead, and stage 2
	// would read EOF and abort the payload.
	liveW.Close()
	if cmd.ProcessState == nil {
		os.Exit(1)
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		os.Exit(1)
	}
	if ws.Signaled() {
		sig := ws.Signal()
		signal.Reset(sig)
		_ = syscall.Kill(syscall.Getpid(), sig)
		// Non-fatal default disposition, or delivery raced: 128+sig.
		os.Exit(128 + int(sig))
	}
	os.Exit(ws.ExitStatus())
}

// nsenterStage2Handler runs inside the joined pid namespace, between
// the shim and the payload: it arms PR_SET_PDEATHSIG so the payload
// cannot outlive the shim, applies the chroot/workdir, then execs the
// payload. The shim cannot arm the signal via SysProcAttr.Pdeathsig —
// Go's implementation makes the child re-check getppid() against the
// pre-fork parent pid and kill itself on mismatch, and getppid() across
// a pid-namespace boundary is always 0. fd 3 is the shim's liveness
// pipe: EOF there means the shim died before the prctl armed, so exit
// rather than run unsupervised.
//
// Two dependencies worth stating: pdeath_signal is per-thread, so the
// prctl and the exec must run on one thread — guaranteed because the
// runtime holds LockOSThread across package initializers, where this
// handler runs; and the kernel clears pdeath_signal across exec of a
// set-uid/set-gid/file-capability binary, so the orphan backstop does
// not cover such payloads (the C shim shares this limit).
//
// Invoked as: /proc/self/exe __nsexec --root=<r> --wd=<w> <path> -- <argv...>.
func nsenterStage2Handler() {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: prctl PDEATHSIG: %v\n", err)
		os.Exit(1)
	}
	if err := unix.SetNonblock(3, true); err == nil {
		var b [1]byte
		if n, err := unix.Read(3, b[:]); n == 0 && err == nil {
			os.Exit(1) // EOF: shim already gone.
		}
	}
	unix.Close(3)

	if len(os.Args) < 7 || os.Args[5] != "--" ||
		!strings.HasPrefix(os.Args[2], "--root=") || !strings.HasPrefix(os.Args[3], "--wd=") {
		fmt.Fprintf(os.Stderr, "nsenter: malformed __nsexec args\n")
		os.Exit(1)
	}
	root := strings.TrimPrefix(os.Args[2], "--root=")
	wd := strings.TrimPrefix(os.Args[3], "--wd=")
	path := os.Args[4]
	argv := os.Args[6:]

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

	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nsenter: exec %s: %v\n", path, err)
		os.Exit(1)
	}
}
