#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Clone flags not always available in older headers. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

/* Sync protocol messages — must match Go constants. */
enum {
	SYNC_USERMAP_REQ = 0x01,
	SYNC_USERMAP_ACK = 0x02,
	SYNC_CHILD_PID   = 0x03,
	SYNC_READY       = 0x04,
};

/*
 * Config struct read from pipe. Packed to match Go's binary.Write layout.
 * Must match nsenterCConfig in nsenter.go.
 */
struct __attribute__((packed)) nsenter_config {
	uint32_t clone_flags;
	uint8_t  self_map;
	uint32_t uid;
	uint32_t gid;
	uint32_t join_count;
};

/* Join entry header. Packed to match Go's binary.Write layout. */
struct __attribute__((packed)) ns_join {
	uint32_t flag;
	uint32_t path_len;
};

static void bail(const char *msg)
{
	fprintf(stderr, "nsenter: %s: %s\n", msg, strerror(errno));
	_exit(1);
}

static void bail_msg(const char *msg)
{
	fprintf(stderr, "nsenter: %s\n", msg);
	_exit(1);
}

static int getenv_fd(const char *name)
{
	const char *val = getenv(name);
	if (!val)
		return -1;
	return atoi(val);
}

static void read_exact(int fd, void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = read(fd, (char *)buf + done, n - done);
		if (r <= 0)
			bail("read pipe");
		done += r;
	}
}

static void write_file(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		bail(path);
	ssize_t len = (ssize_t)strlen(data);
	if (write(fd, data, len) != len) {
		close(fd);
		bail(path);
	}
	close(fd);
}

static void sync_write_byte(int fd, uint8_t msg)
{
	if (write(fd, &msg, 1) != 1)
		bail("sync write");
}

static void sync_write_pid(int fd, pid_t pid)
{
	uint8_t buf[5];
	buf[0] = SYNC_CHILD_PID;
	memcpy(buf + 1, &pid, sizeof(uint32_t));
	if (write(fd, buf, 5) != 5)
		bail("sync write pid");
}

static uint8_t sync_read_byte(int fd)
{
	uint8_t msg;
	ssize_t n = read(fd, &msg, 1);
	if (n != 1)
		bail("sync read");
	return msg;
}

static volatile pid_t pidns_payload = -1;

static void forward_to_payload(int sig)
{
	if (pidns_payload > 0)
		kill(pidns_payload, sig);
	/*
	 * Stop signals are forwarded and then mirrored: without the
	 * self-stop, the payload would sit stopped while the shim stayed
	 * runnable and no WUNTRACED waiter would ever see a stop.
	 * SIGCONT resumes the shim before its handler runs, so the
	 * matching continue is forwarded on the way back up.
	 */
	if (sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
		raise(SIGSTOP);
}

/*
 * fork_into_pidns forks so the child becomes a member of the pid
 * namespace installed by a preceding setns(CLONE_NEWPID): setns only
 * re-homes future children, never the caller. Returns in the child
 * (the payload). The parent stays behind as a transparent shim in its
 * original pid namespace: it forwards signals to the payload, then
 * mirrors the payload's exit — same code, or death by the same signal.
 */
static void fork_into_pidns(void)
{
	/*
	 * Block catchable signals across the fork: neither side may take a
	 * default disposition before the shim's forwarding and the
	 * payload's PDEATHSIG are armed. The child restores the mask
	 * before returning — execve preserves it.
	 */
	sigset_t all, old;
	sigfillset(&all);
	sigprocmask(SIG_SETMASK, &all, &old);

	/*
	 * Liveness pipe: PR_SET_PDEATHSIG only helps once armed. The child
	 * checks the read end after the prctl — EOF means the shim died
	 * inside the window, so exit rather than run unsupervised.
	 */
	int live[2];
	if (pipe2(live, O_CLOEXEC) < 0)
		bail("pipe2");

	pid_t child = fork();
	if (child < 0)
		bail("fork into pid ns");

	if (child == 0) {
		close(live[1]); /* Only the shim may hold the write end. */
		/*
		 * The kernel clears pdeath_signal across exec of a set-uid,
		 * set-gid, or file-capability binary; the orphan backstop
		 * does not cover such payloads.
		 */
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0)
			bail("prctl PDEATHSIG");
		if (fcntl(live[0], F_SETFL, O_NONBLOCK) == 0) {
			char b;
			if (read(live[0], &b, 1) == 0)
				_exit(1); /* EOF: shim already gone. */
		}
		close(live[0]);
		sigprocmask(SIG_SETMASK, &old, NULL);
		return;
	}

	close(live[0]);
	pidns_payload = child;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = forward_to_payload;
	sigemptyset(&sa.sa_mask);
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP || sig == SIGCHLD)
			continue;
		sigaction(sig, &sa, NULL); /* Best-effort. */
	}
	sigprocmask(SIG_SETMASK, &old, NULL);

	int status;
	for (;;) {
		pid_t w = waitpid(child, &status, 0);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			bail("waitpid payload");
		}
		break;
	}

	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		signal(sig, SIG_DFL);
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, sig);
		sigprocmask(SIG_UNBLOCK, &set, NULL);
		raise(sig);
		/* Non-fatal default disposition: fall back to 128+sig. */
		_exit(128 + sig);
	}
	_exit(WEXITSTATUS(status));
}

/*
 * do_join enters existing namespaces of a target process and execs the
 * target command. This function NEVER returns — it either execs or exits.
 *
 * This must be done entirely in C because:
 * - setns(CLONE_NEWNS) requires single-threaded (Go runtime is multi-threaded)
 * - After joining mount namespace, /proc shows container's PID view,
 *   which breaks Go runtime startup (pthread_create fails)
 *
 * All namespace fds are opened BEFORE any setns() call, since joining
 * mount namespace changes /proc visibility.
 *
 * Args are read from /proc/self/cmdline:
 *   __nsenter [--root=X] [--wd=X] -- cmd [args...]
 */
static void do_join(void)
{
	const char *pid_str = getenv("_CONTAINER_PID");
	if (!pid_str)
		bail_msg("_CONTAINER_PID not set");

	/*
	 * Phase 0: Parse command-line args from /proc/self/cmdline.
	 * Must be done before joining mount namespace (host /proc needed).
	 */
	static char cmdline[262144];
	int cmdline_fd = open("/proc/self/cmdline", O_RDONLY);
	if (cmdline_fd < 0)
		bail("open /proc/self/cmdline");
	ssize_t cmdline_len = 0;
	for (;;) {
		ssize_t r = read(cmdline_fd, cmdline + cmdline_len,
				 sizeof(cmdline) - (size_t)cmdline_len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			bail("read cmdline");
		}
		if (r == 0)
			break;
		cmdline_len += r;
		/* A full buffer with more to come would exec truncated args. */
		if ((size_t)cmdline_len == sizeof(cmdline))
			bail_msg("command line too long");
	}
	close(cmdline_fd);
	if (cmdline_len <= 0)
		bail_msg("empty cmdline");
	cmdline[cmdline_len] = '\0';

	char *argv_all[4096];
	int argc = 0;
	char *p = cmdline;
	while (p < cmdline + cmdline_len) {
		if (argc >= (int)(sizeof(argv_all) / sizeof(argv_all[0])) - 1)
			bail_msg("too many arguments");
		argv_all[argc++] = p;
		p += strlen(p) + 1;
	}
	argv_all[argc] = NULL;

	/* Find "--" separator and parse --root/--wd flags. */
	const char *root = NULL, *wd = NULL;
	int cmd_start = -1;
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv_all[i], "--") == 0) {
			cmd_start = i + 1;
			break;
		}
		if (strncmp(argv_all[i], "--root=", 7) == 0)
			root = argv_all[i] + 7;
		else if (strncmp(argv_all[i], "--wd=", 5) == 0)
			wd = argv_all[i] + 5;
	}
	if (cmd_start < 0 || cmd_start >= argc)
		bail_msg("no command after -- in __nsenter args");

	char **exec_argv = &argv_all[cmd_start];

	/*
	 * Phase 1: Open all namespace fds while /proc is still the host's.
	 * Skip any namespace that is the same as ours — joining a namespace
	 * we're already in after setns(CLONE_NEWUSER) would fail with EPERM
	 * because we lose capabilities in the parent user namespace.
	 */
	char path[4096];
	struct {
		const char *name;
		int flag;
		int fd;
	} ns[] = {
		{ "user",   CLONE_NEWUSER,   -1 },
		{ "mnt",    CLONE_NEWNS,     -1 },
		{ "uts",    CLONE_NEWUTS,    -1 },
		{ "ipc",    CLONE_NEWIPC,    -1 },
		{ "net",    CLONE_NEWNET,    -1 },
		{ "pid",    CLONE_NEWPID,    -1 },
		{ "cgroup", CLONE_NEWCGROUP, -1 },
		{ "time",   CLONE_NEWTIME,   -1 },
	};
	int ns_count = (int)(sizeof(ns) / sizeof(ns[0]));

	for (int i = 0; i < ns_count; i++) {
		/* Open target namespace. */
		snprintf(path, sizeof(path), "/proc/%s/ns/%s",
			 pid_str, ns[i].name);
		int target_fd = open(path, O_RDONLY | O_CLOEXEC);
		if (target_fd < 0)
			continue;

		/* Open our own namespace and compare inodes — skip if same. */
		snprintf(path, sizeof(path), "/proc/self/ns/%s", ns[i].name);
		int self_fd = open(path, O_RDONLY | O_CLOEXEC);
		if (self_fd >= 0) {
			struct stat self_st, target_st;
			if (fstat(self_fd, &self_st) == 0 &&
			    fstat(target_fd, &target_st) == 0 &&
			    self_st.st_ino == target_st.st_ino) {
				close(self_fd);
				close(target_fd);
				continue; /* Same namespace, skip. */
			}
			close(self_fd);
		}

		ns[i].fd = target_fd;
	}

	/*
	 * Phase 2: setns into each namespace. User first for capabilities.
	 */
	int joined_pid = 0;
	for (int i = 0; i < ns_count; i++) {
		if (ns[i].fd < 0)
			continue;
		if (setns(ns[i].fd, ns[i].flag) < 0) {
			char msg[64];
			snprintf(msg, sizeof(msg), "setns %s", ns[i].name);
			bail(msg);
		}
		close(ns[i].fd);
		if (ns[i].flag == CLONE_NEWPID)
			joined_pid = 1;
	}

	/*
	 * The control-protocol variables must not leak into the payload's
	 * environment; do_join execs without returning to the constructor's
	 * cleanup.
	 */
	unsetenv("_CONTAINER_MODE");
	unsetenv("_CONTAINER_PID");

	if (joined_pid)
		fork_into_pidns();

	/*
	 * Phase 3: chroot/chdir and exec. Never returns.
	 */
	if (root && root[0]) {
		if (chroot(root) < 0)
			bail("chroot");
		if (chdir("/") < 0)
			bail("chdir");
	}
	if (wd && wd[0]) {
		if (chdir(wd) < 0)
			bail("chdir wd");
	}

	execvp(exec_argv[0], exec_argv);
	bail("exec");
}

/*
 * do_setup creates new namespaces and optionally forks for PID namespace.
 * Used for container creation and self-containerization.
 */
static void do_setup(void)
{
	int configfd = getenv_fd("_CONTAINER_CONFIGFD");
	int syncfd = getenv_fd("_CONTAINER_SYNCFD");
	if (configfd < 0)
		bail_msg("_CONTAINER_CONFIGFD not set");
	if (syncfd < 0)
		bail_msg("_CONTAINER_SYNCFD not set");

	/* Read config header. */
	struct nsenter_config config;
	read_exact(configfd, &config, sizeof(config));

	/* Read join entries (shared namespaces to enter). */
	uint32_t join_count = config.join_count;
	uint32_t *join_flags = NULL;
	char (*join_paths)[4096] = NULL;

	if (join_count > 0) {
		join_flags = malloc(join_count * sizeof(uint32_t));
		join_paths = malloc(join_count * sizeof(*join_paths));
		if (!join_flags || !join_paths) {
			free(join_flags);
			free(join_paths);
			bail("malloc");
		}
		for (uint32_t i = 0; i < join_count; i++) {
			struct ns_join entry;
			read_exact(configfd, &entry, sizeof(entry));
			join_flags[i] = entry.flag;
			if (entry.path_len >= 4095) {
				free(join_flags);
				free(join_paths);
				bail_msg("ns path too long");
			}
			read_exact(configfd, join_paths[i], entry.path_len);
			join_paths[i][entry.path_len] = '\0';
		}
	}
	close(configfd);

	/* --- User namespace --- */
	if (config.clone_flags & CLONE_NEWUSER) {
		if (unshare(CLONE_NEWUSER) < 0)
			bail("unshare CLONE_NEWUSER");

		if (config.self_map) {
			/*
			 * Rootless: self-write single-range maps.
			 * Must write "deny" to setgroups before gid_map.
			 */
			char map[64];
			write_file("/proc/self/setgroups", "deny");
			snprintf(map, sizeof(map), "0 %u 1\n", config.uid);
			write_file("/proc/self/uid_map", map);
			snprintf(map, sizeof(map), "0 %u 1\n", config.gid);
			write_file("/proc/self/gid_map", map);
		} else {
			/*
			 * Privileged: parent writes multi-range maps.
			 * Set dumpable so parent can access /proc/self/*.
			 */
			if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
				bail("prctl SET_DUMPABLE");
			sync_write_byte(syncfd, SYNC_USERMAP_REQ);
			if (sync_read_byte(syncfd) != SYNC_USERMAP_ACK)
				bail_msg("expected SYNC_USERMAP_ACK");
			if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
				bail("prctl SET_DUMPABLE");
		}

		/* Become root in the new user namespace. */
		if (setresuid(0, 0, 0) < 0)
			bail("setresuid");
		if (setresgid(0, 0, 0) < 0)
			bail("setresgid");
	}

	/* --- Join shared namespaces --- */
	int joined_pid = 0;
	for (uint32_t i = 0; i < join_count; i++) {
		int fd = open(join_paths[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			bail(join_paths[i]);
		if (setns(fd, join_flags[i]) < 0)
			bail("setns shared");
		close(fd);
		if (join_flags[i] == CLONE_NEWPID)
			joined_pid = 1;
	}
	free(join_flags);
	free(join_paths);

	/* --- Unshare remaining namespaces --- */
	uint32_t remaining = config.clone_flags & ~((uint32_t)CLONE_NEWUSER);
	if (remaining) {
		if (unshare(remaining) < 0)
			bail("unshare");
	}

	/*
	 * --- Fork for PID namespace ---
	 * Needed for a new pid ns (unshare only re-homes future children)
	 * and equally for a joined one (setns(CLONE_NEWPID) has the same
	 * children-only semantics).
	 */
	if ((config.clone_flags & CLONE_NEWPID) || joined_pid) {
		pid_t child = fork();
		if (child < 0)
			bail("fork");

		if (child > 0) {
			/* Middle child: report grandchild PID and exit. */
			sync_write_pid(syncfd, child);
			close(syncfd);
			_exit(0);
		}

		/* Grandchild: wait for parent to acknowledge. */
		if (sync_read_byte(syncfd) != SYNC_READY)
			bail_msg("expected SYNC_READY");
	}

	/* --- Final setup --- */
	setsid(); /* EPERM is fine — may already be session leader. */

	close(syncfd);
}

__attribute__((constructor)) static void nsenter_init(void)
{
	const char *mode = getenv("_CONTAINER_MODE");
	if (!mode)
		return;

	if (strcmp(mode, "setup") == 0)
		do_setup();
	else if (strcmp(mode, "join") == 0)
		do_join();

	/* Clear C-only env vars. Keep _CONTAINER_INITFD for Go handler. */
	unsetenv("_CONTAINER_MODE");
	unsetenv("_CONTAINER_PID");
	unsetenv("_CONTAINER_CONFIGFD");
	unsetenv("_CONTAINER_SYNCFD");
}
