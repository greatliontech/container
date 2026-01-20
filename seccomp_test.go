package container

import (
	"testing"

	"github.com/elastic/go-seccomp-bpf"
)

func TestDefaultSeccompProfile(t *testing.T) {
	profile := DefaultSeccompProfile()

	if profile == nil {
		t.Fatal("DefaultSeccompProfile returned nil")
	}

	// Default action should be Allow (whitelist approach with specific blocks)
	if profile.DefaultAction != seccomp.ActionAllow {
		t.Errorf("DefaultAction = %v, want ActionAllow", profile.DefaultAction)
	}

	// Should have syscall rules defined
	if len(profile.Syscalls) == 0 {
		t.Error("Syscalls rules should not be empty")
	}

	// Collect all blocked syscalls
	blockedSyscalls := make(map[string]seccomp.Action)
	for _, group := range profile.Syscalls {
		for _, name := range group.Names {
			blockedSyscalls[name] = group.Action
		}
	}

	// Verify dangerous syscalls are blocked
	dangerousSyscalls := []string{
		// Kernel module operations
		"init_module",
		"finit_module",
		"delete_module",
		// System reboot/shutdown
		"reboot",
		// Swap operations
		"swapon",
		"swapoff",
		// Mount operations
		"mount",
		"umount2",
		// System time manipulation
		"settimeofday",
		"clock_settime",
		"adjtimex",
		// Process accounting
		"acct",
		// Quota
		"quotactl",
		// Kexec (load new kernel)
		"kexec_load",
		"kexec_file_load",
		// Performance monitoring
		"perf_event_open",
		// BPF
		"bpf",
		// Userfaultfd (used in exploits)
		"userfaultfd",
		// io_uring
		"io_uring_setup",
		"io_uring_enter",
		"io_uring_register",
		// Ptrace
		"ptrace",
		// Personality (can disable ASLR)
		"personality",
	}

	for _, syscall := range dangerousSyscalls {
		action, blocked := blockedSyscalls[syscall]
		if !blocked {
			t.Errorf("dangerous syscall %s should be blocked", syscall)
		} else if action != seccomp.ActionErrno {
			t.Errorf("syscall %s action = %v, want ActionErrno", syscall, action)
		}
	}
}

func TestDefaultSeccompProfile_NoOverlapWithSafeSyscalls(t *testing.T) {
	profile := DefaultSeccompProfile()

	// Collect all blocked syscalls
	blockedSyscalls := make(map[string]bool)
	for _, group := range profile.Syscalls {
		for _, name := range group.Names {
			blockedSyscalls[name] = true
		}
	}

	// These common syscalls should NOT be blocked for normal container operation
	safeSyscalls := []string{
		"read",
		"write",
		"open",
		"close",
		"stat",
		"fstat",
		"lstat",
		"poll",
		"lseek",
		"mmap",
		"mprotect",
		"munmap",
		"brk",
		"ioctl",
		"access",
		"pipe",
		"dup",
		"dup2",
		"socket",
		"connect",
		"accept",
		"sendto",
		"recvfrom",
		"fork",
		"vfork",
		"clone",
		"execve",
		"exit",
		"wait4",
		"kill",
		"getpid",
		"getuid",
		"getgid",
		"geteuid",
		"getegid",
		"setuid",
		"setgid",
		"chdir",
		"getcwd",
		"rename",
		"mkdir",
		"rmdir",
		"unlink",
		"chmod",
		"chown",
		"time",
		"nanosleep",
	}

	for _, syscall := range safeSyscalls {
		if blockedSyscalls[syscall] {
			t.Errorf("safe syscall %s should not be blocked", syscall)
		}
	}
}

func TestSeccompProfile_toSeccompPolicy(t *testing.T) {
	profile := &SeccompProfile{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"reboot", "kexec_load"},
			},
			{
				Action: seccomp.ActionTrap,
				Names:  []string{"init_module"},
			},
		},
	}

	policy := profile.toSeccompPolicy()

	if policy.DefaultAction != seccomp.ActionAllow {
		t.Errorf("Policy.DefaultAction = %v, want ActionAllow", policy.DefaultAction)
	}

	if len(policy.Syscalls) != 2 {
		t.Errorf("Policy.Syscalls length = %d, want 2", len(policy.Syscalls))
	}

	// Verify first group
	if policy.Syscalls[0].Action != seccomp.ActionErrno {
		t.Errorf("First group action = %v, want ActionErrno", policy.Syscalls[0].Action)
	}
	if len(policy.Syscalls[0].Names) != 2 {
		t.Errorf("First group names length = %d, want 2", len(policy.Syscalls[0].Names))
	}

	// Verify second group
	if policy.Syscalls[1].Action != seccomp.ActionTrap {
		t.Errorf("Second group action = %v, want ActionTrap", policy.Syscalls[1].Action)
	}
	if len(policy.Syscalls[1].Names) != 1 {
		t.Errorf("Second group names length = %d, want 1", len(policy.Syscalls[1].Names))
	}
}

func TestSeccompProfile_toSeccompPolicy_Empty(t *testing.T) {
	profile := &SeccompProfile{
		DefaultAction: seccomp.ActionErrno,
		Syscalls:      nil,
	}

	policy := profile.toSeccompPolicy()

	if policy.DefaultAction != seccomp.ActionErrno {
		t.Errorf("Policy.DefaultAction = %v, want ActionErrno", policy.DefaultAction)
	}

	if policy.Syscalls != nil {
		t.Errorf("Policy.Syscalls = %v, want nil", policy.Syscalls)
	}
}

func TestSeccompProfileStruct(t *testing.T) {
	profile := SeccompProfile{
		DefaultAction: seccomp.ActionErrno,
		Syscalls: []seccomp.SyscallGroup{
			{
				Action: seccomp.ActionAllow,
				Names:  []string{"read", "write", "exit"},
			},
		},
	}

	if profile.DefaultAction != seccomp.ActionErrno {
		t.Errorf("DefaultAction = %v, want ActionErrno", profile.DefaultAction)
	}

	if len(profile.Syscalls) != 1 {
		t.Errorf("Syscalls length = %d, want 1", len(profile.Syscalls))
	}

	if profile.Syscalls[0].Action != seccomp.ActionAllow {
		t.Errorf("Syscalls[0].Action = %v, want ActionAllow", profile.Syscalls[0].Action)
	}

	if len(profile.Syscalls[0].Names) != 3 {
		t.Errorf("Syscalls[0].Names length = %d, want 3", len(profile.Syscalls[0].Names))
	}
}

func TestSeccompActions(t *testing.T) {
	// Verify the seccomp action constants are distinct and non-zero
	actions := []seccomp.Action{
		seccomp.ActionTrap,
		seccomp.ActionErrno,
		seccomp.ActionTrace,
		seccomp.ActionAllow,
	}

	seen := make(map[seccomp.Action]bool)
	for _, action := range actions {
		if seen[action] {
			t.Errorf("duplicate action value: %v", action)
		}
		seen[action] = true
	}
}

func TestDefaultSeccompProfile_GroupOrganization(t *testing.T) {
	profile := DefaultSeccompProfile()

	// Each group should have the same action for all syscalls in it
	for i, group := range profile.Syscalls {
		if len(group.Names) == 0 {
			t.Errorf("group %d has no syscalls", i)
		}

		// Verify group has a valid action
		validActions := map[seccomp.Action]bool{
			seccomp.ActionTrap:  true,
			seccomp.ActionErrno: true,
			seccomp.ActionTrace: true,
			seccomp.ActionAllow: true,
		}

		if !validActions[group.Action] {
			t.Errorf("group %d has invalid action: %v", i, group.Action)
		}
	}
}
