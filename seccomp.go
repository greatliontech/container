package container

import (
	"github.com/elastic/go-seccomp-bpf"
)

// SeccompProfile defines the seccomp filtering configuration
type SeccompProfile struct {
	// DefaultAction is the action for syscalls not in the rules
	DefaultAction seccomp.Action
	// Syscalls defines the syscall filtering rules
	Syscalls []seccomp.SyscallGroup
}

// DefaultSeccompProfile returns a restrictive seccomp profile suitable for containers.
// It blocks dangerous syscalls while allowing normal container operation.
func DefaultSeccompProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			// Block kernel module operations
			{
				Action: seccomp.ActionErrno,
				Names: []string{
					"init_module",
					"finit_module",
					"delete_module",
				},
			},
			// Block system reboot/shutdown
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"reboot"},
			},
			// Block swap operations
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"swapon", "swapoff"},
			},
			// Block mount operations (use mount namespace instead)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"mount", "umount2"},
			},
			// Block changing system time
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"settimeofday", "clock_settime", "adjtimex"},
			},
			// Block process accounting
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"acct"},
			},
			// Block quotactl
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"quotactl"},
			},
			// Block kexec
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"kexec_load", "kexec_file_load"},
			},
			// Block perf_event_open (potential info leak)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"perf_event_open"},
			},
			// Block bpf
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"bpf"},
			},
			// Block userfaultfd (used in exploits)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"userfaultfd"},
			},
			// Block io_uring (potential security issues)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"io_uring_setup", "io_uring_enter", "io_uring_register"},
			},
			// Block ptrace (debugging)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"ptrace"},
			},
			// Block personality changes (used to disable ASLR)
			{
				Action: seccomp.ActionErrno,
				Names:  []string{"personality"},
			},
		},
	}
}

// toSeccompPolicy converts our profile to the elastic seccomp policy
func (p *SeccompProfile) toSeccompPolicy() seccomp.Policy {
	return seccomp.Policy{
		DefaultAction: p.DefaultAction,
		Syscalls:      p.Syscalls,
	}
}

// applySeccomp applies the seccomp profile to the current process.
// This sets NO_NEW_PRIVS and loads the BPF filter.
func applySeccomp(profile *SeccompProfile) error {
	if profile == nil {
		return nil
	}

	policy := profile.toSeccompPolicy()
	filter := seccomp.Filter{
		NoNewPrivs: true, // Required for unprivileged seccomp
		Flag:       seccomp.FilterFlagTSync, // Sync across all threads
		Policy:     policy,
	}

	return seccomp.LoadFilter(filter)
}
