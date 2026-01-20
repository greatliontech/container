package container

import (
	"encoding/json"

	"github.com/elastic/go-seccomp-bpf"
)

// SeccompProfile defines the seccomp filtering configuration
type SeccompProfile struct {
	// DefaultAction is the action for syscalls not in the rules
	DefaultAction seccomp.Action
	// Syscalls defines the syscall filtering rules
	Syscalls []seccomp.SyscallGroup
}

// seccompProfileJSON is a JSON-friendly version of SeccompProfile
type seccompProfileJSON struct {
	DefaultAction uint32             `json:"default_action"`
	Syscalls      []syscallGroupJSON `json:"syscalls"`
}

// syscallGroupJSON is a JSON-friendly version of seccomp.SyscallGroup
type syscallGroupJSON struct {
	Action uint32   `json:"action"`
	Names  []string `json:"names"`
}

// MarshalJSON implements json.Marshaler for SeccompProfile
func (p *SeccompProfile) MarshalJSON() ([]byte, error) {
	jp := seccompProfileJSON{
		DefaultAction: uint32(p.DefaultAction),
		Syscalls:      make([]syscallGroupJSON, len(p.Syscalls)),
	}
	for i, sg := range p.Syscalls {
		jp.Syscalls[i] = syscallGroupJSON{
			Action: uint32(sg.Action),
			Names:  sg.Names,
		}
	}
	return json.Marshal(jp)
}

// UnmarshalJSON implements json.Unmarshaler for SeccompProfile
func (p *SeccompProfile) UnmarshalJSON(data []byte) error {
	var jp seccompProfileJSON
	if err := json.Unmarshal(data, &jp); err != nil {
		return err
	}
	p.DefaultAction = seccomp.Action(jp.DefaultAction)
	p.Syscalls = make([]seccomp.SyscallGroup, len(jp.Syscalls))
	for i, sg := range jp.Syscalls {
		p.Syscalls[i] = seccomp.SyscallGroup{
			Action: seccomp.Action(sg.Action),
			Names:  sg.Names,
		}
	}
	return nil
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
			// Note: personality is NOT blocked as it's commonly used by programs
			// during startup to query system capabilities. Blocking it breaks
			// many applications including busybox.
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
