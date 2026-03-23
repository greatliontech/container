package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/elastic/go-seccomp-bpf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// FromOCISpec converts an OCI runtime spec to a Config and Process.
func FromOCISpec(spec *specs.Spec) (*Config, *Process, error) {
	cfg := &Config{}
	var proc *Process

	// Root filesystem.
	if spec.Root != nil {
		cfg.Root = spec.Root.Path
		cfg.ReadonlyRoot = spec.Root.Readonly
	}

	cfg.Hostname = spec.Hostname
	cfg.Domainname = spec.Domainname
	cfg.Annotations = spec.Annotations

	// Mounts.
	for _, m := range spec.Mounts {
		flags, data := parseMountOptions(m.Options)
		cfg.Mounts = append(cfg.Mounts, Mount{
			Source: m.Source,
			Target: m.Destination,
			Type:   m.Type,
			Flags:  flags,
			Data:   data,
		})
	}

	// Linux-specific config.
	if spec.Linux != nil {
		l := spec.Linux

		// Namespaces.
		for _, ns := range l.Namespaces {
			setNamespace(&cfg.Namespaces, ns)
		}

		// UID/GID mappings.
		for _, m := range l.UIDMappings {
			cfg.UidMappings = append(cfg.UidMappings, syscall.SysProcIDMap{
				ContainerID: int(m.ContainerID),
				HostID:      int(m.HostID),
				Size:        int(m.Size),
			})
		}
		for _, m := range l.GIDMappings {
			cfg.GidMappings = append(cfg.GidMappings, syscall.SysProcIDMap{
				ContainerID: int(m.ContainerID),
				HostID:      int(m.HostID),
				Size:        int(m.Size),
			})
		}

		// Sysctl.
		cfg.Sysctl = l.Sysctl

		// Cgroup path.
		cfg.CgroupsPath = l.CgroupsPath

		// Rootfs propagation.
		cfg.RootfsPropagation = l.RootfsPropagation

		// Masked/readonly paths.
		cfg.MaskPaths = l.MaskedPaths
		cfg.ReadonlyPaths = l.ReadonlyPaths

		// Devices.
		for _, d := range l.Devices {
			dev := Device{
				Path:  d.Path,
				Major: uint32(d.Major),
				Minor: uint32(d.Minor),
			}
			switch d.Type {
			case "c":
				dev.Type = unix.S_IFCHR
			case "b":
				dev.Type = unix.S_IFBLK
			}
			if d.FileMode != nil {
				dev.Mode = uint32(*d.FileMode)
			}
			if d.UID != nil {
				dev.Uid = *d.UID
			}
			if d.GID != nil {
				dev.Gid = *d.GID
			}
			cfg.Devices = append(cfg.Devices, dev)
		}

		// Resources.
		if l.Resources != nil {
			cfg.Resources = convertResources(l.Resources)
		}

		// Seccomp.
		if l.Seccomp != nil {
			profile, err := convertSeccomp(l.Seccomp)
			if err != nil {
				return nil, nil, fmt.Errorf("seccomp: %w", err)
			}
			cfg.Seccomp = profile
		}
	}

	// Process.
	if spec.Process != nil {
		p := spec.Process
		proc = &Process{}

		if len(p.Args) > 0 {
			proc.Cmd = p.Args[0]
			if len(p.Args) > 1 {
				proc.Args = p.Args[1:]
			}
		}

		proc.Env = p.Env
		proc.WorkDir = p.Cwd
		cfg.NoNewPrivileges = p.NoNewPrivileges

		// User credentials.
		proc.Credential = &syscall.Credential{
			Uid:    p.User.UID,
			Gid:    p.User.GID,
			Groups: p.User.AdditionalGids,
		}
		if p.User.Umask != nil {
			proc.Umask = p.User.Umask
		}

		// OOM score.
		if p.OOMScoreAdj != nil {
			cfg.OOMScoreAdj = p.OOMScoreAdj
		}

		// Console.
		proc.Terminal = p.Terminal
		if p.ConsoleSize != nil {
			proc.ConsoleHeight = p.ConsoleSize.Height
			proc.ConsoleWidth = p.ConsoleSize.Width
		}

		// Capabilities.
		if p.Capabilities != nil {
			cfg.Capabilities = convertCapabilities(p.Capabilities)
		}

		// Rlimits.
		for _, rl := range p.Rlimits {
			rlType, err := parseRlimitType(rl.Type)
			if err != nil {
				return nil, nil, err
			}
			cfg.Rlimits = append(cfg.Rlimits, Rlimit{
				Type: rlType,
				Soft: rl.Soft,
				Hard: rl.Hard,
			})
		}
	}

	// Hooks.
	if spec.Hooks != nil {
		cfg.Hooks = convertHooks(spec.Hooks)
	}

	// Default to pivot_root (OCI standard).
	cfg.UsePivotRoot = true
	cfg.SetupDev = true

	return cfg, proc, nil
}

// LoadOCIBundle reads config.json from a bundle directory and converts it.
func LoadOCIBundle(bundlePath string) (*Config, *Process, error) {
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read config.json: %w", err)
	}

	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, fmt.Errorf("parse config.json: %w", err)
	}

	// Make root path relative to bundle.
	if spec.Root != nil && !filepath.IsAbs(spec.Root.Path) {
		spec.Root.Path = filepath.Join(bundlePath, spec.Root.Path)
	}

	return FromOCISpec(&spec)
}

// --- Namespace conversion ---

func setNamespace(ns *Namespaces, ociNs specs.LinuxNamespace) {
	switch ociNs.Type {
	case specs.PIDNamespace:
		if ociNs.Path != "" {
			ns.JoinPID = ociNs.Path
		} else {
			ns.NewPID = true
		}
	case specs.NetworkNamespace:
		if ociNs.Path != "" {
			ns.JoinNet = ociNs.Path
		} else {
			ns.NewNet = true
		}
	case specs.MountNamespace:
		if ociNs.Path != "" {
			ns.JoinMnt = ociNs.Path
		} else {
			ns.NewMnt = true
		}
	case specs.IPCNamespace:
		if ociNs.Path != "" {
			ns.JoinIPC = ociNs.Path
		} else {
			ns.NewIPC = true
		}
	case specs.UTSNamespace:
		if ociNs.Path != "" {
			ns.JoinUTS = ociNs.Path
		} else {
			ns.NewUTS = true
		}
	case specs.UserNamespace:
		if ociNs.Path != "" {
			ns.JoinUser = ociNs.Path
		} else {
			ns.NewUser = true
		}
	case specs.CgroupNamespace:
		if ociNs.Path != "" {
			ns.JoinCgroup = ociNs.Path
		} else {
			ns.NewCgroup = true
		}
	case specs.TimeNamespace:
		if ociNs.Path != "" {
			ns.JoinTime = ociNs.Path
		} else {
			ns.NewTime = true
		}
	}
}

// --- Resource conversion ---

func convertResources(r *specs.LinuxResources) *Resources {
	res := &Resources{}

	if r.Memory != nil {
		mem := &MemoryResources{}
		if r.Memory.Limit != nil {
			mem.Max = *r.Memory.Limit
		}
		if r.Memory.Reservation != nil {
			mem.High = *r.Memory.Reservation
		}
		if r.Memory.Swap != nil {
			mem.SwapMax = *r.Memory.Swap
		}
		if r.Memory.DisableOOMKiller != nil && *r.Memory.DisableOOMKiller {
			mem.DisableOOMKiller = true
		}
		res.Memory = mem
	}

	if r.CPU != nil {
		cpu := &CPUResources{}
		if r.CPU.Quota != nil {
			cpu.Quota = *r.CPU.Quota
		}
		if r.CPU.Period != nil {
			cpu.Period = *r.CPU.Period
		}
		if r.CPU.Burst != nil {
			cpu.Burst = *r.CPU.Burst
		}
		if r.CPU.Shares != nil {
			cpu.Weight = *r.CPU.Shares
		}
		cpu.Cpus = r.CPU.Cpus
		cpu.Mems = r.CPU.Mems
		res.CPU = cpu
	}

	if r.Pids != nil && r.Pids.Limit != nil {
		res.Pids = &PidsResources{Max: *r.Pids.Limit}
	}

	// BlockIO → IO conversion.
	if r.BlockIO != nil {
		io := &IOResources{}
		if r.BlockIO.Weight != nil {
			io.Weight = uint64(*r.BlockIO.Weight)
		}
		io.Max = make(map[string]string)
		for _, td := range r.BlockIO.ThrottleReadBpsDevice {
			key := fmt.Sprintf("%d:%d", td.Major, td.Minor)
			io.Max[key] = appendIOLimit(io.Max[key], "rbps", td.Rate)
		}
		for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
			key := fmt.Sprintf("%d:%d", td.Major, td.Minor)
			io.Max[key] = appendIOLimit(io.Max[key], "wbps", td.Rate)
		}
		for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
			key := fmt.Sprintf("%d:%d", td.Major, td.Minor)
			io.Max[key] = appendIOLimit(io.Max[key], "riops", td.Rate)
		}
		for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
			key := fmt.Sprintf("%d:%d", td.Major, td.Minor)
			io.Max[key] = appendIOLimit(io.Max[key], "wiops", td.Rate)
		}
		if io.Weight > 0 || len(io.Max) > 0 {
			res.IO = io
		}
	}

	res.Unified = r.Unified

	return res
}

func appendIOLimit(existing, key string, rate uint64) string {
	entry := fmt.Sprintf("%s=%d", key, rate)
	if existing == "" {
		return entry
	}
	return existing + " " + entry
}

// --- Seccomp conversion ---

func convertSeccomp(s *specs.LinuxSeccomp) (*SeccompProfile, error) {
	profile := &SeccompProfile{
		DefaultAction: convertSeccompAction(s.DefaultAction),
	}

	for _, sc := range s.Syscalls {
		group := seccomp.SyscallGroup{
			Action: convertSeccompAction(sc.Action),
			Names:  sc.Names,
		}
		// Convert argument filters if present.
		if len(sc.Args) > 0 {
			for _, name := range sc.Names {
				nc := seccomp.NameWithConditions{
					Name:       name,
					Conditions: convertSeccompArgs(sc.Args),
				}
				group.NamesWithCondtions = append(group.NamesWithCondtions, nc)
			}
			group.Names = nil // Use NamesWithConditions instead.
		}
		profile.Syscalls = append(profile.Syscalls, group)
	}

	return profile, nil
}

func convertSeccompArgs(args []specs.LinuxSeccompArg) seccomp.ArgumentConditions {
	var conditions seccomp.ArgumentConditions
	for _, arg := range args {
		conditions = append(conditions, seccomp.Condition{
			Argument:  uint32(arg.Index),
			Operation: convertSeccompOp(arg.Op),
			Value:     arg.Value,
		})
	}
	return conditions
}

func convertSeccompOp(op specs.LinuxSeccompOperator) seccomp.Operation {
	switch op {
	case specs.OpEqualTo:
		return seccomp.Equal
	case specs.OpNotEqual:
		return seccomp.NotEqual
	case specs.OpGreaterThan:
		return seccomp.GreaterThan
	case specs.OpGreaterEqual:
		return seccomp.GreaterOrEqual
	case specs.OpLessThan:
		return seccomp.LessThan
	case specs.OpLessEqual:
		return seccomp.LessOrEqual
	case specs.OpMaskedEqual:
		return seccomp.BitsSet
	default:
		return seccomp.Equal
	}
}

func convertSeccompAction(a specs.LinuxSeccompAction) seccomp.Action {
	switch a {
	case specs.ActKill, specs.ActKillProcess, specs.ActKillThread:
		return seccomp.ActionKillProcess
	case specs.ActTrap:
		return seccomp.ActionTrap
	case specs.ActErrno:
		return seccomp.ActionErrno
	case specs.ActTrace:
		return seccomp.ActionTrace
	case specs.ActAllow:
		return seccomp.ActionAllow
	case specs.ActLog:
		return seccomp.ActionLog
	default:
		return seccomp.ActionErrno
	}
}

// --- Capability conversion ---

func convertCapabilities(lc *specs.LinuxCapabilities) *Capabilities {
	return &Capabilities{
		Bounding:    parseCapNames(lc.Bounding),
		Effective:   parseCapNames(lc.Effective),
		Inheritable: parseCapNames(lc.Inheritable),
		Permitted:   parseCapNames(lc.Permitted),
		Ambient:     parseCapNames(lc.Ambient),
	}
}

func parseCapNames(names []string) []cap.Value {
	var vals []cap.Value
	for _, name := range names {
		v, err := cap.FromName(name)
		if err != nil {
			continue // Skip unknown capabilities.
		}
		vals = append(vals, v)
	}
	return vals
}

// --- Hook conversion ---

func convertHooks(h *specs.Hooks) *Hooks {
	hooks := &Hooks{}
	hooks.Prestart = convertHookList(h.Prestart)
	hooks.CreateRuntime = convertHookList(h.CreateRuntime)
	hooks.CreateContainer = convertHookList(h.CreateContainer)
	hooks.StartContainer = convertHookList(h.StartContainer)
	hooks.Poststart = convertHookList(h.Poststart)
	hooks.Poststop = convertHookList(h.Poststop)
	return hooks
}

func convertHookList(ociHooks []specs.Hook) []Hook {
	var hooks []Hook
	for _, h := range ociHooks {
		hook := Hook{
			Path: h.Path,
			Args: h.Args,
			Env:  h.Env,
		}
		if h.Timeout != nil {
			hook.Timeout = time.Duration(*h.Timeout) * time.Second
		}
		hooks = append(hooks, hook)
	}
	return hooks
}

// --- Mount option parsing ---

func parseMountOptions(options []string) (uintptr, string) {
	var flags uintptr
	var dataOpts []string

	for _, opt := range options {
		switch opt {
		case "bind":
			flags |= unix.MS_BIND
		case "rbind":
			flags |= unix.MS_BIND | unix.MS_REC
		case "ro", "readonly":
			flags |= unix.MS_RDONLY
		case "rw":
			// default, no flag
		case "nosuid":
			flags |= unix.MS_NOSUID
		case "nodev":
			flags |= unix.MS_NODEV
		case "noexec":
			flags |= unix.MS_NOEXEC
		case "remount":
			flags |= unix.MS_REMOUNT
		case "private":
			flags |= unix.MS_PRIVATE
		case "rprivate":
			flags |= unix.MS_PRIVATE | unix.MS_REC
		case "slave":
			flags |= unix.MS_SLAVE
		case "rslave":
			flags |= unix.MS_SLAVE | unix.MS_REC
		case "shared":
			flags |= unix.MS_SHARED
		case "rshared":
			flags |= unix.MS_SHARED | unix.MS_REC
		case "relatime":
			flags |= unix.MS_RELATIME
		case "strictatime":
			flags |= unix.MS_STRICTATIME
		case "noatime":
			flags |= unix.MS_NOATIME
		case "nodiratime":
			flags |= unix.MS_NODIRATIME
		default:
			dataOpts = append(dataOpts, opt)
		}
	}

	data := ""
	if len(dataOpts) > 0 {
		for i, opt := range dataOpts {
			if i > 0 {
				data += ","
			}
			data += opt
		}
	}

	return flags, data
}

// --- Rlimit type parsing ---

var rlimitTypes = map[string]int{
	"RLIMIT_AS":         unix.RLIMIT_AS,
	"RLIMIT_CORE":       unix.RLIMIT_CORE,
	"RLIMIT_CPU":        unix.RLIMIT_CPU,
	"RLIMIT_DATA":       unix.RLIMIT_DATA,
	"RLIMIT_FSIZE":      unix.RLIMIT_FSIZE,
	"RLIMIT_LOCKS":      unix.RLIMIT_LOCKS,
	"RLIMIT_MEMLOCK":    unix.RLIMIT_MEMLOCK,
	"RLIMIT_MSGQUEUE":   unix.RLIMIT_MSGQUEUE,
	"RLIMIT_NICE":       unix.RLIMIT_NICE,
	"RLIMIT_NOFILE":     unix.RLIMIT_NOFILE,
	"RLIMIT_NPROC":      unix.RLIMIT_NPROC,
	"RLIMIT_RSS":        unix.RLIMIT_RSS,
	"RLIMIT_RTPRIO":     unix.RLIMIT_RTPRIO,
	"RLIMIT_RTTIME":     unix.RLIMIT_RTTIME,
	"RLIMIT_SIGPENDING": unix.RLIMIT_SIGPENDING,
	"RLIMIT_STACK":      unix.RLIMIT_STACK,
}

func parseRlimitType(name string) (int, error) {
	if v, ok := rlimitTypes[name]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unknown rlimit type: %s", name)
}
