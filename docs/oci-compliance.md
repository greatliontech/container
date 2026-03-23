# OCI Runtime Spec Compliance Tracker

Reference: [opencontainers/runtime-spec v1.3.0](https://github.com/opencontainers/runtime-spec)

Status key:
- [x] Implemented in runtime and OCI converter
- [ ] Not implemented

---

## Spec (top-level)

- [x] Version — parsed
- [x] Process — converted to container.Process
- [x] Root.Path — mapped to Config.Root
- [x] Root.Readonly — mapped to Config.ReadonlyRoot, enforced via bind remount
- [x] Hostname — mapped to Config.Hostname
- [x] Domainname — mapped to Config.Domainname, set via setdomainname(2)
- [x] Mounts — converted with option parsing (flags + data)
- [x] Hooks — all 6 hook types converted
- [x] Annotations — mapped to Config.Annotations, passed to hooks via ContainerState
- [x] Linux — see below

## Process

- [x] Terminal — mapped to Process.Terminal, PTY allocated automatically, master via Container.Console()
- [x] ConsoleSize — mapped to Process.ConsoleHeight/ConsoleWidth, TIOCSWINSZ ioctl
- [x] User.UID — mapped to Process.Credential.Uid
- [x] User.GID — mapped to Process.Credential.Gid
- [x] User.AdditionalGids — mapped to Process.Credential.Groups
- [x] User.Umask — mapped to Process.Umask, applied via syscall.Umask in child
- [ ] User.Username — requires container /etc/passwd parsing
- [x] Args — mapped to Process.Cmd + Process.Args
- [x] Env — mapped to Process.Env
- [x] Cwd — mapped to Process.WorkDir
- [x] Capabilities — all 5 sets converted via cap.FromName
- [x] Rlimits — type string parsed, mapped to Config.Rlimits
- [x] NoNewPrivileges — mapped to Config.NoNewPrivileges
- [x] OOMScoreAdj — mapped to Config.OOMScoreAdj, written to /proc/self/oom_score_adj
- [ ] ApparmorProfile — not supported
- [ ] Scheduler — not supported
- [ ] SelinuxLabel — not supported
- [ ] IOPriority — not supported
- [ ] ExecCPUAffinity — not supported

## Linux

- [x] UIDMappings — mapped to Config.UidMappings
- [x] GIDMappings — mapped to Config.GidMappings
- [x] Sysctl — mapped to Config.Sysctl
- [x] Resources — see LinuxResources below
- [x] CgroupsPath — mapped to Config.CgroupsPath
- [x] Namespaces — all 8 types, create or join
- [x] Devices — converted to Config.Devices (including UID/GID)
- [ ] NetDevices — not supported
- [x] Seccomp — see LinuxSeccomp below
- [x] RootfsPropagation — mapped to Config.RootfsPropagation (private/slave/shared)
- [x] MaskedPaths — mapped to Config.MaskPaths
- [x] ReadonlyPaths — mapped to Config.ReadonlyPaths
- [ ] MountLabel — SELinux, not supported
- [ ] IntelRdt — not supported
- [ ] MemoryPolicy — not supported
- [ ] Personality — not supported
- [ ] TimeOffsets — requires C sync protocol extension

## LinuxNamespace

- [x] Type: pid
- [x] Type: network
- [x] Type: mount
- [x] Type: ipc
- [x] Type: uts
- [x] Type: user
- [x] Type: cgroup
- [x] Type: time
- [x] Path (join existing namespace)

## LinuxResources

- [ ] Devices (cgroup device allowlist) — requires eBPF in cgroups v2
- [x] Memory — see LinuxMemory below
- [x] CPU — see LinuxCPU below
- [x] Pids.Limit — mapped to Resources.Pids.Max
- [x] BlockIO — converted to IO.Weight + IO.Max via throttle device mapping
- [ ] HugepageLimits — not supported
- [ ] Network — not supported
- [ ] Rdma — not supported
- [x] Unified — mapped to Resources.Unified, raw cgroup key-value writes

## LinuxMemory

- [x] Limit — mapped to Resources.Memory.Max
- [x] Reservation — mapped to Resources.Memory.High
- [x] Swap — mapped to Resources.Memory.SwapMax
- [x] DisableOOMKiller — mapped to Resources.Memory.DisableOOMKiller (memory.oom.group)
- [ ] Kernel — deprecated in cgroups v2
- [ ] KernelTCP — deprecated in cgroups v2
- [ ] Swappiness — cgroups v1 only
- [ ] UseHierarchy — cgroups v2 always hierarchical
- [ ] CheckBeforeUpdate — not supported

## LinuxCPU

- [x] Shares — mapped to Resources.CPU.Weight
- [x] Quota — mapped to Resources.CPU.Quota
- [x] Period — mapped to Resources.CPU.Period
- [x] Burst — mapped to Resources.CPU.Burst (cpu.max.burst)
- [ ] RealtimeRuntime — not supported
- [ ] RealtimePeriod — not supported
- [x] Cpus — mapped to Resources.CPU.Cpus
- [x] Mems — mapped to Resources.CPU.Mems
- [ ] Idle — not supported

## LinuxSeccomp

- [x] DefaultAction — converted to seccomp.Action
- [ ] DefaultErrnoRet — not supported
- [ ] Architectures — not supported
- [ ] Flags — not supported
- [ ] ListenerPath — not supported
- [ ] ListenerMetadata — not supported
- [x] Syscalls.Names — converted
- [x] Syscalls.Action — converted
- [ ] Syscalls.ErrnoRet — not supported
- [x] Syscalls.Args — converted to go-seccomp-bpf Conditions via operator mapping

## LinuxSeccompArg

- [x] Index — mapped to Condition.Argument
- [x] Value — mapped to Condition.Value
- [ ] ValueTwo — not supported (MaskedEqual second operand)
- [x] Op — mapped: SCMP_CMP_EQ→Equal, NE→NotEqual, GT→GreaterThan, GE→GreaterOrEqual, LT→LessThan, LE→LessOrEqual, MASKED_EQ→BitsSet

## LinuxCapabilities

- [x] Bounding — converted via cap.FromName
- [x] Effective — converted
- [x] Inheritable — converted
- [x] Permitted — converted
- [x] Ambient — converted

## POSIXRlimit

- [x] Type — string parsed to unix.RLIMIT_* constant
- [x] Hard — mapped
- [x] Soft — mapped

## User

- [x] UID — mapped to Process.Credential.Uid
- [x] GID — mapped to Process.Credential.Gid
- [x] AdditionalGids — mapped to Process.Credential.Groups
- [x] Umask — mapped to Process.Umask
- [ ] Username — requires container /etc/passwd parsing

## Hook

- [x] Path — mapped
- [x] Args — mapped
- [x] Env — mapped
- [x] Timeout — converted from OCI seconds (*int) to Go time.Duration

## Mount

- [x] Destination — mapped to Mount.Target
- [x] Type — mapped
- [x] Source — mapped
- [x] Options — parsed to flags + data string
- [ ] UIDMappings — mount-level ID mapping (mount_setattr)
- [ ] GIDMappings — mount-level ID mapping

## LinuxDevice

- [x] Path — mapped
- [x] Type — "c"/"b" converted to S_IFCHR/S_IFBLK
- [x] Major — mapped
- [x] Minor — mapped
- [x] FileMode — mapped
- [x] UID — mapped
- [x] GID — mapped

## LinuxDeviceCgroup (cgroup device allowlist)

- [ ] Allow — not supported (requires eBPF in cgroups v2)
- [ ] Type — not supported
- [ ] Major — not supported
- [ ] Minor — not supported
- [ ] Access — not supported

## LinuxBlockIO

- [x] Weight — mapped to IO.Weight
- [ ] LeafWeight — not supported
- [ ] WeightDevice — not supported
- [x] ThrottleReadBpsDevice — converted to IO.Max entries
- [x] ThrottleWriteBpsDevice — converted to IO.Max entries
- [x] ThrottleReadIOPSDevice — converted to IO.Max entries
- [x] ThrottleWriteIOPSDevice — converted to IO.Max entries

## LinuxHugepageLimit

- [ ] Pagesize — not supported
- [ ] Limit — not supported

## LinuxNetwork

- [ ] ClassID — not supported
- [ ] Priorities — not supported

## LinuxRdma

- [ ] HcaHandles — not supported
- [ ] HcaObjects — not supported

## LinuxIntelRdt

- [ ] ClosID — not supported
- [ ] Schemata — not supported
- [ ] L3CacheSchema — not supported
- [ ] MemBwSchema — not supported
- [ ] EnableMonitoring — not supported

## LinuxPersonality

- [ ] Domain — not supported
- [ ] Flags — not supported

## LinuxTimeOffset

- [ ] Secs — not supported
- [ ] Nanosecs — not supported

## Box (console size)

- [x] Height — mapped to Process.ConsoleHeight
- [x] Width — mapped to Process.ConsoleWidth

## Scheduler

- [ ] Policy — not supported
- [ ] Nice — not supported
- [ ] Priority — not supported
- [ ] Flags — not supported
- [ ] Runtime — not supported
- [ ] Deadline — not supported
- [ ] Period — not supported

## LinuxIOPriority

- [ ] Class — not supported
- [ ] Priority — not supported

## CPUAffinity

- [ ] Initial — not supported
- [ ] Final — not supported

## LinuxNetDevice

- [ ] Name — not supported

## LinuxMemoryPolicy

- [ ] Mode — not supported
- [ ] Nodes — not supported
- [ ] Flags — not supported

---

## OCI Runtime Lifecycle Operations

- [x] Create — Container.Create() with ready pipe synchronization
- [x] Start — Container.Start() signals child to exec
- [x] State — Container.State() / Container.Pid() / Container.ExitCode()
- [x] Kill — Container.Signal()
- [x] Delete — Container.Destroy()
- [ ] CLI interface (runtime create/start/state/kill/delete commands)
- [ ] OCI state JSON output format (ociVersion, id, status, pid, bundle, annotations)
