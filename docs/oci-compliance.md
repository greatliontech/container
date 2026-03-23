# OCI Runtime Spec Compliance Tracker

Reference: [opencontainers/runtime-spec v1.3.0](https://github.com/opencontainers/runtime-spec)

Status key:
- [x] Implemented in runtime and OCI converter
- [~] Partially implemented (see notes)
- [ ] Not implemented

---

## Spec (top-level)

- [x] Version — not stored, but parsed
- [x] Process — converted to container.Process
- [x] Root.Path — mapped to Config.Root
- [ ] Root.Readonly — not enforced
- [x] Hostname — mapped to Config.Hostname
- [ ] Domainname — no field in Config
- [x] Mounts — converted with option parsing (flags + data)
- [x] Hooks — all 6 hook types converted
- [ ] Annotations — no field in Config
- [x] Linux — see below
- [ ] Solaris — not applicable (Linux-only)
- [ ] Windows — not applicable
- [ ] VM — not applicable
- [ ] ZOS — not applicable
- [ ] FreeBSD — not applicable

## Process

- [ ] Terminal — not wired (ConsoleSocket exists but converter doesn't set it)
- [ ] ConsoleSize (Box.Height, Box.Width) — no resize support
- [ ] User.UID — not mapped to Process.Credential
- [ ] User.GID — not mapped to Process.Credential
- [ ] User.Umask — not supported
- [ ] User.AdditionalGids — not mapped
- [ ] User.Username — not supported
- [x] Args — mapped to Process.Cmd + Process.Args
- [ ] CommandLine — Windows-only, not applicable
- [x] Env — mapped to Process.Env
- [x] Cwd — mapped to Process.WorkDir
- [x] Capabilities — all 5 sets converted via cap.FromName
- [x] Rlimits — type string parsed, mapped to Config.Rlimits
- [x] NoNewPrivileges — mapped to Config.NoNewPrivileges
- [ ] ApparmorProfile — not supported
- [ ] OOMScoreAdj — no field in Config
- [ ] Scheduler — not supported
- [ ] SelinuxLabel — not supported
- [ ] IOPriority — not supported
- [ ] ExecCPUAffinity — not supported

## Linux

- [x] UIDMappings — mapped to Config.UidMappings
- [x] GIDMappings — mapped to Config.GidMappings
- [x] Sysctl — mapped to Config.Sysctl
- [~] Resources — see LinuxResources below
- [ ] CgroupsPath — ignored (runtime auto-creates cgroups)
- [x] Namespaces — all 8 types, create or join
- [x] Devices — converted to Config.Devices
- [ ] NetDevices — not supported
- [~] Seccomp — see LinuxSeccomp below
- [ ] RootfsPropagation — always MS_PRIVATE
- [x] MaskedPaths — mapped to Config.MaskPaths
- [x] ReadonlyPaths — mapped to Config.ReadonlyPaths
- [ ] MountLabel — SELinux, not supported
- [ ] IntelRdt — not supported
- [ ] MemoryPolicy — not supported
- [ ] Personality — not supported
- [ ] TimeOffsets — no field in Config (namespace exists but offsets not configurable)

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

- [ ] Devices (cgroup device allowlist) — not supported
- [~] Memory — see LinuxMemory below
- [~] CPU — see LinuxCPU below
- [x] Pids.Limit — mapped to Resources.Pids.Max
- [ ] BlockIO — not converted (runtime has IO.Max but different format)
- [ ] HugepageLimits — not supported
- [ ] Network — not supported
- [ ] Rdma — not supported
- [ ] Unified (raw cgroup key-value) — not supported

## LinuxMemory

- [x] Limit — mapped to Resources.Memory.Max
- [x] Reservation — mapped to Resources.Memory.High
- [x] Swap — mapped to Resources.Memory.SwapMax
- [ ] Kernel — deprecated in cgroups v2
- [ ] KernelTCP — deprecated in cgroups v2
- [ ] Swappiness — not supported
- [ ] DisableOOMKiller — not supported
- [ ] UseHierarchy — cgroups v2 always hierarchical
- [ ] CheckBeforeUpdate — not supported

## LinuxCPU

- [x] Shares — mapped to Resources.CPU.Weight
- [x] Quota — mapped to Resources.CPU.Quota
- [x] Period — mapped to Resources.CPU.Period
- [ ] Burst — not supported
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
- [ ] Syscalls.Args — not converted (runtime supports it via go-seccomp-bpf but OCI→internal conversion missing)

## LinuxSeccompArg

- [ ] Index — not converted
- [ ] Value — not converted
- [ ] ValueTwo — not converted
- [ ] Op — not converted

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

- [ ] UID — not mapped to Process.Credential
- [ ] GID — not mapped to Process.Credential
- [ ] Umask — not supported
- [ ] AdditionalGids — not mapped
- [ ] Username — not supported

## Hook

- [x] Path — mapped
- [x] Args — mapped
- [x] Env — mapped
- [~] Timeout — field exists but OCI seconds→Go duration conversion incomplete

## Mount

- [x] Destination — mapped to Mount.Target
- [x] Type — mapped
- [x] Source — mapped
- [x] Options — parsed to flags + data string
- [ ] UIDMappings — not supported (mount-level ID mapping)
- [ ] GIDMappings — not supported

## LinuxDevice

- [x] Path — mapped
- [x] Type — "c"/"b" converted to S_IFCHR/S_IFBLK
- [x] Major — mapped
- [x] Minor — mapped
- [x] FileMode — mapped
- [ ] UID — not mapped (Device struct has field but converter doesn't set it)
- [ ] GID — not mapped

## LinuxDeviceCgroup (cgroup device allowlist)

- [ ] Allow — not supported
- [ ] Type — not supported
- [ ] Major — not supported
- [ ] Minor — not supported
- [ ] Access — not supported

## LinuxBlockIO

- [ ] Weight — not converted
- [ ] LeafWeight — not supported
- [ ] WeightDevice — not supported
- [ ] ThrottleReadBpsDevice — not supported
- [ ] ThrottleWriteBpsDevice — not supported
- [ ] ThrottleReadIOPSDevice — not supported
- [ ] ThrottleWriteIOPSDevice — not supported

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

- [ ] Height — not supported
- [ ] Width — not supported

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
