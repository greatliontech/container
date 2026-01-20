# Container Runtime Roadmap

This document outlines the development roadmap for the pure-Go container runtime.

## Current State

The runtime currently implements:
- All 6 Linux namespaces (IPC, Mount, Network, PID, UTS, User)
- UID/GID mappings for rootless containers
- Flexible mount system with bind mount support
- Clean parent-child process separation via `/proc/self/exe` re-exec
- Piped I/O support
- Hostname configuration

## Design Philosophy

- **Pure Go**: No CGO dependencies. Leverage Go's `syscall` package and `SysProcAttr`.
- **Simplicity**: Minimal code, clear abstractions, easy to understand.
- **Security by default**: Safe defaults, opt-in for less secure configurations.

---

## Phase 1: Security Hardening

**Goal**: Establish proper security foundations.

### 1.1 pivot_root instead of chroot

- [x] Replace `chroot()` with `pivot_root()` syscall
- [x] Properly set up mount propagation (`MS_PRIVATE`)
- [x] Clean up old root after pivot

**Why**: `chroot` is escapable by privileged processes. `pivot_root` provides true filesystem isolation by changing the root mount, making it impossible to access the old root.

### 1.2 Capability Dropping

- [x] Add `Capabilities` configuration to `Config`
- [x] Support bounding, effective, permitted, inheritable, and ambient capability sets
- [x] Default to minimal capabilities (drop all, add only needed)
- [x] Add `NoNewPrivs` flag support

**Why**: By default, processes inherit all capabilities from parent. Containers should run with least privilege - only the capabilities they actually need.

### 1.3 Seccomp Support

- [x] Add `SeccompProfile` to `Config`
- [x] Implement default restrictive profile (block dangerous syscalls)
- [x] Support custom seccomp profiles
- [ ] Allow syscall argument filtering (partial - struct defined, not fully implemented)

**Why**: Without syscall filtering, container processes can call any syscall. Seccomp provides defense-in-depth by restricting the kernel attack surface.

### 1.4 Device Node Setup

- [x] Create `/dev` tmpfs in container
- [x] Populate minimal device nodes:
  - `/dev/null`
  - `/dev/zero`
  - `/dev/full`
  - `/dev/random`
  - `/dev/urandom`
  - `/dev/tty`
- [x] Support custom device configuration

**Why**: Containers need basic device nodes to function. A minimal `/dev` reduces attack surface compared to bind-mounting host `/dev`.

---

## Phase 2: Resource Control

**Goal**: Implement resource limits via cgroups v2.

### 2.1 Cgroups v2 Foundation

- [x] Create cgroup hierarchy for containers
- [x] Add `Resources` configuration struct
- [x] Implement cgroup cleanup on container exit

### 2.2 Memory Limits

- [x] `memory.max` - hard memory limit
- [x] `memory.high` - memory throttling threshold
- [x] `memory.swap.max` - swap limit
- [ ] OOM handling and notifications

### 2.3 CPU Limits

- [x] `cpu.max` - CPU bandwidth limit (quota/period)
- [x] `cpu.weight` - CPU shares for fair scheduling
- [x] `cpuset.cpus` - CPU pinning

### 2.4 Process Limits

- [x] `pids.max` - maximum number of processes
- [x] Fork bomb protection

### 2.5 I/O Limits

- [x] `io.max` - I/O bandwidth limits
- [x] `io.weight` - I/O priority

---

## Phase 3: Networking

**Goal**: Provide network connectivity to containers.

### 3.1 Network Namespace Setup

- [x] veth pair creation
- [x] Bridge networking mode
- [x] Host networking mode (share host netns)
- [x] None networking mode (isolated, no connectivity)

### 3.2 IP Configuration

- [x] IP address assignment
- [x] Default gateway configuration
- [ ] Custom routes support

### 3.3 Port Forwarding

- [x] Port mapping (host:container)
- [x] Support TCP and UDP
- [x] nftables rules management (pure Go via `github.com/google/nftables`)

### 3.4 DNS Configuration

- [x] `/etc/resolv.conf` generation
- [x] Custom DNS servers
- [x] `/etc/hosts` management

---

## Phase 4: Lifecycle Management

**Goal**: Full container lifecycle with hooks and state management.

### 4.1 Container State Machine

- [x] States: Created → Running → Stopped
- [x] State persistence to disk
- [x] State querying API

### 4.2 Signal Handling

- [x] Forward signals to container init process
- [x] Graceful shutdown with SIGTERM → SIGKILL escalation
- [x] Configurable stop timeout

### 4.3 Lifecycle Hooks (OCI-style)

- [x] `prestart` - after container created, before user process
- [x] `createRuntime` - during create, before pivot_root
- [x] `createContainer` - during create, after pivot_root
- [x] `startContainer` - before starting user process
- [x] `poststart` - after user process started
- [x] `poststop` - after container stopped

### 4.4 Exec into Running Container

- [x] Join existing namespaces via `setns()` (non-user namespaces)
- [x] Support for `nsenter` equivalent functionality
- [x] Attach to running container's stdio

**Note**: Due to Go's multithreading model, joining user namespaces from Go is unsafe. The implementation provides two approaches:
1. `ExecWithNsenter()` - uses the `nsenter(1)` utility (recommended, handles all namespaces)
2. `ExecNoUserNs()` - pure Go, enters all namespaces except user namespace

---

## Phase 5: Compatibility (Optional)

**Goal**: Interoperability with container ecosystem.

### 5.1 OCI Runtime Spec

- [ ] Parse OCI `config.json` format
- [ ] Implement OCI runtime operations:
  - `create`
  - `start`
  - `state`
  - `kill`
  - `delete`
- [ ] OCI bundle support

### 5.2 Image Handling

- [ ] OCI image spec support (already via `ocifs`)
- [ ] Image layer extraction
- [ ] Image metadata handling

### 5.3 Container Runtime Interface (CRI)

- [ ] Basic CRI compatibility for Kubernetes integration
- [ ] RuntimeService implementation
- [ ] ImageService implementation

---

## Future Considerations

### Checkpoint/Restore
- CRIU integration for container migration
- Live migration between hosts

### Security Enhancements
- AppArmor profile support
- SELinux context configuration
- Rootless networking improvements

### Observability
- Metrics export (Prometheus format)
- Event streaming
- Logging drivers

### Storage
- Volume mounts with proper permissions
- tmpfs volumes with size limits
- Named volumes

---

## Implementation Notes

### Avoiding CGO

The runtime avoids CGO by:
1. Using `/proc/self/exe` re-exec to create single-threaded child
2. Applying namespaces via `SysProcAttr.Cloneflags` at fork time
3. Serializing configuration to disk for parent-child communication

This approach works because Go's `syscall.SysProcAttr` internally uses the C library's `clone()` syscall with the appropriate flags, all handled within Go's runtime.

### Seccomp Without CGO

Using `github.com/elastic/go-seccomp-bpf`:
- Pure Go, no CGO or libseccomp dependency
- Handles thread synchronization via `SECCOMP_FILTER_FLAG_TSYNC`
- Automatically sets `NO_NEW_PRIVS`
- Supports syscall argument filtering
- Supports amd64, arm64, arm, 386

### Capabilities Without CGO

Using `kernel.org/pub/linux/libs/security/libcap/cap`:
- Official libcap bindings from kernel.org
- Pure Go with `CGO_ENABLED=0`
- Proper POSIX semantics (all threads stay in sync)
- Full IAB (Inheritable, Ambient, Bounding) support
- BSD/GPL dual licensed
