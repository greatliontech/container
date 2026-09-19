// Package container is a Linux container runtime: a full create path
// (namespaces, the pivoted root, cgroups, capability and seccomp
// hardening), exec into a running container, and an OCI runtime
// configuration surface.
//
// The create path's Linux mechanism — nsenter.go, cgroups.go,
// security.go, seccomp.go and the CLONE_INTO_CGROUP wiring — has an
// independently owned twin in greatliontech/sandbox's internal
// mechanism layer, seeded from this repo and diverging by contract:
// sandbox derives its verbs from a create-only, intent-in contract,
// this runtime keeps an OCI runtime's shape. The kernel rules beneath
// the two must not diverge: any kernel-rule fix found in either copy
// (locked mount flags on a read-only remount, cgroup placement under
// a delegated ancestry, the no-internal-process rule,
// CLONE_INTO_CGROUP semantics, and their kin) is applied to both,
// while a contract-level rule stays each copy's own — here swap
// follows the OCI configuration's own memory.swap, as runc reads it.
package container
