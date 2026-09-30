# nanonetes as a pod-runtime consumer

**Lands:** the container×sandbox ruling (which library ociplug delegates
to). This entry records the consumer that ruling must account for; it
asks for no feature and sets no date.

## The consumer

`thegrumpylion/nanonetes` is a Kubernetes control plane in one process
per node; its node agent replaces the kubelet and runs pods through
this library plus ocifs. A pod, as Kubernetes defines it and as the
conformance suite exercises it, needs from a runtime:

- **Create** with the full hardening path this library already has
  (namespaces, pivoted root, cgroups, capabilities, seccomp).
- **Join**: every container after the first in a pod joins the pod's
  sandbox network, IPC and UTS namespaces rather than creating its own.
  A per-container network namespace is not a pod.
- **Exec into a running container** (`kubectl exec`, `attach`, probes
  of the exec kind), which is a namespace join by definition.

Join and exec are exactly what `greatliontech/sandbox` refuses by its
create-only contract, so for this consumer the answer to the ruling is
this library, with the pure-Go namespace-join work in the
`setns-sysprocattr` branch of `thegrumpylion/go` (drafts in
`thegrumpylion/go-nsjoin-drafts`) as the way exec stays cgo-free.

## The networking seam

The 2026-03-23 removal of `network.go` and `portforward.go` (bridge,
veth, IP assignment, DNS files, nftables port mapping) called those
orchestration concerns. nanonetes is that orchestrator and agrees: it
will own pod networking, or consume a shared pure-Go netlink/nftables
layer once one has an owner in the estate. What it needs from this
library is only the seam the removal left implicit — a container can
be created into, or joined to, a network namespace the caller prepared,
and the caller learns the namespace handle it needs to configure it.
The deleted code is the seed for the consumer side; nothing of it
returns here.

## What this entry is not

Not a request to un-pause, not a networking feature request, and not a
timeline. When the ruling lands with this consumer accounted for, the
rationale is promoted into the ruling's record and this file is deleted.
