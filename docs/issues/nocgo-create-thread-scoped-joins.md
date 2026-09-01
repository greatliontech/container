# nocgo create path: join thread-scoped namespaces

**Lands:** user decision

## Gap

A nocgo build rejects every `Namespaces.Join*` at create with an error
naming CGO. Only user and mount namespace joins are genuinely
cgo-bound (the kernel requires a single-threaded caller for their
`setns`). The other six are joinable from multithreaded Go, and the
nocgo exec path already joins them: uts, ipc, net, cgroup, and time
apply per-thread; pid applies to the setns'd thread's future children
and needs a fork before the payload. The blanket rejection presents an
implementation gap as a platform constraint.

## Direction

Two independent capabilities, in this order:

1. **Thread-scoped five (uts, ipc, net, cgroup, time) at create.** The
   `__container` handler locks its OS thread on entry, setns-joins
   these before `containerSetup`, and execs the payload on that thread
   so the namespaces carry over — the same walk the nocgo join handler
   uses for exec. Validation narrows to rejecting user/mnt joins (and
   pid, until 2 lands), and the error text attributes the limit to
   what is actually cgo-bound.

2. **`JoinPID` at create.** Requires the fork-after-setns topology the
   nocgo exec path already has (payload spawned through the `__nsexec`
   stage: PR_SET_PDEATHSIG armed inside the namespace, liveness pipe
   for the arming race, exit/signal/stop transparency), plus what exec
   did not need: the payload's pid reported back to the parent so
   `Wait`/`Signal`/state target the real container process — the pure-
   Go equivalent of the C setup path's middle-child pid handshake,
   including its scoped-subreaper reparenting window. This is a
   process-topology change to the nocgo create flow, not a wiring
   change.

## Constraint to preserve

Joining a namespace requires capabilities over its *owning user
namespace*. `NewUser` combined with joins of externally-owned
namespaces fails with EPERM in both builds (the C setup path has the
same ordering); that is kernel semantics of the configuration, not a
build-mode limit — surface the kernel's error, do not pre-reject the
combination.

## Tests

Per-namespace create-join membership tests on both builds (ns-link
equality against the target, as the exec-path suite does); the pid
capability additionally extends the shared shim-transparency suite
(exit code, death signal, forwarding, stop mirroring, orphan backstop)
to the create flow.
