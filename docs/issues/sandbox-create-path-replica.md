# sandbox replicates this repo's create path

Lands: sandbox's first tagged release whose Linux backend delivers the
Strong row of its docs/specs/sandbox.md whole (checkable against
sandbox's tags)

greatliontech/sandbox seeds its internal Linux mechanism layer from
this repo's create path as of
866eb725dc6be9acb1ac36fd66ce8152280e71aa — nsenter.go, cgroups.go,
security.go, seccomp.go, and the CLONE_INTO_CGROUP wiring in
container.go — and maintains it independently, so its API can find its
shape under sandbox's own contract without a cross-repo dependency
freezing it. The twin record is sandbox's
docs/issues/linux-mechanism-replica.md.

The standing cost of the replica: any kernel-rule fix landing in this
repo's create path (locked mount flags on read-only remounts, cgroup
delegation-ancestry placement, CLONE_INTO_CGROUP semantics, and their
kin) MUST also be applied to sandbox's copy, and vice versa.

At the trigger, judge whether the create path should rebase onto an
exported sandbox mechanism layer (one copy of the kernel rules,
container keeping join/exec/console/devices as its own) or whether
independent ownership is the end state. Both outcomes resolve this
issue.
