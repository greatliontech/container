# Issues

Tracked deferrals carrying a `Lands:` trigger. On resolution, the
load-bearing rationale is promoted into a kept-current artifact and the
issue file deleted — git holds history.

| Issue | Summary | Lands |
|---|---|---|
| [nocgo-create-thread-scoped-joins](nocgo-create-thread-scoped-joins.md) | nocgo create rejects all namespace joins; six of eight are joinable in pure Go — implement, narrow the rejection to user/mnt | user decision |
| [nanonetes-pod-runtime-consumer](nanonetes-pod-runtime-consumer.md) | nanonetes's node agent needs create, sandbox-namespace join and exec (which sandbox refuses by contract) plus a network-namespace seam; it owns pod networking itself | the container×sandbox ruling |
