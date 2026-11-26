# Deep runtime host isolation

The Linux `deep-runtime` Cargo feature selects the deep host namespaces. A
regular build keeps the existing defaults.

Give each deep Serve a dedicated absolute state directory and an explicit
Unix socket. An empty directory is claimed on first use. Keep the resulting
ownership markers on restart. A state directory can have one active Serve.
An external socket directory is claimed for one installed state identity. The
state marker holds a random instance ID, which Serve returns as
`runtime_instance_id` in the bundle handshake. Restart preserves the ID. A new
state directory at the same path receives a new ID. Configure
a different guest rollout port for each Serve and reserve the official
default for the official runtime.

```sh
smolvm --state-dir /var/lib/smolvm-custom/engines/engine-a serve start \
  --listen unix:///run/smolvm-custom/engines/engine-a/serve.sock \
  --guest-rollout-port 10091
```

Use absolute, non-symlink paths. Keep writable settings, checkpoint staging,
usage records and cache disks inside the selected state directory. Install
the agent and VMM libraries from that Serve's verified bundle. Docker
Engine activation is disabled for this distribution because its global
socket and activation services are outside the Serve's namespace.

Each VMM scope is placed under `smolvmdeep.slice` by default. To configure a
dedicated top-level systemd slice, set `SMOLVM_WORKER_SLICE_NAME` on the Worker
and all Serve processes that use its socket. The slice name has a stem of at
most 63 ASCII letters, digits or underscores, followed by `.slice`. Serve
checks the setting with the Worker at startup. Scope names include the
installed runtime instance ID and a hash of the machine name, so two Serves
can use the same machine name. Boot and Worker admission verify the actual
cgroup membership. Read-only Serve operations can be tested without systemd.
VMM launch requires the systemd placement and per-VM UID isolation. A
root-owned Worker registry at `/var/lib/smolvm-custom/worker/uid-claims`
serializes UID assignments across deep runtimes in a range separate from
the official allocator. A Serve retains orphaned claims it cannot verify.

The Worker owns the shared slice's admission and automatic lifecycle
policy. It reads the slice's aggregate memory counters and host and slice
pressure stall information. During pressure, it throttles admission and
performs bounded cache reclaim before considering Hibernate for an eligible
idle guest. Set the deep slice budget independently of the official lane
before deployment.

The managed resource query reports the current execution, created CPU
slots, the Linux online CPU set when the Guest Agent can read it, and the
scope's measured CPU bandwidth and resident memory. Linux CPU offlining
preserves the existing slots and their budget. Balloon receipts separate
the requested target, the Guest's actual size, and cgroup memory samples.

The x86-64 System launch option `live_compute_growth` enables the existing
CPU and RAM hot-add devices. The current parked StatePoint reader rejects
capture of this topology. The default System profile supports parked
capture and can online or offline its existing CPU slots with a capable
Guest Agent. The Worker reserves new slots and RAM before dispatch and
keeps a pending resize on the original execution until it can confirm the
result. Capture and resize share the same execution lock.

By default, checkpoint scratch uses each Serve's own state directory. To
supply tmpfs scratch, mount separate, root-owned tmpfs filesystems at
`/dev/shm/smolvmdeep-capture-ID` (mode `0711`) and
`/dev/shm/smolvmdeep-restore-ID` (mode `0700`). `ID` is the 32-character runtime instance ID.
Size those filesystems from the Worker budget. A directory or bind mount
backed by the shared `/dev/shm` filesystem leaves the state-directory
scratch path in use.
