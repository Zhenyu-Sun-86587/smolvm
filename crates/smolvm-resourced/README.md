# Worker resource catalog

`smolvm-resourced` is a Linux worker service with a private SQLite catalog. Use one daemon and one state directory per Worker. The service and its control client communicate over one JSON packet per connection on a local `SOCK_SEQPACKET` socket.

```sh
cargo build --locked -p smolvm-resourced
target/debug/smolvm-resourced serve --state-dir /run/user/"$(id -u)"/deep-catalog \
  --socket /run/user/"$(id -u)"/deep-worker.sock
printf '%s\n' '{"protocol":"WorkerResource/1","method":"Health","request_id":"health"}' |
  target/debug/smolvm-resourced call --socket /run/user/"$(id -u)"/deep-worker.sock
```

Use a persistent private state directory for a Worker deployment. The catalog owner's effective UID has control access by default. A service can give a control process access with `--admin-uid` and grant socket access to a group with `--socket-gid`. Filesystem access to the socket permits a connection and requests still require authenticated peer credentials.

The request envelope uses `protocol`, `method`, `request_id`, and `payload`. Scoped methods also take `route_id`, `bundle_digest`, and `expected` with `instance_id`, `incarnation_id`, and `execution_epoch`. Scope operation mutations with `operation_id` and `request_digest`. Use epoch zero and a null incarnation when accepting the first operation on a new instance. A request retry can reuse its operation ID and digest. Use `QueryOperation` after a disconnect to observe the durable record.

| Method | Additional payload and effect |
| --- | --- |
| `Health` | Reports the Worker boot, broker session, recovery status and supported authority. |
| `RegisterBundle` | Associates a trusted installed bundle digest with `executable_sha256`. Supply the executable digest reported by the bundle installer. |
| `BeginOperation` | Reserves the per-instance operation slot using the expected execution. Supported `kind` values are `catalog`, `launch`, `writer_reservation`, `generation`, and `resource_lease`. |
| `QueryOperation` | Returns the record for the envelope's `operation_id` within its `route_id` and `bundle_digest`. |
| `FinishOperation` | Releases the operation slot with `abort` and `expected_revision`. First drop operation pins and writer reservations. |
| `IssueLaunchPermit` | Short-lived permit for a target `pid` and `uid` under the accepted launch operation. Name the next epoch and the new incarnation in `expected`. |
| `RegisterExecution` | The actual process redeems `launch_permit` with that same scope and operation. Peer UID/PID, process start time, pidfd and the registered executable SHA-256 bind the permit. Registration records the broker's initial closed network state. Network enforcement is an independent runtime step. |
| `QueryExecution`, `FinalizeExecutionExit` | Query the named execution or confirm its process exit. Exit processing respects held reservations. |
| `RegisterResource`, `QueryResource` | Register a catalog descriptor with `resource_id`, `durability` and a JSON `descriptor`, or query by `resource_id`. |
| `AddResourceEdge` | Adds a directed edge using `owner_resource_id`, `child_resource_id` and `role`. Rejects cycles. |
| `AddOwnerRef`, `DropOwnerRef` | Manage a root with `owner_kind`, `owner_id`, `resource_id` and `expected_revision`. An `operation` root pins objects to that operation. |
| `QueryOwnerClosure` | Reads the graph reachable from `owner_kind` and `owner_id`. |
| `MarkResourceForGC`, `CollectResource` | Mark and collect a catalog descriptor by `resource_id` and `expected_revision` after checking roots, incoming edges and operation ownership. Backing data files remain under their storage owner. |
| `RegisterVolumeHead` | Registers an administrator-staged regular file at `objects/<head_resource_id>/data` under the state directory. Supply `volume_id` and `head_resource_id`. |
| `ReserveWriterSet`, `QueryWriterSet`, `ReleaseWriterReservation` | Reserves a group of `heads` entries containing volume and head IDs. The broker keeps the backing OFD locks and enforces a global unique volume and inode identity. Query by operation ID and release using the reservation's `expected_revision`. |
| `ReconcileExecution` | An existing process reestablishes its recorded process identity after a broker restart. |
| `CompleteRecovery` | Transitions to ready using the current `broker_session_id` after resolving unknown executions and leases, pending intents and held reservations. |

Reservations report `writer_authority=false`. Managed block writer grants use the explicit FD protocol below. StatePoint publication and activation need the corresponding capture and identity protocols. Recovery retains unknown reservations and blocks new admissions and GC. The catalog uses WAL, foreign keys and FULL synchronous writes.

Local Linux control code can call `smolvm_resourced::client::query_operation(socket_path, bundle_digest, operation_id)`. It returns a typed operation receipt in the deep route and preserves the worker's error code.

## Sealed RAM descriptor escrow

An authenticated execution can send immutable RAM backings with `SCM_RIGHTS` under an accepted `generation` operation.

1. Call `RegisterGenerationBegin` with `transfer_id`, `resource_id`, `descriptor_digest`, and `descriptor`. The descriptor defines sorted, page-aligned `regions` with `gpa`, `length`, and contiguous `extents`. Each extent has `offset`, `length`, `backing_id`, and `backing_offset`. Provide an ID-to-length `backing_sizes` object. Compute the digest from compact UTF-8 JSON with object keys sorted.
2. Call `RegisterGenerationBatch` with `transfer_id` and a zero-based `batch_index`. Each top-level `fd_table` row gives the zero-based packet `index`, the backing `resource_id`, and the `immutable_backing` role. Each packet accepts up to 64 FDs. The broker checks memfd identity, size and write/grow/shrink seals and reopens validated descriptors read-only.
3. Call `RegisterGenerationCommit` with `transfer_id`. A complete transfer publishes the resource and its operation pin in one catalog transaction. `AbortGenerationTransfer` releases the staging FDs before publication.

To receive descriptors, accept a `resource_lease` operation and have its execution call `AcquireResourceLease` with `lease_id`, `resource_id`, `access=ro`, and the zero-based `offset` into the backing list. The resource must belong to the same bundle. The broker persists the consumer root before passing FDs. Follow `next_offset` until it reaches `total`. Confirm receipt with `AckAttached` using `lease_id` and `expected_revision`, and use `ReleaseResourceLease` once the consumer has closed its references. Requests and responses with descriptors require a client that uses `sendmsg` and `recvmsg`.

After a broker restart on the same boot, staged transfers are lost and a generation with a potentially live provider is missing. Existing leases remain unknown and pinned. A live provider can call `ReconcileExecution` and then send its retained handles through `ReconcileExecutionExports`, with up to 64 descriptor table entries per packet. A publisher can use its original `transfer_id` under the generation operation while its operation pin remains active. A consumer sends `lease_id` and the unknown lease's `expected_revision` under the original lease operation. The broker matches each sealed descriptor's device, inode and size against the committed capture. When the complete set arrives, one catalog transaction makes the generation available and reattaches the lease when applicable. A consumer receives the newest lease revision in that receipt.

A consumer that has closed its references can release the lease. The broker can also release it after confirming the execution exited. Without a remaining provider, the generation becomes lost. A changed host boot ID marks volatile descriptors lost. Catalog metadata preserves identity and layout across restart. The actual bytes must come from a live holder of the backing descriptors.

```sh
cargo test --locked -p smolvm-resourced
python3 crates/smolvm-resourced/tests/worker-resource.py target/debug/smolvm-resourced -v
```

## Diskless KVM handoff probe

Run on a private Linux x86-64 KVM worker. Use the Linux `BLK=1 NET=1` libkrun build with `krun_export_snapshot_ram_v1`, `krun_set_diskless_snapshot_ram_v1` and matching firmware. The worker sees three separate host processes as the source, child and grandchild, with explicit launch permits for their actual PIDs.

```sh
cc -O2 -Wall -Wextra -Werror -static \
  crates/smolvm-resourced/tests/kvm-generation-guest.c -o "$GUEST_TEST_BIN"
LD_LIBRARY_PATH="$FIRMWARE_DIR" python3 -B crates/smolvm-resourced/tests/kvm-generation.py \
  target/debug/smolvm-resourced "$LIBKRUN_SO" "$GUEST_TEST_BIN"
```

The probe snapshots a two-vCPU, 512 MiB guest and sends the sealed RAM directly from the VMM process. It restarts the broker and recovers the backing from the original VMM while the operation pin is held. It then kills the source and deletes its original capture directory. The child restores from the small checkpoint and the broker's read-only memfd lease. It advances the inherited guest counter, reads the saved sentinel and uses private mappings of the original backing. The probe restarts the broker again while the child keeps executing and confirms recovery from the child's retained lease. A grandchild resumes after its own parent exits using a generation that shares the original backings and adds private deltas.

On the project KVM worker with Linux guest kernel 6.18.60, the source captured at tick 3 using three sealed backings. The child first ran at tick 4, read the sentinel at tick 9, and advanced to tick 11 through broker restart. The grandchild first ran at tick 12 using six sealed backings. The child and grandchild mapped those backings privately. The separate WorkerResource integration tests cover the two-bundle OFD writer-reservation conflict and restart fence. The diskless probe covers RAM and VMM continuation. Full writable block attachment, process isolation policy, guest identity, and product activation remain separate acceptance gates.

## Managed blocks and writer grants

Import a raw base with `ImportImmutableBlock` under an active catalog operation. Supply `resource_id`, `capacity_bytes`, and the expected `content_sha256`, plus an `O_RDONLY` descriptor with the `block_import` role. The broker copies and verifies the bytes in a private object directory, publishes a durable immutable generation, then allows the staging file to be removed.

Call `CreateVolumeHead` with a unique `resource_id`, `volume_id` and `capacity_bytes`. Pass `backing_id` to create a thin qcow2 head over the exact immutable generation. A head without a backing is sparse raw. The committed closure is available through `QueryBlockClosure`. Qcow2 headers store backing resource IDs. The VMM matches those IDs and formats to supplied ancestor FDs.

1. The control process reserves a complete set of heads with `ReserveWriterSet`.
2. The registered VMM calls `AcquireWriterSet` under that operation with a new `grant_id` and the reservation's `expected_revision`. The broker records the offer before delivering the entire set. The `block_writer` entries carry the locked `O_RDWR` descriptions. The `block_ancestor` entries carry read-only immutable descriptions.
3. The VMM installs the full device set with `krun_attach_block_set_v1` and calls `AckWriterSetAttached` with the grant revision. This drops the broker's writer duplicates and allows the control operation to finish while the actual grant remains live. The supplied libkrun path uses the original open file descriptions and full synchronous block I/O.
4. A surviving VMM reestablishes its process identity after restart and calls `ReconcileWriterSet` with the unknown grant revision and every exact writable descriptor. The broker verifies the inode and existing exclusive OFD for each head. A failed or partial proof preserves the grant.
5. Finalizing a dead execution requires fresh exclusive OFD locks on all issued heads and a successful sync. An OFD inherited by another process prevents release even after the registered VMM exits.

The x86-64 KVM block probe boots two distinct registered executions. The first reads the shared immutable base from two qcow2 heads and writes and flushes distinct markers. Broker restart recovers the live writer, and a deliberately inherited duplicate prevents death fencing. Once that holder exits, the second execution acquires both heads and reads both persisted markers. The immutable base stays byte-for-byte identical.

```sh
cc -O2 -Wall -Wextra -Werror -static \
  crates/smolvm-resourced/tests/kvm-block-guest.c -o "$GUEST_TEST_BIN"
LD_LIBRARY_PATH="$FIRMWARE_DIR" python3 -B crates/smolvm-resourced/tests/kvm-block.py \
  target/debug/smolvm-resourced "$LIBKRUN_SO" "$GUEST_TEST_BIN"
```

The current ABI attaches managed disk sets at cold boot. Captured multi-disk pivots, live detach, online expansion and exact-generation restore require the held capture and activation path.
### Private IPv4 reservations

The Worker administrator registers an RFC1918 CIDR and its isolated route
domain with `RegisterPrivateNetwork`. Each active `launch` or
`network_reservation` operation can call `ReserveNetworkAttachment` with its
attachment ID, network ID, stable device ID, and mode. `native` assigns the
private address to the Guest. `fixed_internal` keeps the requested
`guest_ipv4` and allocates a distinct private address in the route domain.

`QueryNetworkReservation` reads the original operation's reservation.
`ReleaseNetworkReservation` takes the attachment ID and expected revision,
and releases only an unissued reservation. Unknown reservations retain their
address and device pins. This API reserves identifiers and addresses, while
TAP delivery, traffic publication, and identity activation require their
own Worker admission.
