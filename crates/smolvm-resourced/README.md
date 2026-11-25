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
| `BeginOperation` | Reserves the per-instance operation slot using the expected execution. Supported `kind` values are `catalog`, `launch`, and `writer_reservation`. |
| `QueryOperation` | Returns the record for the envelope's `operation_id` within its `route_id` and `bundle_digest`. |
| `FinishOperation` | Releases the operation slot with `abort` and `expected_revision`. First drop operation pins and writer reservations. |
| `IssueLaunchPermit` | Short-lived permit for a target `pid` and `uid` under the accepted launch operation. Name the next epoch and the new incarnation in `expected`. |
| `RegisterExecution` | The actual process redeems `launch_permit` with that same scope and operation. It is bound by peer UID/PID, process start time, pidfd and the registered executable SHA-256. The initial registration records a closed network state. |
| `QueryExecution`, `FinalizeExecutionExit` | Query the named execution or confirm its process exit. Exit processing respects held reservations. |
| `RegisterResource`, `QueryResource` | Register a catalog descriptor with `resource_id`, `durability` and a JSON `descriptor`, or query by `resource_id`. |
| `AddResourceEdge` | Adds a directed edge using `owner_resource_id`, `child_resource_id` and `role`. Rejects cycles. |
| `AddOwnerRef`, `DropOwnerRef` | Manage a root with `owner_kind`, `owner_id`, `resource_id` and `expected_revision`. An `operation` root pins objects to that operation. |
| `QueryOwnerClosure` | Reads the graph reachable from `owner_kind` and `owner_id`. |
| `MarkResourceForGC`, `CollectResource` | Mark and collect a catalog descriptor by `resource_id` and `expected_revision` after checking roots, incoming edges and operation ownership. Backing data files remain under their storage owner. |
| `RegisterVolumeHead` | Registers an administrator-staged regular file at `objects/<head_resource_id>/data` under the state directory. Supply `volume_id` and `head_resource_id`. |
| `ReserveWriterSet`, `QueryWriterSet`, `ReleaseWriterReservation` | Reserves a group of `heads` entries containing volume and head IDs. The broker keeps the backing OFD locks and enforces a global unique volume and inode identity. Query by operation ID and release using the reservation's `expected_revision`. |
| `ReconcileExecution` | An existing process reestablishes its recorded process identity after a broker restart. |
| `CompleteRecovery` | Transitions to ready using the current `broker_session_id` after resolving unknown executions, pending intents and held reservations. |

Reservations report `writer_authority=false`. Actual writer grants, descriptor leases, generation publication and VMM activation return `E_CAPABILITY_UNSUPPORTED`. Recovery retains unknown reservations and blocks new admissions and GC. A changed host boot ID marks volatile descriptors lost. The catalog uses WAL, foreign keys and FULL synchronous writes.

Local Linux control code can call `smolvm_resourced::client::query_operation(socket_path, bundle_digest, operation_id)`. It returns a typed operation receipt in the deep route and preserves the worker's error code.

```sh
cargo test --locked -p smolvm-resourced
python3 crates/smolvm-resourced/tests/worker-resource.py target/debug/smolvm-resourced -v
```
