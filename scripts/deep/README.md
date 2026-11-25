# Deep runtime source build

Run the build on a provisioned Linux x86-64 builder with the locked toolchain and a clean smolvm checkout with both submodules initialized. The guest Rust target is `x86_64-unknown-linux-musl`. Use the platform repository's `packaging/deep/bundle.py` for input and artifact verification. Select a glibc 2.31 or older release builder.

```bash
common=(--source-lock "$build_lock" --toolchain-lock "$toolchain_lock"
        --kernel-archive "$kernel_archive" --builder-image "$builder_image"
        --bundle-tool "$bundle_tool" --jobs 2)
scripts/deep/build-bundle.sh "${common[@]}" --stage libraries --output "$library_stage"
scripts/deep/build-bundle.sh "${common[@]}" --stage runtime --output "$runtime_stage" \
    --libraries "$library_stage" --rootfs-seed "$oci_seed" \
    --rootfs-input-lock scripts/deep/locks/oci-x86_64.json
```

The libraries stage builds firmware, static guest init and libkrun in a private checkout. It applies kernel config fragments listed in `RuntimeBuildLock/1.patches` under `libkrunfw/config-fragments/`, in lock order. The inputs must include the kernel archive pinned by both the build lock and the firmware Makefile. The staged configuration is checked before and after firmware compilation.

Prepare the OCI seed with the locked `scripts/build-agent-rootfs.sh` recipe and the source-built crun. Archive the seed with its Alpine package database and crane intact. Commit a seed input lock with these fields, and include its smolvm-relative path and digest in `RuntimeToolchainLock/1.lockfiles`.

| Field | Value |
| --- | --- |
| `schema` | `RuntimeRootfsSeed/1` |
| `recipe` | `scripts/build-agent-rootfs.sh` |
| `seed_sha256` | Prefixed SHA-256 of the gzip-compressed tar archive |
| `crun_build_sha256` | Prefixed SHA-256 of `usr/share/smolvm/crun/build.json` |
| `package_db_sha256` | Prefixed SHA-256 of `lib/apk/db/installed` |
| `crane_sha256` | Prefixed SHA-256 of `usr/local/bin/crane` |

The runtime stage verifies the seed and matches its crun provenance to the pinned recipe, patches, inputs and installed binary. It builds the Agent, smolvm with `deep-runtime` enabled, and resourced from the locked source checkout. The OCI archive contains the newly built Agent. Staging records include the seed input lock, the rootfs provenance and the resulting artifact digests. Deployment must set `SMOLVM_AGENT_ROOTFS` to the extracted, verified rootfs directory.

The manual **Build deep runtime from source** workflow runs both stages inside the digest-pinned builder image. Dispatch it from the smolvm commit in the build lock and supply the pinned platform checkout and lock directory, plus HTTPS locations for the kernel and OCI seed. The workflow stores the runtime stage as a tar archive to preserve file modes.

The stage output is intended for subsequent Bundle packaging. Packaging requires production identity, profile and license inputs. An isolated KVM boot and exec gate is still required for release.

## Managed runtime benchmark

Run the benchmark on a development Worker with KVM, an installed managed
RuntimeBundle, Python 3.11 or newer and a C compiler capable of static linking.

```bash
sudo python3 scripts/deep/bench-managed-runtime.py \
  --bundle "$BUNDLE" --output /var/tmp/managed-bench.json \
  --samples 2 --modes clean dirty --read-lanes 16 4 0 --durable
```

Each sample runs inside private mount and network namespaces. It exercises
cold start, repeated capture, concurrent fanout, three recursive generations,
checkpoint publication and two reads of a durable StatePoint. Use
`--fanout` to fit the Worker's admitted vCPU budget. A focused lane count
comparison can use `--depth 0` and omit `--durable`.

The Guest writes and verifies separate markers on two real writable block
devices. In each restored Guest a new workload forks four readers, performs
1,024 direct random 4 KiB reads and verifies every returned block. The
`dirty` workload also overwrites 16 MiB of Guest memory per heartbeat.

The JSON report contains every successful sample, observed Worker operation
phases and per-scenario p50 and p95 values. Source heartbeat gaps measure the
change in the Guest's ordinary execution loop. Host detection of the first
workload result uses the polling resolution of the harness. The report includes
per-target PSS, Linux RSS high-water values, thread counts, host I/O counters
and observed read rates. Global host page caches remain in place. The first
and repeated durable reads use the same StatePoint and separate target
incarnations. The fixture uses local disks and a Guest without a TAP device.

The lane sweep requires a libkrun build that supports `KRUN_BLOCK_READ_LANES`.
The expected host VMM thread difference for the three synchronous block
devices is 36 threads between 16 and 4 lanes or 48 between 16 and 0.

The optional `--guest-dir` accepts static `bench-guest-clean` and
`bench-guest-dirty` artifacts built from the fixture with `DIRTY_MIB=0`
and `DIRTY_MIB=16`. Their SHA-256 values are recorded in each sample.
