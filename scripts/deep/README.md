# Deep runtime source build

Run the build on a provisioned Linux x86-64 builder with the locked toolchain and a clean smolvm checkout with both submodules initialized. The guest Rust target is `x86_64-unknown-linux-musl`. Use the platform repository's `packaging/deep/bundle.py` for input and artifact verification. Select a glibc 2.31 or older release builder.

```bash
common=(--source-lock "$build_lock" --toolchain-lock "$toolchain_lock"
        --kernel-archive "$kernel_archive" --builder-image "$builder_image"
        --bundle-tool "$bundle_tool" --jobs 2)
scripts/deep/build-bundle.sh "${common[@]}" --stage libraries --output "$library_stage"
scripts/deep/build-bundle.sh "${common[@]}" --stage runtime --output "$runtime_stage" \
    --libraries "$library_stage" --rootfs-seed "$oci_seed" \
    --rootfs-input-lock scripts/deep/oci-rootfs-input.json
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

The stage output is intended for subsequent Bundle packaging. Packaging requires production identity, profile and license inputs. An isolated KVM boot and exec gate is still required for release.
