#!/usr/bin/env bash
# Build the libraries and the host/guest runtime inputs for a deep RuntimeBundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
BUILD_LOCK= TOOLCHAIN_LOCK= KERNEL_ARCHIVE= BUILDER_IMAGE= BUNDLE_TOOL= OUTPUT= STAGE=
LIBRARIES= ROOTFS_SEED= ROOTFS_INPUT_LOCK=
JOBS="$(nproc)"

usage() {
    cat <<'EOF'
Usage: scripts/deep/build-bundle.sh --stage libraries|runtime --source-lock FILE
    --toolchain-lock FILE --kernel-archive FILE --builder-image IMAGE@sha256:DIGEST
    --bundle-tool FILE --output DIR [--jobs N]

Run from the clean, pinned smolvm checkout with initialized libkrun/libkrunfw.
The libraries stage builds the kernel, VMM libraries and static init. The runtime
stage also requires --libraries DIR, --rootfs-seed FILE and --rootfs-input-lock
REPO_PATH. It adds the CLI, resourced, Agent and OCI template to the verified
libraries stage. Both stages write a fresh directory inside the locked builder.
EOF
}

fail() {
    printf 'deep build: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --stage|--source-lock|--toolchain-lock|--kernel-archive|--builder-image|--bundle-tool|--output|--jobs|\
        --libraries|--rootfs-seed|--rootfs-input-lock)
            [[ -n "${2:-}" && "$2" != --* ]] || fail "$1 requires a value"
            case "$1" in
                --stage) STAGE="$2" ;;
                --source-lock) BUILD_LOCK="$2" ;;
                --toolchain-lock) TOOLCHAIN_LOCK="$2" ;;
                --kernel-archive) KERNEL_ARCHIVE="$2" ;;
                --builder-image) BUILDER_IMAGE="$2" ;;
                --bundle-tool) BUNDLE_TOOL="$2" ;;
                --output) OUTPUT="$2" ;;
                --jobs) JOBS="$2" ;;
                --libraries) LIBRARIES="$2" ;;
                --rootfs-seed) ROOTFS_SEED="$2" ;;
                --rootfs-input-lock) ROOTFS_INPUT_LOCK="$2" ;;
            esac
            shift 2 ;;
        *) fail "unknown option $1" ;;
    esac
done

case "$STAGE" in
    libraries) [[ -z "$LIBRARIES$ROOTFS_SEED$ROOTFS_INPUT_LOCK" ]] || fail "rootfs inputs require --stage runtime" ;;
    runtime)
        [[ -n "$LIBRARIES" && -n "$ROOTFS_SEED" && -n "$ROOTFS_INPUT_LOCK" ]] ||
            fail "runtime stage requires --libraries, --rootfs-seed and --rootfs-input-lock"
        LIBRARIES="$(realpath -e -- "$LIBRARIES")"
        ROOTFS_SEED="$(realpath -e -- "$ROOTFS_SEED")" ;;
    *) fail "expected --stage libraries or --stage runtime" ;;
esac
[[ -n "$BUILD_LOCK" && -n "$TOOLCHAIN_LOCK" && -n "$KERNEL_ARCHIVE" &&
    -n "$BUILDER_IMAGE" && -n "$BUNDLE_TOOL" && -n "$OUTPUT" ]] || fail "missing required options; see --help"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || fail "--jobs must be a positive integer"
[[ "$(uname -s):$(uname -m)" == Linux:x86_64 ]] || fail "the deep build targets Linux x86_64"

export LC_ALL=C GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 GIT_LFS_SKIP_SMUDGE=1 PYTHONDONTWRITEBYTECODE=1
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET CARGO_BUILD_TARGET_DIR CARGO_ENCODED_RUSTFLAGS RUSTFLAGS RUSTC_WRAPPER \
    RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTFLAGS KRUN_INIT_BINARY_PATH \
    MAKEFLAGS MFLAGS GNUMAKEFLAGS KBUILD_OUTPUT KCONFIG_CONFIG KERNEL_CONFIG_FRAGMENTS ARCH CROSS_COMPILE \
    SEV TDX AWS_NITRO INPUT VHOST_USER VIRGL_RESOURCE_MAP2 TIMESYNC INIT_BLOB VARIANT LINUX_GLIBC

OUTPUT_PARENT="$(realpath -e -- "$(dirname -- "$OUTPUT")")"
OUTPUT="$OUTPUT_PARENT/$(basename -- "$OUTPUT")"
BUNDLE_TOOL="$(realpath -e -- "$BUNDLE_TOOL")"
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || fail "output exists: $OUTPUT"
[[ "$OUTPUT" != "$SOURCE_ROOT" && "$OUTPUT" != "$SOURCE_ROOT/"* ]] || fail "output must be outside the input checkout"

WORK="$(mktemp -d -- "$OUTPUT_PARENT/.deep-build.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
CANDIDATE="$WORK/artifacts"
SOURCES="$WORK/smolvm"
mkdir -p "$CANDIDATE"/{guest,lib,metadata,sources}
install -m 0644 -- "$BUILD_LOCK" "$CANDIDATE/metadata/build-lock.json"
install -m 0644 -- "$TOOLCHAIN_LOCK" "$CANDIDATE/metadata/toolchain-lock.json"
install -m 0644 -- "$KERNEL_ARCHIVE" "$WORK/kernel.tar.xz"
BUILD_LOCK="$CANDIDATE/metadata/build-lock.json"
TOOLCHAIN_LOCK="$CANDIDATE/metadata/toolchain-lock.json"
KERNEL_ARCHIVE="$WORK/kernel.tar.xz"

python3 "$BUNDLE_TOOL" check-inputs --build-lock "$BUILD_LOCK" --toolchain-lock "$TOOLCHAIN_LOCK" \
    --smolvm "$SOURCE_ROOT" --kernel-archive "$KERNEL_ARCHIVE" --builder-image "$BUILDER_IMAGE"

build_values="$(python3 - "$BUILD_LOCK" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lock = json.load(handle)
if lock["gitlinks"] != {name: name for name in ("libkrun", "libkrunfw")}:
    sys.exit("deep build: the upstream Makefiles require the libkrun and libkrunfw checkout paths")
flags = {"INPUT": 1, "SKIP_LIBKRUNFW": 0, **lock["flags"]}
if (any(type(value) is not int for value in flags.values()) or
        flags != {"BLK": 1, "NET": 1, "INPUT": 1, "GPU": 0, "SKIP_LIBKRUNFW": 0}):
    sys.exit("deep build: the libraries stage requires BLK=1 NET=1 INPUT=1 GPU=0 SKIP_LIBKRUNFW=0")
glibc = tuple(int(piece) for piece in lock["maximum_glibc"].split("."))
if glibc + (0,) * (3 - len(glibc)) > (2, 31, 0):
    sys.exit("deep build: release artifacts must support glibc 2.31 or earlier")
print(*(lock["sources"][name]["commit"] for name in ("smolvm", "libkrun", "libkrunfw")))
print(lock["kernel"]["release"], lock["maximum_glibc"])
for patch in lock["patches"]:
    if (patch["repository"] == "libkrunfw" and patch["path"].startswith("config-fragments/")
            and patch["path"].endswith(".config")):
        print(patch["path"])
PY
)"
mapfile -t BUILD_VALUES <<< "$build_values"
read -r SMOLVM_COMMIT KRUN_COMMIT FW_COMMIT <<< "${BUILD_VALUES[0]}"
read -r KERNEL_RELEASE MAX_GLIBC <<< "${BUILD_VALUES[1]}"
KERNEL_FRAGMENTS=("${BUILD_VALUES[@]:2}")

stage_checkout() {
    local input="$1" stage="$2" commit="$3" exclude_libraries="$4"
    mkdir -p "$stage"
    git -C "$stage" init --quiet --template=
    git -C "$stage" -c protocol.allow=never -c protocol.file.allow=always \
        fetch --quiet --no-recurse-submodules --no-tags --update-shallow "$input" "$commit"
    if [[ "$exclude_libraries" == yes ]]; then
        # The original checkout is independently validated including LFS files.
        # This staged tree only receives newly compiled lib/ outputs.
        printf '/*\n!/lib/\n' | git -C "$stage" sparse-checkout set --no-cone --stdin
    fi
    git -C "$stage" -c core.hooksPath=/dev/null checkout --quiet --detach "$commit"
}

stage_checkout "$SOURCE_ROOT" "$SOURCES" "$SMOLVM_COMMIT" yes

build_libraries() {
    stage_checkout "$SOURCE_ROOT/libkrun" "$SOURCES/libkrun" "$KRUN_COMMIT" no
    stage_checkout "$SOURCE_ROOT/libkrunfw" "$SOURCES/libkrunfw" "$FW_COMMIT" no

    FW="$SOURCES/libkrunfw"
    KERNEL_NAME="linux-$KERNEL_RELEASE"
    KERNEL_DIR="$FW/$KERNEL_NAME"
    makefile_kernel="$(awk '$1 == "KERNEL_VERSION" && $2 == "=" {print $3}' "$FW/Makefile")"
    makefile_sha256="$(awk '$1 == "KERNEL_SHA256" && $2 == "=" {print $3}' "$FW/Makefile")"
    [[ "$makefile_kernel" == "$KERNEL_NAME" ]] || fail "locked kernel release differs from the firmware Makefile"
    [[ "$(sha256sum -- "$KERNEL_ARCHIVE" | cut -d' ' -f1)" == "$makefile_sha256" ]] ||
        fail "locked kernel digest differs from the firmware Makefile"

    prepare_kernel() (
        cd "$FW"
        tar -xJf "$KERNEL_ARCHIVE"
        [[ -f "$KERNEL_NAME/Makefile" ]] || fail "kernel archive does not contain $KERNEL_NAME"
        patch_series="$(find patches -name '0*.patch' -type f | sort)"
        if [[ -n "$patch_series" ]]; then
            while IFS= read -r patch_file; do
                patch --batch --forward --fuzz=0 -p1 -d "$KERNEL_NAME" < "$patch_file"
            done <<< "$patch_series"
        fi
        cp config-libkrunfw_x86_64 "$KERNEL_NAME/.config"
        if ((${#KERNEL_FRAGMENTS[@]})); then
            "$KERNEL_NAME/scripts/kconfig/merge_config.sh" -m -O "$KERNEL_NAME" \
                "$KERNEL_NAME/.config" "${KERNEL_FRAGMENTS[@]}"
        fi
        cd "$KERNEL_NAME"
        make --no-print-directory CC=gcc olddefconfig
    )

    prepare_kernel
    cp "$KERNEL_DIR/.config" "$WORK/verified-kernel.config"
    python3 - "$BUNDLE_TOOL" "$BUILD_LOCK" "$KERNEL_DIR/.config" <<'PY'
import json
from pathlib import Path
import runpy
import sys

sys.path.insert(0, str(Path(sys.argv[1]).parent))
bundle = runpy.run_path(sys.argv[1])
with open(sys.argv[2], encoding="utf-8") as handle:
    lock = json.load(handle)
try:
    bundle["verify_config"](Path(sys.argv[3]), lock["kernel"]["required_config"])
except bundle["BundleError"] as error:
    sys.exit(f"deep build: {error}")
PY

    # Verify the staged script is the revision containing the locked source mode.
    cmp -s "$SOURCE_ROOT/scripts/build-libkrun-linux.sh" "$SOURCES/scripts/build-libkrun-linux.sh" ||
        fail "the staged build script differs from the verified checkout"
    GPU=0 SKIP_DEPS=1 SKIP_LIBKRUNFW=0 SMOLVM_VERIFIED_SOURCE_BUILD=1 \
        SMOLVM_VERIFIED_KERNEL_TREE="$KERNEL_NAME" SMOLVM_BUILD_JOBS="$JOBS" \
        "$SOURCES/scripts/build-libkrun-linux.sh"
    cmp -s "$WORK/verified-kernel.config" "$KERNEL_DIR/.config" || fail "kernel build changed the verified configuration"

    LIBS="$SOURCES/lib/linux-x86_64"
    "$SOURCES/scripts/check-libkrun-provenance.sh"
    "$SOURCES/scripts/check-krun-exports.sh"
    "$SOURCES/scripts/check-glibc-floor.sh" "$MAX_GLIBC" "$LIBS/libkrun.so" "$LIBS/libkrunfw.so"
    python3 "$SOURCES/scripts/check-krun-init-static.py" "$LIBS/libkrun.so"

    # Store the SONAME aliases as regular files in the Bundle stage.
    cp -L -- "$LIBS"/libkrun.so* "$LIBS"/libkrunfw.so* "$LIBS/libkrun.provenance" "$CANDIDATE/lib/"
    install -m 0644 -- "$KERNEL_DIR/vmlinux" "$CANDIDATE/guest/vmlinux"
    install -m 0644 -- "$KERNEL_DIR/.config" "$CANDIDATE/guest/kernel.config"
    install -m 0755 -- "$SOURCES/libkrun/target/deep-init/x86_64-unknown-linux-musl/release/krun-init" "$CANDIDATE/guest/init"
    git -C "$SOURCES" archive "$SMOLVM_COMMIT" -- . ':(exclude)lib' | gzip -n > "$CANDIDATE/sources/smolvm.tar.gz"
    git -C "$SOURCES/libkrun" archive "$KRUN_COMMIT" | gzip -n > "$CANDIDATE/sources/libkrun.tar.gz"
    git -C "$SOURCES/libkrunfw" archive "$FW_COMMIT" | gzip -n > "$CANDIDATE/sources/libkrunfw.tar.gz"
}

build_runtime() {
    for lock_name in build-lock toolchain-lock; do
        cmp -s "$CANDIDATE/metadata/$lock_name.json" "$LIBRARIES/metadata/$lock_name.json" ||
            fail "libraries stage uses a different $lock_name"
    done
    python3 "$BUNDLE_TOOL" check-libraries --artifacts "$LIBRARIES"
    cp -p -- "$LIBRARIES/lib/"libkrun.so* "$LIBRARIES/lib/"libkrunfw.so* \
        "$LIBRARIES/lib/libkrun.provenance" "$CANDIDATE/lib/"
    cp -p -- "$LIBRARIES/guest/"{vmlinux,kernel.config,init} "$CANDIDATE/guest/"
    cp -p -- "$LIBRARIES/sources/"{smolvm,libkrun,libkrunfw}.tar.gz "$CANDIDATE/sources/"
    cp -p -- "$LIBRARIES/metadata/build-record.json" "$CANDIDATE/metadata/build-record.json"
    python3 "$BUNDLE_TOOL" check-libraries --artifacts "$CANDIDATE"

    ( cd "$SOURCES"; cargo metadata --locked --no-deps --format-version 1 ) > "$WORK/cargo-metadata.json"
    python3 - "$WORK/cargo-metadata.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    packages = {package["name"]: package for package in json.load(handle)["packages"]}
if "deep-runtime" not in packages.get("smolvm", {}).get("features", {}):
    sys.exit("deep build: pinned smolvm checkout does not define the deep-runtime Cargo feature")
if not {"smolvm-agent", "smolvm-resourced"} <= packages.keys():
    sys.exit("deep build: pinned smolvm checkout must contain Agent and resourced packages")
PY

    ( cd "$SOURCES"; cargo build --locked --jobs "$JOBS" --profile release-small \
        --target x86_64-unknown-linux-musl -p smolvm-agent )
    install -m 0755 -- "$SOURCES/target/x86_64-unknown-linux-musl/release-small/smolvm-agent" "$CANDIDATE/guest/agent"
    install -m 0644 -- "$ROOTFS_SEED" "$WORK/oci-seed.tar.gz"
    python3 "$SOURCES/scripts/deep/assemble-oci-rootfs.py" --source-root "$SOURCES" \
        --toolchain-lock "$TOOLCHAIN_LOCK" --input-lock "$ROOTFS_INPUT_LOCK" --seed "$WORK/oci-seed.tar.gz" \
        --agent "$CANDIDATE/guest/agent" --output "$CANDIDATE/guest/oci-rootfs.tar.gz" --metadata "$CANDIDATE/metadata" \
        --timestamp "$(git -C "$SOURCES" show -s --format=%ct "$SMOLVM_COMMIT")"

    ( cd "$SOURCES"; cargo build --locked --jobs "$JOBS" --release -p smolvm --features deep-runtime;
        cargo build --locked --jobs "$JOBS" --release -p smolvm-resourced )
    install -m 0755 -- "$SOURCES/target/release/smolvm" "$CANDIDATE/smolvm-bin"
    install -m 0755 -- "$SOURCES/target/release/smolvm-resourced" "$CANDIDATE/smolvm-resourced"
    install -m 0755 -- "$SOURCES/scripts/smolvm-wrapper.sh" "$CANDIDATE/smolvm"
    "$SOURCES/scripts/check-glibc-floor.sh" "$MAX_GLIBC" "$CANDIDATE/smolvm-bin" "$CANDIDATE/smolvm-resourced"
}

if [[ "$STAGE" == libraries ]]; then
    build_libraries
else
    build_runtime
fi

python3 - "$CANDIDATE" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])

def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return "sha256:" + result.hexdigest()

locks_and_record = {"metadata/build-lock.json", "metadata/toolchain-lock.json", "metadata/build-record.json"}
paths = {path.relative_to(root).as_posix(): path for path in root.rglob("*") if path.is_file()}
outputs = {name: digest(path) for name, path in paths.items() if name not in locks_and_record}
record = {"schema": "RuntimeBuildRecord/1", "build_lock_digest": digest(root / "metadata/build-lock.json"),
          "outputs": outputs}
(root / "metadata/build-record.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY

python3 "$BUNDLE_TOOL" "check-$STAGE" --artifacts "$CANDIDATE"
mv -T --no-clobber -- "$CANDIDATE" "$OUTPUT"
[[ ! -d "$CANDIDATE" ]] || fail "output was created during the build: $OUTPUT"
printf 'deep build: verified %s stage at %s\n' "$STAGE" "$OUTPUT"
if [[ "$STAGE" == runtime ]]; then
    printf 'deep build: RuntimeBundle packaging also requires the production identity helper and profile inputs\n'
fi
