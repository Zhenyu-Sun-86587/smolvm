#!/usr/bin/env python3
"""Assemble the OCI template from a locked source-prepared seed and fresh agent."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


RECIPE = "scripts/build-agent-rootfs.sh"
CRUN = "usr/bin/crun"
CRUN_BUILD = "usr/share/smolvm/crun/build.json"
PACKAGE_DB = "lib/apk/db/installed"
CRANE = "usr/local/bin/crane"
AGENT = "usr/local/bin/smolvm-agent"
INIT = "sbin/init"
IDENTITY_HELPER = "sbin/smolvm-identity-helper"
REQUIRED_DIRS = {"usr", "usr/local", "usr/local/bin", "sbin"}
SEED_DIGESTS = {"seed_sha256", "crun_build_sha256", "package_db_sha256", "crane_sha256"}


def digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(block)
    return "sha256:" + result.hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return digest(stream)


def check_lock(lock):
    if (set(lock) != {"schema", "recipe", *SEED_DIGESTS} or
            lock["schema"] != "RuntimeRootfsSeed/1" or lock["recipe"] != RECIPE):
        raise ValueError("expected a RuntimeRootfsSeed/1 lock for the smolvm Agent rootfs recipe")
    for key in SEED_DIGESTS:
        if not isinstance(lock[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", lock[key]):
            raise ValueError(f"invalid rootfs seed digest {key}")


def archive_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe rootfs archive path {name!r}")
    return path.as_posix()


def read_member(seed, member):
    if not member.isfile() or member.size == 0:
        raise ValueError(f"expected a nonempty seed file at {member.name}")
    return seed.extractfile(member)


def verify_crun(seed, members, root, lock):
    with read_member(seed, members[CRUN_BUILD]) as handle:
        metadata = handle.read(1024 * 1024 + 1)
    if (len(metadata) > 1024 * 1024 or
            "sha256:" + hashlib.sha256(metadata).hexdigest() != lock["crun_build_sha256"]):
        raise ValueError("seed crun build metadata digest mismatch")
    inputs = json.loads((root / "patches/crun/build-inputs.json").read_text())
    with read_member(seed, members[CRUN]) as handle:
        binary = digest(handle)
    if not members[CRUN].mode & 0o111:
        raise ValueError("seed crun is not executable")
    expected = {
        "version": inputs["version"], "arch": "x86_64", "source": inputs["source"],
        "toolchain_version": inputs["toolchain"]["version"],
        "toolchain": inputs["toolchain"]["hosts"]["x86_64-linux"],
        "sysroot": inputs["sysroots"]["x86_64"],
        "patch_sha256": file_digest(root / "patches/crun/0001-watch-populated-cgroups-only.patch").split(":")[1],
        "builder_sha256": file_digest(root / "scripts/build-crun.py").split(":")[1],
        "binary_sha256": binary.split(":")[1],
    }
    if json.loads(metadata) != expected:
        raise ValueError("seed crun build does not match the pinned recipe, inputs and installed binary")


def assemble(seed_path, agent, helper, output, root, lock, timestamp):
    if file_digest(seed_path) != lock["seed_sha256"]:
        raise ValueError("OCI seed archive digest mismatch")
    with tarfile.open(seed_path, "r:gz") as seed:
        members = {}
        for member in seed:
            name = archive_path(member.name)
            if name in members:
                raise ValueError(f"duplicate rootfs archive path {name}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"unsupported rootfs archive entry at {name}")
            if member.islnk() and archive_path(member.linkname) in {AGENT, INIT, IDENTITY_HELPER}:
                raise ValueError(f"rootfs hardlink to overwritten content at {name}")
            members[name] = member
        for directory in REQUIRED_DIRS:
            if directory not in members or not members[directory].isdir():
                raise ValueError(f"expected a regular rootfs directory at {directory}")

        def verify_seed_file(path, expected):
            with read_member(seed, members[path]) as handle:
                if digest(handle) != lock[expected]:
                    raise ValueError(f"seed digest mismatch at {path}")

        verify_seed_file(PACKAGE_DB, "package_db_sha256")
        verify_seed_file(CRANE, "crane_sha256")
        verify_crun(seed, members, root, lock)

        with output.open("xb") as stream:
            with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as packed:
                    for name, member in members.items():
                        if name in {AGENT, INIT, IDENTITY_HELPER}:
                            continue
                        if member.isfile():
                            with seed.extractfile(member) as content:
                                packed.addfile(member, content)
                        else:
                            packed.addfile(member)
                    for path, program in ((AGENT, agent), (IDENTITY_HELPER, helper)):
                        entry = tarfile.TarInfo(path)
                        entry.mode, entry.size, entry.mtime = 0o755, program.stat().st_size, timestamp
                        with program.open("rb") as content:
                            packed.addfile(entry, content)
                    link = tarfile.TarInfo(INIT)
                    link.type, link.linkname, link.mode, link.mtime = tarfile.SYMTYPE, "/" + AGENT, 0o777, timestamp
                    packed.addfile(link)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("source-root", "toolchain-lock", "input-lock", "seed", "agent", "identity-helper", "output", "metadata"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--timestamp", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.input_lock.is_absolute() or ".." in args.input_lock.parts:
            raise ValueError("rootfs input lock must be relative to the smolvm source root")
        lock_path = args.source_root / args.input_lock
        lock = json.loads(lock_path.read_text())
        check_lock(lock)
        lock_digest = file_digest(lock_path)
        pin = {"repository": "smolvm", "path": args.input_lock.as_posix(), "sha256": lock_digest}
        toolchain = json.loads(args.toolchain_lock.read_text())
        manifest = Path("crates/smolvm-identity-helper/Cargo.toml")
        helper_pin = {"repository": "smolvm", "path": manifest.as_posix(), "sha256": file_digest(args.source_root / manifest)}
        if helper_pin not in toolchain["lockfiles"]:
            raise ValueError("runtime toolchain lock does not pin the identity helper manifest")
        if pin not in toolchain["lockfiles"]:
            raise ValueError("runtime toolchain lock does not pin the supplied OCI seed input lock")
        assemble(args.seed, args.agent, args.identity_helper, args.output, args.source_root, lock, args.timestamp)
        provenance = {key: lock[key] for key in SEED_DIGESTS}
        provenance.update(schema="RuntimeRootfsProvenance/2", input_lock_path=args.input_lock.as_posix(),
                          input_lock_sha256=lock_digest, recipe_sha256=file_digest(args.source_root / RECIPE),
                          agent_sha256=file_digest(args.agent), identity_helper_sha256=file_digest(args.identity_helper),
                          rootfs_sha256=file_digest(args.output))
        (args.metadata / "rootfs-input-lock.json").write_bytes(lock_path.read_bytes())
        (args.metadata / "rootfs-provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        sys.exit(f"deep OCI rootfs: {error}")


if __name__ == "__main__":
    main()
