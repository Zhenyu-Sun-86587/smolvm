#!/usr/bin/env python3
"""Report downstream patch overlap with a pinned upstream source tree."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


REPOSITORIES = ("smolvm", "libkrun", "libkrunfw")
REGISTRY = Path(__file__).with_name("patch-registry.json")
COMMIT = re.compile(r"[0-9a-f]{40}")
PATH_GATES = {
    "src/vmm/": ("A01", "A02", "A03", "A06", "A07", "A09", "A11", "A14", "A19"),
    "src/devices/": ("A09", "A10", "A12", "A13", "A14"),
    "src/api/": ("A04", "A18", "A20", "A26"),
    "crates/smolvm-network/": ("A13", "A20", "A21"),
    "crates/smolvm-agent/": ("A17", "A21", "A22"),
    "crates/smolvm-identity-helper/": ("A14", "A15", "A16"),
    "crates/smolvm-resourced/": ("A04", "A05", "A10", "A19", "A20", "A25"),
    "patches/": ("A06", "A07", "A08", "A14", "A15", "A19"),
    "config-": ("A06", "A14", "A17", "A19"),
    "scripts/": ("A19", "A20"),
    "Cargo.": ("A19", "A20"),
    "Makefile": ("A19", "A20"),
    "libkrun": ("A19", "A20"),
}


def git(repo, *arguments, stdin=None):
    return subprocess.run(["git", "--no-replace-objects", "-C", repo, *arguments], input=stdin,
                          capture_output=True, check=True).stdout


def resolve(repo, oid):
    if not isinstance(oid, str) or COMMIT.fullmatch(oid) is None:
        raise ValueError(f"expected a full commit ID, received {oid!r}")
    checked = git(repo, "rev-parse", "--verify", f"{oid}^{{commit}}").decode().strip()
    if checked != oid:
        raise ValueError(f"{oid} is not a commit in {repo}")
    return checked


def gitlink(repo, revision, path):
    entry = git(repo, "ls-tree", revision, "--", path).decode().split()
    if len(entry) != 4 or entry[:2] != ["160000", "commit"] or entry[3] != path:
        raise ValueError(f"{revision} is missing the {path} gitlink")
    return entry[2]


def tree(repo, revision):
    return git(repo, "show", "--no-patch", "--format=%T", revision, "--").decode().strip()


def paths(repo, left, right):
    entries = git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", left, right, "--")
    return [os.fsdecode(entry) for entry in entries.split(b"\0") if entry]


def upstream_ids(repo, base, upstream):
    changes = git(repo, "log", "--no-merges", "--no-ext-diff", "--no-renames", "--format=%H", "-p",
                  f"{base}..{upstream}", "--")
    return dict(line.split() for line in git(repo, "patch-id", "--stable", stdin=changes).decode().splitlines())


def replacement(repo, revision, equivalent):
    change = git(repo, "show", "--no-ext-diff", "--no-renames", "--format=%H", revision, "--")
    row = git(repo, "patch-id", "--stable", stdin=change).decode().split()
    return equivalent.get(row[0]) if row else None


def downstream_patch(repo, revision, upstream, equivalent, changed):
    try:
        git(repo, "merge-base", "--is-ancestor", revision, upstream)
        return {"commit": revision, "upstream_match": revision, "match": "commit"}
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
    match = replacement(repo, revision, equivalent)
    if match:
        return {"commit": revision, "upstream_match": match, "match": "patch_id"}
    overlap = sorted(changed.intersection(paths(repo, f"{revision}^", revision)))
    return {"commit": revision, "overlap": overlap}


def report(args):
    raw = args.registry.read_bytes()
    registry = json.loads(raw)
    if registry["schema"] != "DeepPatchRegistry/1" or set(registry["upstream_bases"]) != set(REPOSITORIES):
        raise ValueError("invalid downstream patch registry")
    selected = {"smolvm": args.downstream}
    incoming = {"smolvm": args.upstream}
    repos = {"smolvm": args.smolvm}
    for name in REPOSITORIES[1:]:
        repos[name] = getattr(args, name) or args.smolvm / name
        selected[name] = gitlink(args.smolvm, args.downstream, name)
        incoming[name] = gitlink(args.smolvm, args.upstream, name)
    known = set()
    for patch in registry["patches"]:
        if patch["id"] in known or set(patch["commits"]) - set(REPOSITORIES):
            raise ValueError(f"invalid patch entry {patch['id']}")
        known.add(patch["id"])
    for patch in registry["patches"]:
        if set(patch["depends_on"]) - known:
            raise ValueError(f"unknown dependencies in {patch['id']}")
    output = {"schema": "DeepUpstreamSync/1", "patch_registry_sha256": hashlib.sha256(raw).hexdigest(),
              "sources": {}, "required_gates": []}
    gates = set()
    for name, repo in repos.items():
        base = resolve(repo, registry["upstream_bases"][name])
        old = resolve(repo, selected[name])
        new = resolve(repo, incoming[name])
        upstream_tip = getattr(args, name + "_tip", None)
        git(repo, "merge-base", "--is-ancestor", base, new)
        changed = set(paths(repo, base, new))
        equivalent = upstream_ids(repo, base, new)
        for prefix, required in PATH_GATES.items():
            if any(path.startswith(prefix) for path in changed):
                gates.update(required)
        patches = []
        for patch in registry["patches"]:
            entries = []
            for candidate in patch["commits"].get(name, []):
                commit = resolve(repo, candidate)
                git(repo, "merge-base", "--is-ancestor", commit, old)
                entries.append(downstream_patch(repo, commit, new, equivalent, changed))
            if entries:
                patches.append({"id": patch["id"], "changes": entries, "gates": patch["gates"]})
            if any(entry.get("upstream_match") or entry.get("overlap") for entry in entries):
                gates.update(patch["gates"])
        old_tree, new_tree = tree(repo, old), tree(repo, new)
        details = {"upstream_base": base, "downstream_commit": old, "downstream_tree": old_tree,
                   "upstream_commit": new, "upstream_tree": new_tree, "same_tree": old_tree == new_tree,
                   "paths_since_upstream_base": sorted(changed), "patches": patches}
        if upstream_tip:
            tip = resolve(repo, upstream_tip)
            details["observed_upstream_tip"] = {"commit": tip, "tree": tree(repo, tip),
                                                "same_tree_as_pinned": tree(repo, tip) == new_tree}
        output["sources"][name] = details
    output["required_gates"] = sorted(gates)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smolvm", required=True, type=Path)
    parser.add_argument("--libkrun", type=Path)
    parser.add_argument("--libkrunfw", type=Path)
    parser.add_argument("--downstream", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--libkrun-tip")
    parser.add_argument("--libkrunfw-tip")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    args = parser.parse_args()
    try:
        resolve(args.smolvm, args.downstream)
        resolve(args.smolvm, args.upstream)
        print(json.dumps(report(args), indent=2))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.decode(errors="replace").strip(), file=sys.stderr)
        print(f"deep upstream sync: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
