#!/usr/bin/env bash
#
# Fail when any of the given ELF files needs a glibc newer than the floor.
#
# Usage: ./scripts/check-glibc-floor.sh 2.31 target/release/smolvm lib/linux-x86_64/libkrun.so
set -euo pipefail

floor="$1"
shift
status=0
for file in "$@"; do
    # sed succeeds on a valid ELF with no versioned imports. With pipefail an
    # unreadable or malformed input still fails at objdump.
    newest="$(objdump -T "$file" | sed -nE 's/.*GLIBC_([0-9]+(\.[0-9]+)+).*/\1/p' | sort -Vu | tail -1)"
    if [[ -z "$newest" ]]; then
        echo "$file: no versioned glibc symbols"
        continue
    fi
    if [[ "$(printf '%s\n%s\n' "$floor" "$newest" | sort -V | tail -1)" != "$floor" ]]; then
        echo "ERROR: $file needs glibc $newest, above the $floor floor:" >&2
        objdump -T "$file" | grep -E "GLIBC_${newest//./\\.}\b" | awk '{print "  " $NF}' | sort -u >&2
        status=1
    else
        echo "$file: newest glibc symbol $newest (floor $floor)"
    fi
done
exit "$status"
