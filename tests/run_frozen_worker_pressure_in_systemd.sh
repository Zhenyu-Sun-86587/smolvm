#!/usr/bin/env bash
# Give a frozen Serve with a hard-coded VM slice its own real systemd manager.
set -euo pipefail

case "${1:-}" in
  --allocate)
    shift
    current=$(awk -F: '$1 == 0 { print $3 }' /proc/self/cgroup)
    case "$current" in
      /system.slice/smolvmfrozen*.service/supervisor) ;;
      *) printf 'Unexpected delegated cgroup %s\n' "$current" >&2; exit 1 ;;
    esac
    delegated=/sys/fs/cgroup${current%/supervisor}
    printf '+memory +cpu +cpuset +io +pids\n' >"$delegated/cgroup.subtree_control"
    mkdir "$delegated/isolated"
    exec unshare --mount --propagation private --uts --ipc --net --pid --fork --kill-child --mount-proc \
      /bin/bash "$0" --enter "$delegated/isolated" "$@"
    ;;
  --enter)
    shift
    test "$$" -eq 1
    case "$1" in
      /sys/fs/cgroup/system.slice/smolvmfrozen*.service/isolated) ;;
      *) printf 'Unexpected cgroup namespace root %s\n' "$1" >&2; exit 1 ;;
    esac
    # Leave the outer unshare supervisor in its sibling cgroup.
    printf '0\n' >"$1/cgroup.procs"
    shift
    exec unshare --cgroup /bin/bash "$0" --manager "$@"
    ;;
  --manager)
    shift
    test "$$" -eq 1
    test "$(cat /proc/self/cgroup)" = "0::/"
    result=$1
    shift
    export container=smolvm-frozen-proof
    unset DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS SYSTEMD_BUS_ADDRESS
    cgroup_options=$(findmnt -n -o FS-OPTIONS --target /sys/fs/cgroup)
    umount /sys/fs/cgroup
    mount -t cgroup2 -o "$cgroup_options,nosuid,nodev,noexec" cgroup2 /sys/fs/cgroup
    mount -t tmpfs -o size=32m,mode=0755 tmpfs /run
    units=/run/systemd/system
    program=/run/frozen-proof
    install -d -m 0755 "$units" /run/dbus
    install -d -m 0700 "$program"
    cp -- "$0" "$program/runner"
    printf '%s\0' "$@" >"$program/arguments"
    printf '%s' "$result" >"$program/output"
    cat >"$units/frozen-proof.target" <<'EOF'
[Unit]
DefaultDependencies=no
Wants=frozen-proof.service
EOF
    cat >"$units/dbus.socket" <<'EOF'
[Unit]
DefaultDependencies=no

[Socket]
ListenStream=/run/dbus/system_bus_socket
SocketMode=0666
EOF
    cat >"$units/dbus.service" <<'EOF'
[Unit]
DefaultDependencies=no
Requires=dbus.socket
After=dbus.socket

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
EOF
    cat >"$units/frozen-proof.service" <<'EOF'
[Unit]
DefaultDependencies=no
Requires=dbus.socket
After=dbus.socket

[Service]
Type=oneshot
Environment=SMOLVM_PRESSURE_TEST_NAMESPACE=1 PYTHONDONTWRITEBYTECODE=1
ExecStart=/bin/bash /run/frozen-proof/runner --exercise
EOF
    exec /usr/lib/systemd/systemd --unit=frozen-proof.target --log-level=warning
    ;;
  --exercise)
    result=$(cat /run/frozen-proof/output)
    exec >"$result/result.log" 2>&1
    mapfile -d '' -t command </run/frozen-proof/arguments
    printf 'Isolated systemd manager and delegated cgroup controllers\n'
    cat /proc/1/cgroup /proc/self/cgroup /sys/fs/cgroup/cgroup.controllers
    test ! -e /sys/fs/cgroup/smolvmdeep.slice
    code=0
    "${command[@]}" || code=$?
    printf '%s\n' "$code" >"$result/status"
    systemctl --no-block exit "$code"
    ;;
  *)
    if (( EUID != 0 || $# == 0 )); then
      printf 'Usage as root: %s absolute-command [args ...]\n' "$0" >&2
      exit 2
    fi
    script=$(realpath -e -- "$0")
    result=$(mktemp -d /var/tmp/smolvm-frozen-pressure.XXXXXX)
    cleanup() {
      rm -f -- "$result/result.log" "$result/status"
      rmdir -- "$result"
    }
    trap cleanup EXIT
    code=0
    systemd-run --unit="smolvmfrozen${result##*.}" --collect --wait --pipe \
      -p Delegate=yes -p DelegateSubgroup=supervisor -p MemoryAccounting=yes -p MemoryMax=3G \
      -p RuntimeMaxSec=12min /bin/bash "$script" --allocate "$result" "$@" || code=$?
    if [[ -f "$result/result.log" ]]; then cat "$result/result.log"; fi
    if [[ ! -f "$result/status" ]]; then
      printf 'The isolated manager exited without a test result.\n' >&2
      exit 1
    fi
    (( code == 0 )) || exit "$code"
    exit "$(cat "$result/status")"
    ;;
esac
