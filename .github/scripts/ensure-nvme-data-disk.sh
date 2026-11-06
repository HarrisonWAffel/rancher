#!/usr/bin/env bash
# Make sure provisioning-tests writes to the runner's local NVMe (EC2 instance store), not the root
# EBS volume, and fail if it can't.
#
# The data that matters is Docker's (/var/lib/docker: volumes, which hold every nested node's data),
# containerd's (/var/lib/containerd: image layers and container filesystems with Docker's containerd
# image store) and the repo's build/ directory (the runtime container's /tmp).
#
# 1. Each path is traced through bind mounts, overlays and RAID down to the physical disks behind it.
#    Disks are told apart by their EC2 model string, never by name: nvme0n1/nvme1n1 ordering is not
#    stable across instance types.
# 2. Paths already on instance store (RunsOn mounts it over /var/lib/docker and /home/runner) are left
#    alone. For the rest, an instance-store filesystem that is already mounted is reused; otherwise
#    blank instance-store disks (no partitions, no filesystem signature, not mounted) are combined
#    (RAID0 if there are several), formatted and mounted. The paths are then bind-mounted onto it.
# 3. Disks behind / and /boot are never candidates. Run before anything is written to the paths:
#    whatever is under them is hidden by the bind mounts.
# 4. The result is checked from inside dockerd's and containerd's mount namespaces, which is what the
#    tests actually write through. Any path not on instance store fails the script.
#
# Usage: sudo .github/scripts/ensure-nvme-data-disk.sh [--check] [PATH...]
#   PATH     extra directories to put on NVMe, e.g. "$GITHUB_WORKSPACE/build"
#   --check  only report and verify; change nothing

set -euo pipefail

INSTANCE_STORE_MODEL="Amazon EC2 NVMe Instance Storage"
MOUNT=/mnt/v2prov-data
CHECK_ONLY=0
EXTRA=()

log() { echo "[ensure-nvme] $*"; }
die() { echo "[ensure-nvme] error: $*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=1 ;;
        -*) die "unknown option: $arg" ;;
        *) EXTRA+=("$arg") ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root"

containerd_root() {
    local root=""
    command -v containerd >/dev/null && root=$(containerd config dump 2>/dev/null | awk -F'"' '/^root *=/ { print $2; exit }')
    echo "${root:-/var/lib/containerd}"
}

PATHS=(/var/lib/docker "$(containerd_root)" "${EXTRA[@]}")

# backing_disks PATH [PID] prints the whole disks behind PATH, as seen from PID's mount namespace
# (default: this one). Bind mounts show up as SOURCE "/dev/x[/subdir]"; overlays are followed
# through their upperdir.
backing_disks() {
    local path=$1 pid=${2:-} src fstype opts upper ns=()
    [ -n "$pid" ] && ns=(nsenter -t "$pid" -m)
    read -r src fstype opts < <("${ns[@]}" findmnt -no SOURCE,FSTYPE,OPTIONS -T "$path")
    if [ "$fstype" = overlay ]; then
        upper=$(tr ',' '\n' <<< "$opts" | sed -n 's/^upperdir=//p')
        [ -n "$upper" ] || return 0
        backing_disks "$upper" "$pid"
        return
    fi
    src=${src%%\[*}
    [[ $src == /dev/* ]] || return 0
    lsblk -nsrpo NAME,TYPE "$src" | awk '$2 == "disk" { print $1 }' | sort -u
}

is_instance_store() { [ "$(lsblk -dno MODEL "$1" | sed 's/ *$//')" = "$INSTANCE_STORE_MODEL" ]; }

# on_instance_store PATH [PID] is true if every disk behind PATH is instance store.
on_instance_store() {
    local disks d
    disks=$(backing_disks "$@")
    [ -n "$disks" ] || return 1
    for d in $disks; do is_instance_store "$d" || return 1; done
}

describe() {
    local path=$1 pid=${2:-} ns=()
    [ -n "$pid" ] && ns=(nsenter -t "$pid" -m)
    printf '%-40s %s -> %s\n' "$path" "$("${ns[@]}" findmnt -no SOURCE,FSTYPE -T "$path" | tr -s ' ')" \
        "$(backing_disks "$path" "$pid" | while read -r d; do printf '%s (%s) ' "$d" "$(lsblk -dno MODEL "$d" | sed 's/ *$//')"; done)"
}

lsblk -o NAME,SIZE,TYPE,FSTYPE,MODEL,MOUNTPOINTS

mapfile -t STORE_DISKS < <(lsblk -dnpo NAME,TYPE | awk '$2 == "disk" { print $1 }' | while read -r d; do is_instance_store "$d" && echo "$d"; done)
[ "${#STORE_DISKS[@]}" -gt 0 ] || die "no '$INSTANCE_STORE_MODEL' disks; pick an instance family with local NVMe (e.g. c6id)"

ROOT_DISKS=$(for p in / /boot /boot/efi; do if mountpoint -q "$p"; then backing_disks "$p"; fi; done | sort -u)
for d in $ROOT_DISKS; do
    if is_instance_store "$d"; then
        die "$d holds the root filesystem but reports itself as instance store; refusing to continue"
    fi
done

todo=()
for p in "${PATHS[@]}"; do
    mkdir -p "$p"
    describe "$p"
    on_instance_store "$p" || todo+=("$p")
done

if [ "${#todo[@]}" -gt 0 ] && [ "$CHECK_ONLY" = 0 ]; then
    log "not on instance store yet: ${todo[*]}"

    # Reuse an instance-store filesystem that's already mounted (e.g. RunsOn's), if there is one.
    # Its device is mounted again at MOUNT, which shows the filesystem's root, so the data doesn't
    # end up nested under one of the paths (e.g. RunsOn's /var/lib/docker).
    existing=""
    if mountpoint -q "$MOUNT"; then
        existing=$(findmnt -no SOURCE "$MOUNT")
    else
        # Listed up front so a findmnt failure stops the script instead of looking like "no mounts".
        mounts=$(findmnt -rno SOURCE,FSTYPE)
        while read -r src fstype; do
            case "$fstype" in ext4|xfs) ;; *) continue ;; esac
            src=${src%%\[*}
            [[ $src == /dev/* ]] || continue
            disks=$(lsblk -nsrpo NAME,TYPE "$src" | awk '$2 == "disk" { print $1 }' | sort -u)
            all=1
            for d in $disks; do
                if ! is_instance_store "$d"; then all=0; fi
            done
            if [ -n "$disks" ] && [ "$all" = 1 ]; then existing=$src; break; fi
        done <<< "$mounts"
    fi

    if [ -n "$existing" ]; then
        log "reusing the instance-store filesystem on $existing"
        if ! mountpoint -q "$MOUNT"; then
            mkdir -p "$MOUNT"
            mount "$existing" "$MOUNT"
        fi
        data=$MOUNT
    else
        blank=()
        for d in "${STORE_DISKS[@]}"; do
            if grep -qxF "$d" <<< "$ROOT_DISKS"; then continue; fi
            [ "$(lsblk -nro NAME "$d" | wc -l)" -eq 1 ] || { log "skipping $d: it has partitions or holders"; continue; }
            [ -z "$(wipefs -n "$d" 2>/dev/null | tail -n +2)" ] || { log "skipping $d: it has a filesystem or RAID signature"; continue; }
            [ -z "$(lsblk -nro MOUNTPOINTS "$d" | tr -d '\n')" ] || { log "skipping $d: it is mounted"; continue; }
            blank+=("$d")
        done
        [ "${#blank[@]}" -gt 0 ] || die "no blank instance-store disk to format (found ${STORE_DISKS[*]})"

        dev=${blank[0]}
        if [ "${#blank[@]}" -gt 1 ]; then
            if command -v mdadm >/dev/null; then
                log "creating RAID0 over ${blank[*]}"
                mdadm --create /dev/md/v2prov --run --level=0 --raid-devices="${#blank[@]}" "${blank[@]}"
                dev=/dev/md/v2prov
            else
                log "mdadm not installed; using only $dev"
            fi
        fi
        log "formatting $dev as ext4"
        # Initialize inode tables and the journal now, instead of in the background during the tests.
        mkfs.ext4 -q -F -L v2prov-data -E lazy_itable_init=0,lazy_journal_init=0 "$dev"
        mkdir -p "$MOUNT"
        mount -o defaults,noatime "$dev" "$MOUNT"
        data=$MOUNT
    fi

    units=()
    for u in docker.socket docker.service containerd.service; do
        systemctl is-active --quiet "$u" && units+=("$u")
    done
    [ "${#units[@]}" -eq 0 ] || { log "stopping ${units[*]}"; systemctl stop "${units[@]}"; }

    for p in "${todo[@]}"; do
        target=$data/$(echo "${p#/}" | tr '/' '_')
        mkdir -p "$target"
        chown --reference="$p" "$target"
        chmod --reference="$p" "$target"
        log "bind-mounting $target over $p"
        mount --bind "$target" "$p"
    done

    for u in containerd.service docker.service docker.socket; do
        if [[ " ${units[*]} " == *" $u "* ]]; then systemctl start "$u"; fi
    done
fi

# Verify through the daemons' own mount namespaces; dockerd also resolves container-run's bind mount
# of build/ in its namespace.
fail=0
dockerd=$(pgrep -xo dockerd || true)
containerd=$(pgrep -xo containerd || true)
for p in "${PATHS[@]}"; do
    pid=$dockerd
    if [ "$p" = "${PATHS[1]}" ]; then pid=$containerd; fi
    if [ -z "$pid" ]; then
        log "no daemon running to check $p against; checking from this namespace"
        pid=""
    fi
    describe "$p" "$pid"
    on_instance_store "$p" "$pid" || { echo "[ensure-nvme] error: $p is not on instance store" >&2; fail=1; }
done
[ "$fail" = 0 ] || die "test data would land on the root disk; see above"
log "all test data paths are on instance store"
