#!/usr/bin/env bash
# Move Docker and containerd storage onto an EC2 instance-store NVMe disk, so provisioning-tests
# (and every node pod nested inside it) writes to that disk instead of the EBS root volume.
#
# Docker with the containerd image store keeps image layers and container filesystems under the
# containerd root (/var/lib/containerd), and volumes under /var/lib/docker. The runtime container's
# /var/lib/rancher and /var/lib/kubelet are volumes, so that is where the host k3s, its pods and all
# node pods' data end up. Both directories are moved.
#
# The disk is formatted (only if it has no filesystem) and mounted at MOUNT, then MOUNT/docker and
# MOUNT/containerd are bind-mounted over the original paths. Paths and /etc/docker/daemon.json stay
# the same, so vm-telemetry.sh's default DATA_PATH (/var/lib/docker) resolves to the NVMe disk.
#
# Usage:
#   sudo ./scripts/setup-nvme-data-disk.sh [options]
#
# Options:
#   -d DEV      device to use (default: the only "Amazon EC2 NVMe Instance Storage" disk)
#   -m DIR      mount point (default /mnt/nvme)
#   -t FSTYPE   ext4 or xfs (default ext4, the same as the EBS root, so tracer output compares)
#   -o OPTS     mount options (default "defaults")
#   --copy      copy the current Docker and containerd data onto the disk, keeping loaded images
#   --status    show what backs the Docker and containerd paths, then exit
#   -h          show this help
#
# Instance storage is wiped when the instance stops, and the mounts do not survive a reboot. Rerun
# the script after either; it is safe to rerun and never formats a disk that has a filesystem.

set -euo pipefail

DEV=""
MOUNT=/mnt/nvme
FSTYPE=ext4
OPTS=defaults
COPY=0
STATUS=0

log() { echo "[$(date +%T)] $*"; }
warn() { echo "[$(date +%T)] warning: $*" >&2; }
die() { echo "error: $*" >&2; exit 1; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -d) DEV=${2:?"-d needs a value"}; shift 2 ;;
        -m) MOUNT=${2:?"-m needs a value"}; shift 2 ;;
        -t) FSTYPE=${2:?"-t needs a value"}; shift 2 ;;
        -o) OPTS=${2:?"-o needs a value"}; shift 2 ;;
        --copy) COPY=1; shift ;;
        --status) STATUS=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

[ "$(uname -s)" = Linux ] || die "this script only runs on Linux"
[ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
case "$FSTYPE" in ext4|xfs) ;; *) die "-t must be ext4 or xfs, got '$FSTYPE'" ;; esac

containerd_root() {
    local root=""
    command -v containerd >/dev/null && root=$(containerd config dump 2>/dev/null | awk -F'"' '/^root *=/ { print $2; exit }')
    echo "${root:-/var/lib/containerd}"
}

PATHS=(/var/lib/docker "$(containerd_root)")

# daemon_view prints the device the running daemon sees backing path, from inside the daemon's own
# mount namespace; a mount made in this shell's namespace is not necessarily visible there.
daemon_view() {
    local daemon=$1 path=$2 pid
    pid=$(pgrep -xo "$daemon") || { echo "(not running)"; return 0; }
    nsenter -t "$pid" -m findmnt -no SOURCE -T "$path" 2>&1
}

status() {
    local p
    for p in "${PATHS[@]}"; do
        if [ -e "$p" ]; then
            printf '%-24s %s\n' "$p" "$(findmnt -no SOURCE,FSTYPE,OPTIONS -T "$p")"
        else
            printf '%-24s %s\n' "$p" "(missing)"
        fi
    done
    printf '%-24s %s\n' "dockerd sees" "${PATHS[0]} on $(daemon_view dockerd "${PATHS[0]}")"
    printf '%-24s %s\n' "containerd sees" "${PATHS[1]} on $(daemon_view containerd "${PATHS[1]}")"
    command -v docker >/dev/null || return 0
    printf '%-24s %s\n' "docker root" "$(docker info -f '{{.DockerRootDir}}' 2>&1)"

    # Show where each mount of a running container-run container (image rancher-runtime:*) really lives.
    local ctr src dst
    for ctr in $(docker ps --format '{{.ID}} {{.Image}}' | awk '$2 ~ /^rancher-runtime:/ { print $1 }'); do
        echo "container $ctr (rancher-runtime):"
        printf '  %-36s %s\n' "/ (rootfs)" "$(findmnt -no SOURCE -T "${PATHS[1]}")"
        while read -r src dst; do
            [ -e "$src" ] || continue
            printf '  %-36s %s  (%s)\n' "$dst" "$(findmnt -no SOURCE -T "$src")" "$src"
        done < <(docker inspect -f '{{range .Mounts}}{{.Source}} {{.Destination}}{{"\n"}}{{end}}' "$ctr")
    done
    return 0
}

if [ "$STATUS" = 1 ]; then
    status
    exit 0
fi

if [ -z "$DEV" ]; then
    mapfile -t devs < <(lsblk -dnpo NAME,MODEL | awk '/Amazon EC2 NVMe Instance Storage/ { print $1 }')
    [ "${#devs[@]}" -gt 0 ] || die "no instance-store NVMe disk found; is this an instance type with local storage (e.g. c6id, m6id)? lsblk:
$(lsblk -dno NAME,SIZE,MODEL)"
    [ "${#devs[@]}" -eq 1 ] || die "found ${#devs[@]} instance-store disks (${devs[*]}); pick one with -d"
    DEV=${devs[0]}
fi

[ -b "$DEV" ] || die "$DEV is not a block device"
root_src=$(findmnt -no SOURCE /)
root_disk=$(lsblk -npo PKNAME "$root_src" | head -n1)
[ "$DEV" != "$root_src" ] && [ "$DEV" != "$root_disk" ] || die "$DEV holds the root filesystem"
[ "$(lsblk -nro NAME "$DEV" | wc -l)" -eq 1 ] || die "$DEV has partitions; refusing to touch it"

existing=$(blkid -o value -s TYPE "$DEV" || true)
if [ -z "$existing" ]; then
    log "formatting $DEV as $FSTYPE"
    # Initialize inode tables and the journal now; ext4 otherwise zeroes them in the background
    # after mounting, which would show up as IO in the measurements.
    case "$FSTYPE" in
        ext4) mkfs.ext4 -q -F -L v2prov-data -E lazy_itable_init=0,lazy_journal_init=0 "$DEV" ;;
        xfs) mkfs.xfs -q -f -L v2prov-data "$DEV" ;;
    esac
elif [ "$existing" != "$FSTYPE" ]; then
    die "$DEV already has a $existing filesystem; run 'wipefs -a $DEV' first to reformat it as $FSTYPE"
else
    log "$DEV already has a $FSTYPE filesystem, reusing it"
fi

mkdir -p "$MOUNT"
if mountpoint -q "$MOUNT"; then
    src=$(findmnt -no SOURCE "$MOUNT")
    [ "$src" = "$DEV" ] || die "$MOUNT already has $src mounted"
    log "$DEV is already mounted at $MOUNT"
else
    log "mounting $DEV at $MOUNT ($OPTS)"
    mount -t "$FSTYPE" -o "$OPTS" "$DEV" "$MOUNT"
fi

units=()
for u in docker.socket docker.service containerd.service; do
    systemctl cat "$u" >/dev/null 2>&1 && units+=("$u")
done
if [ "${#units[@]}" -gt 0 ]; then
    log "stopping ${units[*]}"
    systemctl stop "${units[@]}"
fi

for p in "${PATHS[@]}"; do
    target="$MOUNT/$(basename "$p")"
    mkdir -p "$target" "$p"
    if mountpoint -q "$p"; then
        src=$(findmnt -no SOURCE "$p")
        [[ $src == "$DEV"* ]] || die "$p is already a mount of $src"
        log "$p is already on $DEV"
        continue
    fi
    if [ "$COPY" = 1 ]; then
        if [ -n "$(ls -A "$target")" ]; then
            warn "$target is not empty, not copying $p into it"
        else
            log "copying $p to $target"
            cp -a "$p/." "$target/"
        fi
    fi
    log "bind-mounting $target over $p"
    mount --bind "$target" "$p"
done

# Start containerd first; docker.service depends on it but socket activation alone would not.
for u in containerd.service docker.service docker.socket; do
    if [[ " ${units[*]} " == *" $u "* ]]; then
        systemctl start "$u"
    fi
done

status
for check in "dockerd ${PATHS[0]}" "containerd ${PATHS[1]}"; do
    read -r daemon path <<< "$check"
    seen=$(daemon_view "$daemon" "$path")
    [[ $seen == "$DEV"* ]] || die "$daemon sees $path on '$seen', not $DEV; it will keep writing to that disk"
done
log "done: dockerd and containerd both see their data on $DEV"
if [ "$COPY" = 0 ]; then
    log "Docker starts empty: reload images (e.g. the rancher and rancher-agent tarballs) before running tests"
fi
log "data under the old paths on the root disk is hidden, not deleted; unmount $MOUNT's bind mounts to get it back"
log "the repo checkout stays where it is, and its build/ is the runtime container's /tmp (rancher.log, test output, Go build temp dirs); clone it under $MOUNT and run from there to move it too"
