#!/usr/bin/env bash
# Boot the OpenWrt integration test image in QEMU (KVM) and wait until it is ready (#137).
#
#   tools/integration/openwrt/start-vm.sh <openwrt.img> <run-dir> [https-port] [ssh-port]
#
# NICs (virtio): eth0 on QEMU's user-mode network with 127.0.0.1:<https-port> forwarded to the
# guest's 443 and 127.0.0.1:<ssh-port> to its 22 (dropbear); eth1 and eth2 on hubs of their own (link up, nothing else on the wire), the ports
# of br-lan. Serial console: <run-dir>/console.log. The VM runs in the background
# (<run-dir>/qemu.pid); stop it with `kill "$(cat <run-dir>/qemu.pid)"`.
set -euo pipefail

IMAGE=${1:?usage: start-vm.sh <openwrt.img> <run-dir> [https-port]}
RUN=${2:?usage: start-vm.sh <openwrt.img> <run-dir> [https-port]}
PORT=${3:-8443}
SSH_PORT=${4:-8022}
TIMEOUT=${IT_OPENWRT_BOOT_TIMEOUT:-300}
mkdir -p "$RUN"
cp "$IMAGE" "$RUN/disk.img"  # the cached image stays pristine
: > "$RUN/console.log"

accel=(-enable-kvm -cpu host)
[ -w /dev/kvm ] || { echo "::warning::no /dev/kvm, emulating (slow)"; accel=(-cpu max); }

qemu-system-x86_64 "${accel[@]}" -m 512 -smp 2 \
  -drive file="$RUN/disk.img",format=raw,if=virtio \
  -netdev user,id=mgmt,net=10.0.2.0/24,hostfwd=tcp:127.0.0.1:"$PORT"-:443,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 \
  -device virtio-net-pci,netdev=mgmt,mac=02:00:00:00:a0:00 \
  -netdev hubport,id=p1,hubid=1 -device virtio-net-pci,netdev=p1,mac=02:00:00:00:a0:01 \
  -netdev hubport,id=p2,hubid=2 -device virtio-net-pci,netdev=p2,mac=02:00:00:00:a0:02 \
  -display none -serial file:"$RUN/console.log" -monitor none \
  -daemonize -pidfile "$RUN/qemu.pid"

echo "QEMU started (pid $(cat "$RUN/qemu.pid")); waiting up to ${TIMEOUT}s for the device"
for ((i = 0; i < TIMEOUT; i++)); do
  if grep -q 'SIGNALBOX-IT-READY' "$RUN/console.log"; then
    echo "ready after ${i}s"
    exit 0
  fi
  if grep -q 'SIGNALBOX-IT-NOT-READY' "$RUN/console.log"; then
    echo "the device came up incomplete (see the console log)" >&2
    exit 1
  fi
  kill -0 "$(cat "$RUN/qemu.pid")" 2>/dev/null || { echo "QEMU exited" >&2; exit 1; }
  sleep 1
done
echo "not ready after ${TIMEOUT}s" >&2
exit 1
