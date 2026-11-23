#!/usr/bin/env bash
# A second DHCP server and IPv6 router for tests/integration/test_probe_real.py (#184):
# dnsmasq in the network namespace "sbrogue" behind the veth pair sbp0 (host) / sbp1 (namespace).
#
#   tools/integration/probe/netns.sh start DIR   # needs sudo; writes DIR/env for $GITHUB_ENV
#   tools/integration/probe/netns.sh stop DIR
set -euo pipefail
cmd=${1:?start or stop}
dir=${2:?directory}
mkdir -p "$dir"

case "$cmd" in
start)
  sudo ip netns add sbrogue
  sudo ip link add sbp0 type veth peer name sbp1
  sudo ip link set sbp1 netns sbrogue
  sudo ip addr add 198.51.100.2/24 dev sbp0
  sudo ip link set sbp0 up
  sudo ip netns exec sbrogue ip link set lo up
  sudo ip netns exec sbrogue ip addr add 198.51.100.1/24 dev sbp1
  sudo ip netns exec sbrogue ip -6 addr add 2001:db8:5::1/64 dev sbp1 nodad
  sudo ip netns exec sbrogue ip link set sbp1 up
  sudo ip netns exec sbrogue sysctl -qw net.ipv6.conf.all.forwarding=1
  : > "$dir/leases"
  chmod 666 "$dir/leases"
  sudo ip netns exec sbrogue dnsmasq \
    --user=root --port=0 --interface=sbp1 --bind-interfaces --no-resolv --no-hosts \
    --dhcp-range=198.51.100.100,198.51.100.150,255.255.255.0,12h \
    --dhcp-option=option:router,198.51.100.1 \
    --dhcp-option=option:dns-server,198.51.100.1 \
    --enable-ra --dhcp-range=2001:db8:5::,ra-only,64,12h \
    --dhcp-leasefile="$dir/leases" --pid-file="$dir/dnsmasq.pid" \
    --log-facility="$dir/dnsmasq.log" --log-dhcp
  # the DHCP client port for the unprivileged CI user (docs/PROBES.md)
  sudo sysctl -qw net.ipv4.ip_unprivileged_port_start=67
  # wait for the host side's IPv6 link-local address (DAD)
  for _ in $(seq 1 50); do
    ip -6 addr show dev sbp0 scope link | grep -q 'inet6 fe80' && \
      ! ip -6 addr show dev sbp0 | grep -q tentative && break
    sleep 0.2
  done
  {
    echo "IT_PROBE_URL=veth://sbp0"
    echo "IT_PROBE_USER=none"
    echo "IT_PROBE_PASSWORD=none"
    echo "IT_PROBE_SERVER=198.51.100.1"
    echo "IT_PROBE_LEASES=$dir/leases"
  } > "$dir/env"
  ;;
stop)
  if [ -f "$dir/dnsmasq.pid" ]; then sudo kill "$(cat "$dir/dnsmasq.pid")" || true; fi
  sudo ip link del sbp0 || true
  sudo ip netns del sbrogue || true
  ;;
*)
  echo "usage: $0 start|stop DIR" >&2
  exit 2
  ;;
esac
