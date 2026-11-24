#!/bin/sh
# Network and daemons of the Linux integration target (#240). Documentation addresses only.
# Environment: ROOT_PASSWORD, ADMIN_USER, ADMIN_PASSWORD (a sudo user that needs its password).
set -eu

# a LAN bridge over two dummy "jacks", a VLAN on a third, a WireGuard tunnel
ip link add br0 type bridge
for n in lan1 lan2 lan0; do ip link add "$n" type dummy; done
ip link set lan1 master br0
ip link set lan2 master br0
ip link add link lan0 name lan0.30 type vlan id 30
for n in lan1 lan2 lan0 br0 lan0.30; do ip link set "$n" up; done
# a static MAC address table entry (#160), read as the read user with bridge -j fdb show
bridge fdb add 02:00:00:00:53:01 dev lan1 master static
ip addr add 192.0.2.1/25 dev br0
ip addr add 2001:db8:1::1/64 dev br0 nodad
ip addr add 192.0.2.129/26 dev lan0.30
wg genkey > /root/wg0.key
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /root/wg0.key \
  peer "$(wg genkey | wg pubkey)" endpoint 203.0.113.1:51820 \
  allowed-ips 203.0.113.249/32,198.51.100.128/25 persistent-keepalive 25
ip addr add 203.0.113.250/30 dev wg0
ip link set wg0 up
ip route add 198.51.100.128/25 dev wg0
# routes and policy routing (#149): a lab behind a second router, a table with its own default
# route and the rule that sends one network to it
ip route add 198.18.20.0/24 via 192.0.2.5 dev br0
ip route add default via 192.0.2.5 dev br0 table 100
ip rule add from 192.0.2.128/26 lookup 100 priority 1000
sysctl -qw net.ipv4.ip_forward=1 || true
wg show wg0 public-key > /wg0.pub

# a small nftables firewall (#135): input and forward drop by default, a jump, a named set, one
# port forward and masquerade. SSH stays open for everyone: the test connects from the Docker host.
nft -f - <<'END'
table inet filter {
  set office { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    tcp dport 22 accept comment "ssh"
    iifname "lo" accept
    iifname "br0" accept
    iifname "eth0" ip saddr @office tcp dport 8080 accept comment "web from the office"
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "br0" oifname "eth0" accept
    iifname "eth0" ct status dnat accept comment "port forwards"
    iifname "wg0" jump from_vpn
  }
  chain from_vpn {
    ip daddr 192.0.2.20 tcp dport { 80, 443 } accept
  }
}
table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100;
    iifname "eth0" tcp dport 8443 dnat to 192.0.2.20:443 comment "nas"
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "eth0" masquerade
  }
}
END

# dnsmasq: DHCP and DNS on the LAN, with a reservation and a lease
cat > /etc/dnsmasq.conf <<'END'
interface=br0
bind-interfaces
listen-address=192.0.2.1
no-resolv
server=203.0.113.53
domain=home.example
dhcp-authoritative
dhcp-range=set:lan,192.0.2.50,192.0.2.100,255.255.255.128,12h
dhcp-option=tag:lan,option:ntp-server,192.0.2.1
dhcp-host=02:00:00:00:00:10,192.0.2.10,printer
host-record=nas.home.example,192.0.2.20
END
echo "$(( $(date +%s) + 3600 )) 02:00:00:00:00:21 192.0.2.61 laptop *" > /var/lib/misc/dnsmasq.leases
dnsmasq

# chrony without touching the clock (-x); it serves time to the LAN
cat > /etc/chrony/chrony.conf <<'END'
server 203.0.113.123 iburst
allow 192.0.2.0/24
END
chronyd -x

# logins: root and a sudo user with passwords (for the automatic setup)
echo "root:${ROOT_PASSWORD}" | chpasswd
useradd --create-home --shell /bin/bash --groups sudo "${ADMIN_USER}"
echo "${ADMIN_USER}:${ADMIN_PASSWORD}" | chpasswd
cat > /etc/ssh/sshd_config.d/10-test.conf <<'END'
PermitRootLogin yes
PasswordAuthentication yes
END
ssh-keygen -A
echo ready > /ready
exec /usr/sbin/sshd -D -e
