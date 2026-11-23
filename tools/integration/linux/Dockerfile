# The Linux gateway target of the integration tests (#240): Debian 12 with OpenSSH, iproute2,
# dnsmasq, chrony, WireGuard tools, nftables, iptables (the nf_tables backend), sudo and
# tracepath (path traces, #253). start.sh builds the network (needs NET_ADMIN and the
# host's dummy, 8021q, bridge, wireguard and nf_tables modules) and runs the daemons.
FROM debian:12-slim
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      openssh-server iproute2 dnsmasq chrony wireguard-tools nftables iptables sudo \
      passwd procps iputils-tracepath \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd
COPY start.sh /start.sh
RUN chmod 755 /start.sh
EXPOSE 22
CMD ["/start.sh"]
