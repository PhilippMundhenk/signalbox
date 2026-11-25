# The Linux gateway target of the integration tests (#240): Debian 11, 12 or 13 (build argument DEBIAN, #417) with OpenSSH, iproute2,
# dnsmasq, chrony, WireGuard tools, nftables, iptables (the nf_tables backend; the legacy backend is switched on by the tests, #394), sudo and
# tracepath (path traces, #253). start.sh builds the network (needs NET_ADMIN and the
# host's dummy, 8021q, bridge, wireguard and nf_tables modules) and runs the daemons.
ARG DEBIAN=12
FROM debian:${DEBIAN}-slim
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      openssh-server iproute2 dnsmasq chrony wireguard-tools nftables iptables sudo \
      passwd procps iputils-tracepath \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/lib/misc /etc/chrony
COPY start.sh /start.sh
RUN chmod 755 /start.sh
EXPOSE 22
CMD ["/start.sh"]
