# The Linux gateway target of the integration tests (#240): Debian 12 with OpenSSH, iproute2,
# dnsmasq, chrony, WireGuard tools and sudo. start.sh builds the network (needs NET_ADMIN and
# the host's dummy, 8021q, bridge and wireguard modules) and runs the daemons.
FROM debian:12-slim
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      openssh-server iproute2 dnsmasq chrony wireguard-tools sudo passwd procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd
COPY start.sh /start.sh
RUN chmod 755 /start.sh
EXPOSE 22
CMD ["/start.sh"]
