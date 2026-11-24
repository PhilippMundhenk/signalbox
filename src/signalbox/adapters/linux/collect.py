"""What the Linux integration runs on the device (#240), and how its answer is split.

One script per observation (``READ``) and one for the clock (``TIME``), each sent on standard
input of ``sh -s`` and answered in sections: a line ``@@<name>`` starts a section, inside a
file dump ``@@@ <path>`` starts a file and ``@@! <path>`` names a file that exists but cannot be
read. Every command only reads: ``ip -j``, ``bridge -j`` (VLANs, MAC address table), ``ss``,
``df``, files under ``/proc``, ``/sys`` and ``/etc``, ``systemctl is-active``/``is-enabled``,
``timedatectl show``, ``chronyc`` monitoring commands. WireGuard needs ``CAP_NET_ADMIN``:
``wg show all <field>`` runs directly (root) or through ``sudo -n`` for exactly the commands
of :data:`WG_FIELDS` (the sudoers rule of the setup guide). Never ``wg show all dump``,
``private-key`` or ``preshared-keys``, never ``/etc/wireguard``: nothing that prints a
private or pre-shared key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: ``wg show all <field>`` commands, the only ones the sudoers rule allows (in this order).
WG_FIELDS = (
    "public-key",
    "listen-port",
    "peers",
    "endpoints",
    "allowed-ips",
    "latest-handshakes",
    "transfer",
    "persistent-keepalive",
)
#: The one nftables command that needs ``CAP_NET_ADMIN``; the sudoers rule allows exactly this.
NFT = "/usr/sbin/nft"
NFT_ARGS = "-j list ruleset"
#: Words that must never appear in a command sent to the device (checked by the tests).
FORBIDDEN = ("dump", "private-key", "preshared-key", "/etc/wireguard", "showconf")

#: Services recognised by their systemd unit.
UNITS = (
    "ssh",
    "sshd",
    "dnsmasq",
    "kea-dhcp4-server",
    "isc-dhcp-server",
    "systemd-networkd",
    "AdGuardHome",
    "pihole-FTL",
    "unbound",
    "chrony",
    "chronyd",
    "systemd-timesyncd",
)

MAX_FILE = 1048576  # bytes per file (a very long lease table is cut)

_PRELUDE = f"""export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
show() {{
  for f in "$@"; do
    [ -f "$f" ] || continue
    if [ -r "$f" ]; then echo "@@@ $f"; head -c {MAX_FILE} "$f"; echo; else echo "@@! $f"; fi
  done
}}
"""

_WG = "".join(f'echo @@wg-{f}; [ -n "$WG" ] && $WG show all {f} 2>/dev/null\n' for f in WG_FIELDS)

READ = (
    "# signalbox-read\n"
    + _PRELUDE
    + """echo @@os; show /etc/os-release /etc/debian_version /etc/rpi-issue
echo @@hostname; cat /proc/sys/kernel/hostname
echo @@kernel; uname -srm
echo @@model; show /proc/device-tree/model \
  /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name
echo @@link; ip -j -d link show
echo @@addr; ip -j addr show
echo @@route; ip -j route show table main
echo @@route6; ip -j -6 route show table main
echo @@sysnet
for d in /sys/class/net/*; do
  n=${d##*/}; dev=0; wifi=0
  [ -e "$d/device" ] && dev=1
  { [ -e "$d/wireless" ] || [ -e "$d/phy80211" ]; } && wifi=1
  echo "$n $dev $wifi $(cat "$d/speed" 2>/dev/null || echo -)" \
    "$(cat "$d/duplex" 2>/dev/null || echo -)"
done
echo @@bridge-vlan; bridge -j vlan show 2>/dev/null
echo @@fdb; bridge -j -s fdb show 2>/dev/null
echo @@forward; cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null
echo @@uptime; cat /proc/uptime
echo @@loadavg; cat /proc/loadavg
echo @@meminfo; cat /proc/meminfo
echo @@cpus; getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null
echo @@df; df -P -T -B1 2>/dev/null
echo @@thermal
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] && echo "$(cat "$z/type" 2>/dev/null) $(cat "$z/temp" 2>/dev/null)"
done
echo @@units
"""
    + "for u in "
    + " ".join(UNITS)
    + """; do
  echo "$u $(systemctl is-active "$u" 2>/dev/null | head -n1)" \
    "$(systemctl is-enabled "$u" 2>/dev/null | head -n1)"
done
echo @@procs; cat /proc/[0-9]*/comm 2>/dev/null | sort -u
echo @@present
for p in /opt/AdGuardHome /etc/pihole /etc/unbound/unbound.conf; do [ -e "$p" ] && echo "$p"; done
echo @@listen; ss -Hltun 2>/dev/null
echo @@sshd; show /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
echo @@resolv; show /etc/resolv.conf
echo @@syslog; show /etc/rsyslog.conf /etc/rsyslog.d/*.conf \
  /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf
echo @@dnsmasq; show /etc/dnsmasq.conf /etc/dnsmasq.d/*.conf
echo @@dnsmasq-leases; show /var/lib/misc/dnsmasq.leases
echo @@kea; show /etc/kea/kea-dhcp4.conf
echo @@kea-leases; show /var/lib/kea/kea-leases4.csv
echo @@isc; show /etc/dhcp/dhcpd.conf
echo @@isc-leases; show /var/lib/dhcp/dhcpd.leases
echo @@networkd; show /etc/systemd/network/*.network /run/systemd/network/*.network
W=$(command -v wg 2>/dev/null); WG=""
if [ -n "$W" ]; then
  if "$W" show all public-key >/dev/null 2>&1; then WG="$W"
  elif sudo -n "$W" show all public-key >/dev/null 2>&1; then WG="sudo -n $W"
  else echo @@wg-denied; fi
fi
echo @@wg-tool; echo "${W:-none}"
N=$(command -v nft 2>/dev/null); J=""
if [ -n "$N" ]; then
  if J=$("$N" -j list ruleset 2>/dev/null); then :
  elif J=$(sudo -n "$N" -j list ruleset 2>/dev/null); then :
  else J=""; echo @@nft-denied; fi
fi
echo @@nft-tool; echo "${N:-none}"
echo @@nft; printf '%s\\n' "$J"
echo @@iptables; iptables -V 2>/dev/null
"""
    + _WG
    + "echo @@end\n"
)

TIME = (
    "# signalbox-time\n"
    + _PRELUDE
    + """echo @@clock; date +%s.%N
echo @@timedatectl; timedatectl show 2>/dev/null
echo @@timesync; timedatectl show-timesync 2>/dev/null
echo @@tracking; chronyc -n -c tracking 2>/dev/null
echo @@sources; chronyc -n -c sources 2>/dev/null
echo @@timezone; show /etc/timezone; readlink /etc/localtime 2>/dev/null
echo @@chrony; show /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf \
  /etc/chrony/sources.d/*.sources /etc/chrony.conf
echo @@timesyncd; show /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf
echo @@end
"""
)


@dataclass
class Answer:
    """The sections of a script's answer; files of a ``show`` section by path."""

    sections: dict[str, str] = field(default_factory=dict)

    def text(self, name: str) -> str:
        return self.sections.get(name, "")

    def lines(self, name: str) -> list[str]:
        return [x for x in self.text(name).splitlines() if x.strip()]

    def has(self, name: str) -> bool:
        return name in self.sections

    def files(self, name: str) -> dict[str, str]:
        """``@@@ <path>`` parts of a section, in order (unreadable files are left out)."""
        out: dict[str, list[str]] = {}
        path: str | None = None
        for line in self.text(name).splitlines():
            if line.startswith("@@@ "):
                path = line[4:].strip()
                out[path] = []
            elif line.startswith("@@! "):
                path = None
            elif path is not None:
                out[path].append(line)
        return {p: "\n".join(v).rstrip("\n") + "\n" for p, v in out.items()}

    def unreadable(self, name: str) -> list[str]:
        return [x[4:].strip() for x in self.text(name).splitlines() if x.startswith("@@! ")]

    def complete(self) -> bool:
        return self.has("end")


def split(text: str) -> Answer:
    """``@@name`` lines start sections (``@@@``/``@@!`` lines belong to a section's files)."""
    out: dict[str, list[str]] = {}
    name: str | None = None
    for line in text.splitlines():
        if line.startswith("@@") and not line.startswith(("@@@ ", "@@! ")):
            name = line[2:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return Answer({k: "\n".join(v) + ("\n" if v else "") for k, v in out.items()})
