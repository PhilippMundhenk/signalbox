"""What the EdgeOS integration runs on the device (#403), and how its answer is split.

One script per observation (``READ``) and one for the clock (``TIME``), sent on standard input
of ``sh -s`` and answered in sections (``@@<name>``, the same format as the Linux integration,
:mod:`signalbox.adapters.linux.collect`). Operational-mode commands run through
``/opt/vyatta/bin/vyatta-op-cmd-wrapper`` (present on EdgeOS 1.x/2.0 and VyOS 1.3/1.4) as the
operator-level user: ``show version``, ``show configuration commands``, ``show dhcp leases``
(EdgeOS) or ``show dhcp server leases`` (VyOS), ``show lldp neighbors detail`` and
``show interfaces wireguard <if> public-key``. The rest is ``ip -o`` (text: the iproute2 of
EdgeOS has no JSON), ``/proc`` and ``/sys``. Nothing writes, nothing needs root.

The configuration is filtered on the device: lines with a private or pre-shared key, a password,
a secret or an SNMP community are never sent (:data:`SECRET_FILTER`); the parser drops them
once more.
"""

from __future__ import annotations

from signalbox.adapters.linux.collect import Answer, split

__all__ = ["FORBIDDEN", "READ", "SECRET_FILTER", "TIME", "Answer", "split"]

#: The wrapper of the operational mode.
WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"
#: ``grep`` expression for the lines the device must not send (the parser drops them again).
SECRET_FILTER = (
    "private-key|preshared-key|pre-shared-key|pre-shared-secret|plaintext-password|"
    "encrypted-password|passphrase|community|[' ]password[' ]|[' ]secret[' ]|[' ]key[' ]"
)
#: Words that must never appear in a command sent to the device (checked by the tests).
FORBIDDEN = ("configure", "commit", "save", "delete", "reboot", "sudo")

_PRELUDE = f"""export LC_ALL=C PATH=/opt/vyatta/bin:/usr/sbin:/usr/bin:/sbin:/bin
W={WRAPPER}
[ -x "$W" ] || W=/bin/true
op() {{ "$W" "$@" 2>/dev/null; }}
"""

READ = (
    "# signalbox-read\n"
    + _PRELUDE
    + f"""echo @@version; op show version
echo @@config; op show configuration commands | grep -v -i -E "{SECRET_FILTER}"
echo @@link; ip -o link show
echo @@addr; ip -o addr show
echo @@route; ip route show table main
echo @@route6; ip -6 route show table main
echo @@sysnet
for d in /sys/class/net/*; do
  n=${{d##*/}}; dev=0; wifi=0
  [ -e "$d/device" ] && dev=1
  {{ [ -e "$d/wireless" ] || [ -e "$d/phy80211" ]; }} && wifi=1
  echo "$n $dev $wifi $(cat "$d/speed" 2>/dev/null || echo -)" \\
    "$(cat "$d/duplex" 2>/dev/null || echo -)"
done
echo @@dhcp-leases; op show dhcp leases
echo @@dhcp-leases-server; op show dhcp server leases
echo @@lldp; op show lldp neighbors detail
echo @@wg-keys
for d in /sys/class/net/*; do
  n=${{d##*/}}
  if grep -q DEVTYPE=wireguard "$d/uevent" 2>/dev/null; then
    echo "$n $(op show interfaces wireguard "$n" public-key | head -n1)"
  fi
done
echo @@uptime; cat /proc/uptime
echo @@loadavg; cat /proc/loadavg
echo @@meminfo; cat /proc/meminfo
echo @@cpus; getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null
echo @@df; df -P -T -B1 2>/dev/null
echo @@thermal
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] && echo "$(cat "$z/type" 2>/dev/null) $(cat "$z/temp" 2>/dev/null)"
done
echo @@kernel; uname -srm
echo @@end
"""
)

TIME = (
    "# signalbox-time\n"
    + _PRELUDE
    + """echo @@clock; date +%s.%N
echo @@end
"""
)
