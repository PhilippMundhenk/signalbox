<!-- rules of src/signalbox/rules/time_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Time and NTP

These checks read the clock, time zone and NTP settings a device reports (capability `time`)
and the NTP servers a DHCP server hands out (option 42). A check stays silent for a device that
does not report the value. An NTP server is *local* when its address lies in a known network or
a private range (RFC 1918, CGNAT, link-local, ULA); it is *public* when it is any other address
or the name of a well-known public service (`*.ntp.org`, `time.google.com`,
`time.cloudflare.com`, `time.apple.com`, `time.windows.com`, `time.facebook.com`,
`time.aws.com`, `*.nist.gov`, `*.ptb.de`, `ntp.ubuntu.com`). Other names may be local
(`router.lan`) and are not counted as public.

## `time.offset`

- **Severity:** warning
- **Checks:** a device's clock differs from Signalbox's by at most 60 seconds, plus the
  uncertainty of the reading (half the request's round trip). Signalbox's own clock is the
  reference: keep the host that runs it synchronised.
- **Fix:** configure NTP on the device (the finding names a device of the site that serves
  time) and check that it reaches the server.

## `time.not-synchronised`

- **Severity:** warning when NTP is configured but not synchronised; info when the NTP client is
  off or has no server
- **Checks:** a device's NTP client is on, has a server and is synchronised. An unknown sync
  state is not reported.
- **Fix:** turn on the NTP client with a server (preferably the gateway); for a client that does
  not synchronise, check the server address, the firewall and DNS.

## `time.ntp-unreachable`

- **Severity:** warning
- **Checks:** an NTP server address of a device that lies in a known network is used by a known
  device or client (checked only where clients are reported for that network), and when it is a
  known device that reports its NTP server, that device serves time on that network. Names and
  addresses outside the known networks are not checked.
- **Fix:** point the device to a device that serves time, or turn on that device's NTP server
  for the network.

## `time.dhcp-ntp-mismatch`

- **Severity:** warning
- **Checks:** the same as `time.ntp-unreachable` for the NTP servers an enabled DHCP server
  hands out.
- **Fix:** hand out the address of a device that serves time (usually the gateway), or turn on
  its NTP server for that network.

## `time.no-local-ntp`

- **Severity:** info
- **Checks:** per site, devices other than gateways that do not serve time themselves use at
  least one local NTP server. Reported when only public servers are configured and either a
  device of the site serves time (the finding names it) or a gateway of the site reports that it
  does not. Silent when nothing is known about the gateway's NTP server.
- **Fix:** point the devices (and DHCP option 42) to the gateway, after turning on its NTP
  server.

## `time.timezone`

- **Severity:** info
- **Checks:** all devices of a site use the same offset from UTC. The offset is the one the
  device reports, or is derived from an IANA zone name (`Europe/Berlin`) at the time of
  reading; POSIX TZ strings without a reported offset are not compared. Zones with different
  names but the same offset are not reported.
- **Fix:** set the same time zone on every device of the site.
