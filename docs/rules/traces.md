<!-- rules of src/signalbox/rules/traces.py; part of the rules documentation (docs/RULES.md lists all) -->

# Path traces

These rules compare the path traces (#253, [ADR 0014](../adr/0014-path-traces.md)) with what
the model predicts. Traces exist only while `traces.enabled` is on and after a run (*Trace
now* on the topology page, or the schedule). Both rules look only at complete traces: the
target answered, every hop answered and the trace ran without an error; anything partial is
not judged. Traces from Signalbox's own host are not judged either (its path starts in the LAN).

## `trace.not-via-tunnel`

- **Severity:** info
- **Checks:** a trace from a device to an address that one of the device's VPN tunnels routes
  (an enabled site peer whose allowed IPs contain it; a default route `0.0.0.0/0` does not
  count), whose first hop is neither the target nor inside the tunnel (a tunnel address of a
  read device, an address in a tunnel's network, or one of the peer's allowed IPs). Typical:
  the route to the other site is missing or a policy route sends it to the provider, so the
  traffic leaves the site unencrypted.
- **Stays quiet** for a trace of one hop (the other end answers with its LAN address, which
  cannot be told apart), for a tunnel that is down or disabled, and for partial traces.
- **Fix:** check the route to that network on the device (it should point into the tunnel)
  and whether the tunnel is up; trace again afterwards.

## `trace.extra-nat`

- **Severity:** info
- **Checks:** a trace from a gateway to the internet target passed more routers with private
  (RFC 1918) addresses before the first public address than the model expects: the known
  gateways in front of it (an uplink address in another gateway's network), plus one unknown
  router when the last uplink has a private address. Provider NAT (100.64.0.0/10) is not
  counted.
- **Stays quiet** when the gateway reports no uplink or the NAT class of an uplink is not
  known, for IPv6 targets, and when the trace never reached a public address.
- **Fix:** find the router at the address the finding names: put an ISP box into bridge or
  exposed-host mode, or add the router to Signalbox. Some providers number their own routers
  privately; acknowledge the finding then.
