# Finding devices

*Find devices* on the devices page looks for devices of the installed integrations, so that you
do not have to know each address and port: Signalbox lists what it found, *Add* opens the device
form with integration, role, address and a name filled in, and you enter the user and password.
Nothing is changed on any device, and no credential is sent while searching. The decision
behind it is [ADR 0006](adr/0006-discovery-probes.md).

## When it runs

Only when you press *Search now*. There is no background or scheduled search. To turn it off
completely (the button disappears and the API refuses), set

```yaml
discovery:
  enabled: false
```

or `SIGNALBOX_DISCOVERY_ENABLED=false`. The other settings are in
[CONFIGURATION.md](CONFIGURATION.md#discovery).

## Where it looks

Only where Signalbox already knows the network, or where you point it:

| Source | What is probed |
| --- | --- |
| Gateway subnets of the routers you added | IPv4 subnets of /24 or smaller (`discovery.sweep_prefix`): every address; larger ones and IPv6: only the gateway address |
| Clients and DHCP reservations those routers report | their IPv4 addresses |
| LLDP neighbours | their management address |
| *Also search these addresses* | what you type: an address (`192.0.2.10`), a host name (`fritz.box`), a network (`192.0.2.0/28`) or a range (`192.0.2.10-192.0.2.20`, `192.0.2.10-20`) |
| Switch broadcasts | Signalbox's own network segment (see below) |

Uncheck *Search the networks of the routers I added* to probe only what you typed. At most
`discovery.max_hosts` (1024) addresses are probed in one run. Network devices are probed first:
gateways, LLDP neighbours, and clients with the MAC prefix of a supported vendor or a host name
like `fritz…`, `openwrt`, `switch`, `ap1`. The page shows *What was searched*.

## What is sent

To each address, every integration's probe in this order (a device may match more than one,
for example a router that also runs a controller). All requests are
unauthenticated; TLS certificates are not checked and not pinned (that happens when you add
the device, before the first login is sent); redirects are not followed; answers are read up
to 256 KiB. The defaults allow 30 requests per second (`discovery.rate_per_second`), 16 addresses
at once (`discovery.concurrency`) and 2 seconds per request (`discovery.timeout_seconds`). An
address that does not answer on two ports, or has no route, is given up.

| Integration | Requests | Recognised by | Tells |
| --- | --- | --- | --- |
| AVM Fritz!Box | `GET http://<host>:49000/tr64desc.xml`; then `POST http://<host>:49000/upnp/control/deviceinfo` with `DeviceInfo:1 GetSecurityPort` | manufacturer AVM or a model `FRITZ!…` in the TR-064 description | model, FRITZ!OS version, the TR-064 HTTPS port (`https://<host>:49443`) |
| MikroTik | `GET https://<host>/rest/system/resource`; else the same over `http`; else `GET /` (WebFig) over https, then http | HTTP 401 with `WWW-Authenticate: Basic realm="RouterOS"`; or `RouterOS` on the WebFig page | only that it is RouterOS (the model needs a login); without REST over HTTPS: a note to switch on `www-ssl` |
| Omada controller | `GET https://<host>:8043/api/info`; else `https://<host>/api/info` (OC200/OC300) | `errorCode 0` with an `omadacId` | controller version |
| OpenWrt | `POST https://<host>/ubus` (else `http`) with JSON-RPC `call` `system board` in the null session `00000000000000000000000000000000`; else `GET /cgi-bin/luci/` over https, then http | a JSON-RPC 2.0 answer (normally `-32002 Access denied`); or LuCI's page | model and release only if the device lets the null session read them; notes when HTTPS or ubus over HTTP is missing |
| OPNsense | `GET https://<host>/` | the login page: `OPNsense` and the fields `usernamefld`/`passwordfld` | only that it is OPNsense |
| NETGEAR ProSAFE Plus | once per run: NSDP read request for the identity tags, UDP from port 63321 to `255.255.255.255:63322` on every interface | an NSDP answer | model, name, MAC, IP address, firmware |
| TP-Link Easy Smart | once per run: discovery request, UDP from port 29809 to `255.255.255.255:29808` | an Easy Smart answer (by broadcast to port 29809) | model, name, MAC, IP address, firmware |

Requests to the same URL are sent once per address (OPNsense's and MikroTik's `GET /` share the
answer). Integrations installed as plugins may add their own probes
([ADAPTERS.md](ADAPTERS.md#discovery)); integrations that run as separate programs do not probe.

## What happens with the answers

A found device is a suggestion. What it told (model, name, firmware) is untrusted text: control
and direction characters are removed, it is cut to 80 characters and shown only as text. It is
kept in memory until the next search; nothing is stored except your *Ignore* list (integration
and address). The role is the integration's usual one (a router for the gateway address of a
subnet you already know); check it in the form. Devices already added (same integration and
the same host in their settings or as their management address) are marked *Added*.

The form then works as for any device: *Test connection* shows the device's certificate, you
compare and trust it, and only then is the login sent.

## ProSAFE Plus and Easy Smart switches: host networking

The switches answer the broadcast only in the same layer-2 network segment, and Easy Smart
switches answer by broadcast. In Docker's default bridge network the broadcast never leaves the
container's network, so no switch answers; the search then says so. Run the container with host
networking for switches to be found (and read):

```yaml
services:
  signalbox:
    network_mode: host
```

Without Switchyard (`pip install ".[switches]"`; the container image has it) the switches are
not searched, and the search says that too. Switches in another network segment can still be
added by hand with their address.

## Not covered

SSDP/UPnP and mDNS announcements are not listened to: that would need a listener running all
the time. The signatures above follow the vendors' documentation and the simulators; please
report in [#21](https://github.com/PhilippMundhenk/signalbox/issues/21) what a real device
answers.
