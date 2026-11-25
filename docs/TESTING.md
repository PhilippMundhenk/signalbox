# Testing

| Suite | Command | What it checks |
| --- | --- | --- |
| Unit and simulator tests | `make test` | every module, every adapter against its simulator (`src/signalbox/sim/`), the 95 % coverage gate |
| Browser tests | `make e2e` | the web interface in Chromium |
| Container smoke test | `make smoke` | the Docker image starts and answers |
| Integration tests | `make integration` | adapters against the **real device software**, emulated or in a container |

The simulators answer like the real software as far as it is known; the integration tests are
where that is checked. When a real target disagrees with a simulator, the adapter is fixed
**and** the simulator is changed to answer like the real software, so the normal suite keeps
testing the real behaviour (#136).

## Simulators that cannot be checked against the real software

Some devices cannot run emulated (#136), so their simulators are built from the closest thing to
the real implementation there is, and tests check the adapters against that:

- **Fritz!Box**: `signalbox.sim.fritzbox` is built from AVM's TR-064 descriptions
  (`tests/fixtures/tr064/`, `tr64desc.xml` and the SCPD files of FRITZ!OS 7.57 and 8.02, with
  their source in `SOURCES.md`). It serves them, answers only described actions and arguments
  with the described data types, and refuses the rest with the UPnP fault.
  `tests/test_fritzbox_scpd.py` checks every action and argument the adapter sends or reads
  against the descriptions, for both versions; a wrong name fails it. What the descriptions
  corrected is listed in [adapters/fritzbox.md](adapters/fritzbox.md#checked-against-avms-service-descriptions).
- **ProSAFE Plus, Easy Smart**: Switchyard's simulators are the reference
  ([ADR 0003](adr/0003-switchyard-library.md)); the published captures of real switches are
  pinned with the Switchyard commit in `tests/fixtures/switches/captures.json` and
  `tests/test_switch_captures.py` checks the pinned Switchyard against them byte for byte.
- **Recordings of real devices**: see below.

## Recordings of real devices (record and replay)

A device report (#21) is most useful as a recording: what the device answered to Signalbox,
with private data neutralised, replayed as a regression test.

```sh
pip install -e ".[dev]"
export SIGNALBOX_RECORD_PASSWORD='...'          # the password or API secret, never an argument
python tools/record_device.py --adapter fritzbox --url https://192.0.2.1:49443 \
  --username signalbox --show-fingerprint       # compare it with what the browser shows
python tools/record_device.py --adapter fritzbox --url https://192.0.2.1:49443 \
  --username signalbox --pin <fingerprint> --note "FRITZ!Box 7590, FRITZ!OS 7.57" \
  --out fritzbox-7590-7.57.json
```

Use the address of the device as you reach it; it is replaced in the file. Further settings
of the adapter (see its page under [adapters/](adapters/)) are given with `--set key=value`,
and `--role ap` where the device is not the gateway. It works for the adapters that talk
HTTP(S): `fritzbox`, `openwrt`, `opnsense`, `mikrotik`, `omada`. The first secret setting
(password, API key, client secret) is read from `SIGNALBOX_RECORD_PASSWORD`, further ones from
`SIGNALBOX_RECORD_<SETTING>` (OPNsense: `SIGNALBOX_RECORD_API_SECRET`).

- **Only reads.** The tool observes the device once through its adapter (`observe()`); nothing
  is changed, no change is planned or applied.
- **Recorded:** every HTTP exchange of the adapter's `DeviceHttp` (method, path, the
  `SOAPAction` and `Content-Type` headers, body, status, content type and body of the answer).
  Not recorded: credentials (`Authorization`, cookies) and digest challenges.
- **Neutralised** (`signalbox.recording.Neutraliser`), the same value always to the same
  placeholder so the replay still fits together:
  - IPv4 addresses: each /24 network to a documentation network (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24, then 198.18.0.0/15), the last octet kept, so addresses
    stay in their subnets; masks, loopback, multicast and broadcast stay;
  - IPv6 addresses: each /64 to `2001:db8:<n>::/64`, interface ids to `::<n>`, link-local to
    `fe80::<n>`;
  - MAC addresses: to `00:00:5e:00:53:<n>` (the documentation range of RFC 7042), from the
    257th on `02:00:5e:00:..`;
  - secrets (passwords, passphrases, pre-shared and WEP keys, tokens, session ids, `sid=` in
    URLs, serial numbers): `redacted-secret-<n>`; the password given to the tool becomes
    `recorded-secret`, the user name `recorded-user`;
  - names people chose (SSIDs, host names, friendly names, descriptions, comments, domain
    names other than vendor defaults such as `fritz.box`): `name-<n>`;
  - free-text logs (`NewDeviceLog` and other fields ending in `log`): emptied.

  Model and firmware version stay: they are what the report is about. Names inside other
  free text and MAC addresses written without separators are **not** found, so read the file
  before you publish it.
- **Replayed:** the tool then replays the neutralised file through the adapter and stores the
  snapshot the adapter made of it (`snapshot`), and warns if the adapter asked for something
  that was not recorded.

Attach the file to your report on #21 (or open a pull request adding it to
`tests/fixtures/recordings/`). `tests/test_recordings.py` replays every file there through its
adapter over pinned TLS (`signalbox.recording.create_app`, which answers each request with
the recorded answer, in order for repeated requests, and 501 for anything not recorded): the
adapter must report exactly the stored snapshot and pass the contract checks. When a change
of the adapter changes the snapshot on purpose, replay the file again with
`signalbox.recording.replay_snapshot` and commit the new snapshot with the change, so the
review shows what changed for that device.

The replay also runs on its own, as a simulator of the recorded device:
`SIGNALBOX_REPLAY=recording.json uvicorn --factory signalbox.recording:create_app`.
`tests/fixtures/recordings/fritzbox-simulator-7.57.json` is an example, recorded from the
Fritz!Box simulator.

## Integration tests

`tests/integration/` (marker `integration`, left out of `make test`). Each target is a real
device's software: an official image in QEMU or a vendor container. The tests read it
through the adapter (`signalbox.testing.assert_contract` plus the mapping of a known lab
configuration), pin its certificate, and deploy changes through the same `Deployer` as the
web interface: plan, backup, apply, verify, confirm, then revert, and the device's
configuration must be exactly what it was.

A target is given by environment variables (`IT_` and not `SIGNALBOX_`, which are settings):

| Variable | |
| --- | --- |
| `IT_<TARGET>_URL` | where the device answers; without it the target's tests are skipped |
| `IT_<TARGET>_USER`, `IT_<TARGET>_PASSWORD` | read-only login |
| `IT_<TARGET>_WRITE_USER`, `IT_<TARGET>_WRITE_PASSWORD` | login with write access |
| `IT_<TARGET>_PIN` | certificate fingerprint to pin (default: read from the device) |
| `IT_<TARGET>_<OTHER>` | target specific, for example `IT_OPENWRT_VERSION` |
| `REQUIRE_INTEGRATION=1` | a target that is not configured fails instead of skipping (CI) |

The framework (`tests/integration/conftest.py`: the `target` fixture and certificate
fingerprints; `tests/integration/lab.py`: a Signalbox installation with one device for
deployment round trips; `tools/integration/annotate.py`: failure output as CI annotations) is
shared by all targets. Each target has a directory `tools/integration/<target>/` that builds and
starts it, a test module `tests/integration/test_<target>_real.py` and a job in
`.github/workflows/integration.yml`, which runs nightly, on demand and on pull requests that
touch adapters, simulators or the integration setup. The automatic setup with an admin login
(#231) has a module of its own per target, `tests/integration/test_<target>_setup_real.py`,
run as a separate step (OPNsense, MikroTik: right after the boot, so its failure is among the
first 50 annotations of the check run; OpenWrt: after the other tests, as it rewrites the ACL
file): it creates a login the image does not
have (`signalbox-auto`, or `signalbox` on OPNsense), reads the device with it and removes it.
The same modules test *Fix it* (#215): OpenWrt with an outdated ACL file and a stopped lldpd,
OPNsense with a privilege taken from the user; package installs are simulator only (#21).

### OpenWrt (x86-64 in QEMU)

`tools/integration/openwrt/build-image.sh <version> <dir>` downloads the official image
builder of a pinned OpenWrt release, checks its SHA-256 against the release's `sha256sums` (and
the pin in the script), and builds the squashfs image with packages from the release's
official feeds (`uhttpd-mod-ubus`, `rpcd-mod-*`, `luci-app-lldpd`, `kmod-mac80211-hwsim`,
`wpad-mbedtls`) and a first-boot script (`files/etc/uci-defaults/99-signalbox-it`):

- HTTPS on uhttpd with the self-signed certificate px5g makes at first start;
- rpcd logins `signalbox` (read) and `signalbox-write` (read and write) with the ACL taken
  verbatim from [adapters/openwrt.md](adapters/openwrt.md), so a wrong ACL in the
  documentation fails the tests;
- `br-lan` with VLAN filtering over `eth1` and `eth2`: VLAN 1 `lan` (192.0.2.1/24, untagged on
  both, dnsmasq DHCP) and VLAN 20 `iot` (198.51.100.1/24, tagged on `eth2`);
- three `mac80211_hwsim` radios: SSID `Example-IT` on radio0 (2.4 GHz) and radio1 (5 GHz),
  radio2 a station associated to it, so hostapd has a client and dnsmasq a lease;
- root's password (`IT_OPENWRT_ROOT_PASSWORD`, as the md5-crypt hash in `/etc/shadow`) and
  dropbear on every interface, for the automatic setup over SSH (#231).

`tools/integration/openwrt/start-vm.sh <image> <run-dir>` boots it with KVM: `eth0` on QEMU's
user-mode network with `127.0.0.1:8443` forwarded to the guest's HTTPS and `127.0.0.1:8022`
to its SSH, the serial console in
`<run-dir>/console.log`, and waits for `SIGNALBOX-IT-READY` there. Then:

```sh
export IT_OPENWRT_URL=https://127.0.0.1:8443/ubus IT_OPENWRT_USER=signalbox \
  IT_OPENWRT_PASSWORD=... IT_OPENWRT_WRITE_USER=signalbox-write IT_OPENWRT_WRITE_PASSWORD=...
make integration
```

This needs a Linux x86-64 host with QEMU (and `/dev/kvm` for speed); the GitHub Actions job
`Integration / OpenWrt` does all of it, with the image cached. A failing run shows the end of
the serial console and the pytest errors as annotations on the check run.

What the real OpenWrt showed that the simulator had wrong is listed in
[adapters/openwrt.md](adapters/openwrt.md#verified-against-the-real-openwrt).

### MikroTik (RouterOS CHR in QEMU)

`tools/integration/mikrotik/`, job `Integration / MikroTik`; see
[adapters/mikrotik.md](adapters/mikrotik.md#integration-tests).

### TP-Link Omada (Software Controller in Docker)

`tools/integration/omada/`, job `Integration / Omada`; see
[adapters/omada.md](adapters/omada.md#integration-tests).

### OPNsense (nano image in QEMU)

`tools/integration/opnsense/`, job `Integration / OPNsense`; see
[adapters/opnsense.md](adapters/opnsense.md#integration-tests).

### Linux gateway (Debian 11, 12 and 13 in Docker)

`tools/integration/linux/` (`target.py start` builds the container, creates the read user with
the commands of the setup guide and exports the `IT_LINUX_*` variables), job
`Integration / Linux gateway`; see [adapters/linux.md](adapters/linux.md#integration-tests).
