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
touch adapters, simulators or the integration setup.

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
  radio2 a station associated to it, so hostapd has a client and dnsmasq a lease.

`tools/integration/openwrt/start-vm.sh <image> <run-dir>` boots it with KVM: `eth0` on QEMU's
user-mode network with `127.0.0.1:8443` forwarded to the guest's HTTPS, the serial console in
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
