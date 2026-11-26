#!/usr/bin/env bash
# Build the OpenWrt x86-64 integration test image (issue #137).
#
#   tools/integration/openwrt/build-image.sh <version> <output-dir>
#
# Downloads the official image builder of a pinned OpenWrt release from downloads.openwrt.org,
# checks its SHA-256 against the release's sha256sums (and against the pin below), and builds
# the squashfs combined image with packages from the release's official feeds (the image
# builder checks their signatures) and the first-boot setup in files/:
#
#   uhttpd with HTTPS (px5g certificate) and uhttpd-mod-ubus, rpcd logins "signalbox" (read ACL)
#   and "signalbox-write" (write ACL), both from docs/adapters/openwrt.md; bridge VLAN filtering
#   on br-lan over eth1/eth2; three mac80211_hwsim radios (two APs, one station); dnsmasq DHCP;
#   lldpd with luci-app-lldpd; WireGuard interface wg0 with one peer (luci-proto-wireguard).
#
# wpad-mbedtls, not wpad-basic: hostapd of wpad-basic has no 802.11v and refuses the whole
# interface when bss_transition is set ("unknown configuration item").
#
# Writes <output-dir>/openwrt.img (raw disk). Runs on a Linux x86-64 host (GitHub Actions).
# Passwords: IT_OPENWRT_PASSWORD, IT_OPENWRT_WRITE_PASSWORD, IT_OPENWRT_ROOT_PASSWORD (root over
# SSH; throwaway, the VM is only reachable through port forwards on 127.0.0.1).
set -euo pipefail

VERSION=${1:?usage: build-image.sh <version> <output-dir>}
OUT=${2:?usage: build-image.sh <version> <output-dir>}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
READ_PASSWORD=${IT_OPENWRT_PASSWORD:?set IT_OPENWRT_PASSWORD}
WRITE_PASSWORD=${IT_OPENWRT_WRITE_PASSWORD:?set IT_OPENWRT_WRITE_PASSWORD}
ROOT_PASSWORD=${IT_OPENWRT_ROOT_PASSWORD:?set IT_OPENWRT_ROOT_PASSWORD}
for pw in "$READ_PASSWORD" "$WRITE_PASSWORD" "$ROOT_PASSWORD"; do
  [[ $pw =~ ^[A-Za-z0-9._-]{8,64}$ ]] || { echo "passwords: 8-64 of A-Z a-z 0-9 . _ -" >&2; exit 2; }
done

# SHA-256 of the image builder of each pinned release (checked in addition to sha256sums).
declare -A PINNED=(
  [23.05.6]="1086f40e313369bd04146408e287bb5edb0a02555f3f6030b67c07f33baa8ba9"
  [24.10.8]="1b0511a92126ed97550d91295459f8869962f9b7c31dd3d0c7cda75c75825741"
  [25.12.6]="a792e29bd2233cda67a0823030bfb53c0b61fbb3836b2063e88adf89730d563b"
)

PACKAGES=(
  uhttpd uhttpd-mod-ubus px5g-mbedtls libustream-mbedtls
  rpcd rpcd-mod-file rpcd-mod-luci rpcd-mod-ucode rpcd-mod-iwinfo luci-base
  lldpd luci-app-lldpd
  kmod-wireguard wireguard-tools luci-proto-wireguard
  kmod-mac80211-hwsim wpad-mbedtls iw
)

BASE=https://downloads.openwrt.org/releases/$VERSION/targets/x86/64
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
CACHE=${IT_OPENWRT_DOWNLOADS:-$OUT/downloads}
mkdir -p "$CACHE"

echo "== OpenWrt $VERSION image builder"
curl -fsSL --retry 4 -o "$WORK/sha256sums" "$BASE/sha256sums"
IB=$(grep -oE 'openwrt-imagebuilder-[^ ]*x86-64\.Linux-x86_64\.tar\.(zst|xz)' "$WORK/sha256sums" | head -1)
[ -n "$IB" ] || { echo "no image builder in sha256sums" >&2; exit 1; }
WANT=$(grep -E "[ *]$IB\$" "$WORK/sha256sums" | cut -d' ' -f1)
if [ ! -f "$CACHE/$IB" ] || [ "$(sha256sum "$CACHE/$IB" | cut -d' ' -f1)" != "$WANT" ]; then
  curl -fsSL --retry 4 -o "$CACHE/$IB" "$BASE/$IB"
fi
HAVE=$(sha256sum "$CACHE/$IB" | cut -d' ' -f1)
echo "$IB sha256 $HAVE"
[ "$HAVE" = "$WANT" ] || { echo "checksum mismatch: $HAVE != $WANT (sha256sums)" >&2; exit 1; }
PIN=${PINNED[$VERSION]:-}
if [ -n "$PIN" ] && [ "$HAVE" != "$PIN" ]; then
  echo "checksum mismatch: $HAVE != $PIN (pinned in build-image.sh)" >&2
  exit 1
fi
[ -n "$PIN" ] || echo "::warning::OpenWrt $VERSION image builder not pinned in build-image.sh: $HAVE"

mkdir -p "$WORK/ib"
case "$IB" in
  *.zst) tar -C "$WORK/ib" --strip-components=1 -I zstd -xf "$CACHE/$IB" ;;
  *) tar -C "$WORK/ib" --strip-components=1 -xJf "$CACHE/$IB" ;;
esac

echo "== first-boot files"
FILES=$WORK/files
cp -a "$HERE/files" "$FILES"
mkdir -p "$FILES/usr/share/rpcd/acl.d"
python3 "$HERE/acl_from_docs.py" "$ROOT/docs/adapters/openwrt.md" > "$FILES/usr/share/rpcd/acl.d/signalbox.json"
# the WireGuard key helper of the setup guide (#152), verbatim
mkdir -p "$FILES/usr/libexec"
python3 "$HERE/acl_from_docs.py" "$ROOT/docs/adapters/openwrt.md" --wg-key-helper > "$FILES/usr/libexec/signalbox-wg-key"
chmod 0755 "$FILES/usr/libexec/signalbox-wg-key"
# root's password for SSH (the automatic setup, #231), as the md5-crypt hash /etc/shadow holds
ROOT_HASH=$(openssl passwd -1 "$ROOT_PASSWORD")
sed -i -e "s/@READ_PASSWORD@/$READ_PASSWORD/" -e "s/@WRITE_PASSWORD@/$WRITE_PASSWORD/" \
  -e "s|@ROOT_HASH@|$ROOT_HASH|" "$FILES/etc/uci-defaults/99-signalbox-it"
chmod 0755 "$FILES/etc/uci-defaults/99-signalbox-it" "$FILES/usr/bin/signalbox-it-ready" "$FILES/etc/rc.local"

echo "== image"
make -C "$WORK/ib" image PROFILE=generic PACKAGES="${PACKAGES[*]}" FILES="$FILES" \
  BIN_DIR="$WORK/bin" EXTRA_IMAGE_NAME=signalbox-it
IMG=$(find "$WORK/bin" -name '*squashfs-combined.img.gz' ! -name '*efi*' | head -1)
[ -n "$IMG" ] || { echo "no squashfs-combined image built" >&2; ls -R "$WORK/bin" >&2; exit 1; }
# OpenWrt pads the image after the gzip stream: gunzip warns "trailing garbage" (exit 2)
gunzip -c "$IMG" > "$OUT/openwrt.img" || [ $? -eq 2 ]
echo "$VERSION" > "$OUT/version"
ls -l "$OUT/openwrt.img"
