# MAC vendor database (OUI)

Signalbox shows the vendor of each client and uses it for `clients.vendor-network`. It works
offline: the data ships inside the package as `src/signalbox/data/oui.bin.xz` (about 240 KB,
40,000 prefixes), and nothing is looked up on the internet.

## Source and licence

The data comes from the **IEEE Registration Authority** public registry of MAC address blocks,
the "MA-L" list (24-bit prefixes, also called OUI), published at
<https://standards-oui.ieee.org/oui/oui.csv>. The IEEE makes this list freely available for
download so that anyone can look up who holds a prefix; it does not attach a separate open-source
licence to it. Signalbox keeps only the facts it needs, the prefix and a shortened company name
(legal forms such as "Co., Ltd." removed, street addresses dropped), and credits the IEEE as the
source. MA-M and MA-S blocks (longer prefixes shared by small vendors) are not included yet: such
a MAC shows no vendor, which is the safe answer.

## Regenerating

```
python tools/gen_oui.py path/to/oui.csv     # a downloaded registry file
python tools/gen_oui.py --download          # fetch it from the IEEE first
```

The output is deterministic for a given input. File format: see `signalbox.oui.encode`.

## What is guessed and what is not

- A **locally administered** MAC (second-lowest bit of the first byte set: the "private Wi-Fi
  address" of phones, virtual machines) has no vendor. Signalbox never guesses one.
- A group (multicast) address has no vendor either.
- A vendor is mapped to a device kind (`iot` or `camera`) only when almost everything it sells
  is of that kind: for example Espressif, Tuya, Shelly, Sonos, WiZ, Signify, IKEA, Ring, Arlo,
  Hikvision, Dahua. Vendors that also build computers, phones, routers or media players (Apple,
  Amazon, Google, Samsung, Xiaomi, TP-Link, Ubiquiti, Sercomm, ...) are deliberately left out:
  the vendor says little about a given device, and a wrong guess produces a wrong finding. The
  map is `_KINDS` in `src/signalbox/oui.py`; extend it only with vendors that fit this rule.
- The kind is a hint. It is never written to the client's category; a category you set in an
  annotation always wins (and `clients.vendor-network` stays quiet for that client).
