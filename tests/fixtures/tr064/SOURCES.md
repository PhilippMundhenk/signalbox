# TR-064 service descriptions (AVM)

The device description `tr64desc.xml` and the service descriptions (SCPD) of the services the
Fritz!Box adapter uses, as a FRITZ!Box serves them at `https://<box>:49443/<file>` (no
authentication needed). They are AVM's published interface specification. The simulator
(`signalbox.sim.fritzbox`) is built from them and serves them; `tests/test_fritzbox_scpd.py`
checks every action and argument the adapter sends or reads against them.

| Directory | FRITZ!OS | Box |
| --- | --- | --- |
| `fritzos-7.57/` | 154.07.57 | FRITZ!Box 7590 |
| `fritzos-8.02/` | 164.08.02 | FRITZ!Box 7530 |

## Source

Fetched 2026-11-22. AVM's download area (`avm.de`, `fritz.com`, `fritz.support`) could not be
reached from the build environment (refused by its network gateway), so the files were taken
from a public dump of the files real boxes serve: repository
[nitram509/gofritz](https://github.com/nitram509/gofritz) (MIT), commit
`a363f90eab4eb7f5ecdcf9058c07216d7384d4e6` (2025-03-15), directories
`__sdcp__/FRITZBox_7590_154.07.57/` and `__sdcp__/FRITZBox_7530_164.08.02/`.

`wancommonifconfigSCPD.xml` (WANCommonInterfaceConfig:1, added for the uplink, #148) is from
the same dump and commit, for both versions.

### The management service descriptions (#173)

`x_remoteSCPD.xml` (X_AVM-DE_RemoteAccess:1), `x_myfritzSCPD.xml` (X_AVM-DE_MyFritz:1),
`x_storageSCPD.xml` (X_AVM-DE_Storage:1) and `x_upnpSCPD.xml` (X_AVM-DE_UPnP:1) are from the
same gofritz dump and commit as the first files (MIT, same directories), byte for byte, for both
versions. The four files are identical in the 7.57 and the 8.02 dump. (`GetSecurityPort` is an
action of the `deviceinfoSCPD.xml` that was already there.)

### The WAN connection descriptions

The gofritz dump has only the services of the root device, not those of the embedded
`WANConnectionDevice`: `wanpppconnSCPD.xml` (WANPPPConnection:1) and `wanipconnSCPD.xml`
(WANIPConnection:1), which both `tr64desc.xml` files list, are not in it. They were taken from
[udondan/fritz](https://github.com/udondan/fritz) (Apache-2.0, licence text in
[LICENSE-udondan-fritz](LICENSE-udondan-fritz)), commit
`6a972e5a43fc89d9ac33f8b5a1e8ba9201e35311` (2026-11-22), directory
`crates/fritz-sim/fixtures/fritzbox-7690/8.25/scpd/`: the files a FRITZ!Box 7690 with FRITZ!OS
8.25 serves, recorded by that project's fixture recorder. The same two files in
[chikenborgir/avmtools](https://github.com/chikenborgir/avmtools) (MIT), commit
`5a8140dbb9bd54277ca3a343d415d564a12f9079`, `docs/xml/WANPPPConnection/` and
`docs/xml/WANIPConnection/` (FRITZ!Box 7530 AX, FRITZ!OS 7.29), have the same actions with the
same arguments; the 8.25 `wancommonifconfigSCPD.xml` is byte for byte the 7.57/8.02 one of the
gofritz dump. So the 8.25 files are copied into both version directories unchanged, on the
assumption that 7.57 and 8.02 describe these two services the same way; a box of those versions
can confirm it (`https://<box>:49443/wanpppconnSCPD.xml`).

The firewall reader (#135) uses `GetGenericPortMappingEntry` of these two descriptions: no new
file was needed.

### The account description (#175)

`lanconfigsecuritySCPD.xml` (LANConfigSecurity:1: `GetInfo` with
`NewX_AVM-DE_IsDefaultPasswordActive`, `X_AVM-DE_GetCurrentUser`, `X_AVM-DE_GetUserList`) is
from the same gofritz dump and commit as the first files (MIT, same directories), byte for
byte; it is identical in the 7.57 and the 8.02 dump. Fetched 2026-11-24.

AVM also publishes the same descriptions as PDFs per service ("TR-064 First Steps" and the
`...SCPD.pdf` files on avm.de / fritz.support). When they can be reached, compare these files
with them; a difference is a bug in the simulator or the adapter.

## Changes to the upstream files

The SCPD files are byte for byte as in their source. In `tr64desc.xml` only device specific
values were neutralised (the dump had already replaced `UDN` and `serialNumber` with
placeholders):

- `presentationURL` `http://192.168.178.1` -> `http://192.0.2.1` (documentation address);
- `fritzos-8.02/tr64desc.xml`: the box's own `friendlyName` -> `FRITZ!Box 7530`.

SHA-256 of the upstream files:

```
5e03cff7a8d10d9865c5475a779f736389c705c371c7cee50b1cf67585a4b6f6  7.57/deviceinfoSCPD.xml
c1af0e6a18c67690e130baa5f981ecf117dd60d7a212f00b2553a28594ed6507  7.57/ethifconfigSCPD.xml
703cd4a4f140a7ff65726559657c12a3a14c0f942b7ca840af77b442063a7806  7.57/hostsSCPD.xml
61d38470df5da85a7f8c51c125a308e20bf31dee91811e6a3b73cb4d7937d1cc  7.57/lanhostconfigmgmSCPD.xml
2c009731674169cb9f15c516912a7bafa8b169b3a0f4762655bcb3515440014d  7.57/timeSCPD.xml (added for #179)
6cd3b37ac1764e78d53c5aa7b691a6d9ace455bb84ac662f2af7ccde6808b102  7.57/tr64desc.xml (before neutralising)
b06d84466ee163ee6a8230385b73c9ceffae68d148e38bc41320ebe5936225ca  7.57/wlanconfigSCPD.xml
6698775c01958d7724172165f22cb34858790b7ce6493e9878f460b2e4c05280  8.02/deviceinfoSCPD.xml
c1af0e6a18c67690e130baa5f981ecf117dd60d7a212f00b2553a28594ed6507  8.02/ethifconfigSCPD.xml
703cd4a4f140a7ff65726559657c12a3a14c0f942b7ca840af77b442063a7806  8.02/hostsSCPD.xml
61d38470df5da85a7f8c51c125a308e20bf31dee91811e6a3b73cb4d7937d1cc  8.02/lanhostconfigmgmSCPD.xml
2c009731674169cb9f15c516912a7bafa8b169b3a0f4762655bcb3515440014d  8.02/timeSCPD.xml (added for #179)
36ea90acc52f7bccfe67c807cee5e58371f5470bfd9ebbceab93335320bb2841  8.02/tr64desc.xml (before neutralising)
85c824ee7e52dc0c6ed490af7fd27c8dc612476c1969034b6b1ad65fd7b24457  8.02/wlanconfigSCPD.xml
1c52829abceadeb81e9edcc91dfbd7977143b562d741a240aaefd5316647e5bd  7.57/wancommonifconfigSCPD.xml
1c52829abceadeb81e9edcc91dfbd7977143b562d741a240aaefd5316647e5bd  8.02/wancommonifconfigSCPD.xml
493476ce98a30fd30c3d189ecfcbbe3d298680585d6058bafb05c30a6115e7e1  7.57/x_myfritzSCPD.xml and 8.02/x_myfritzSCPD.xml
41bca5adc39ed85d460de6c72fbfd502691f5dcd8646d8c52780269fb41f20a0  7.57/x_remoteSCPD.xml and 8.02/x_remoteSCPD.xml
49cac9619e97207e300e23e875fa6f3d4f20cb81199148215a3069f4f08dcd2b  7.57/x_storageSCPD.xml and 8.02/x_storageSCPD.xml
c0ffefe56417077e48fe428bb4658ee00c5510964eaf674bfdf4deb9d9818ab5  7.57/x_upnpSCPD.xml and 8.02/x_upnpSCPD.xml
8e2ec74932d4154a8670ffcfa2cf4152ed02fff8a062e6a9a971987e57fb19ff  7.57/lanconfigsecuritySCPD.xml and 8.02/lanconfigsecuritySCPD.xml
0e6cb75dcffc0fcdd6d5a3a9dbdbe125a7abce3fa08413c2c5e8856379311517  udondan/fritz 8.25/wanipconnSCPD.xml
c1ece74a5f4cb89c66ad15f608abe1817841a718f29e95115e657ffbc34a0046  udondan/fritz 8.25/wanpppconnSCPD.xml
```

## What the descriptions do not say

SCPD files list actions, arguments, data types and allowed values, not fault codes. The
simulator answers with the error codes of the UPnP Device Architecture that TR-064 uses
(401 Invalid Action, 402 Invalid Args, 501 Action Failed, 600 Argument Value Invalid,
601 Argument Value Out of Range, 606 Action Not Authorized, 713 SpecifiedArrayIndexInvalid,
714 NoSuchEntryInArray, 820 Internal Error). Which code a box gives for which mistake is
not specified there and still needs confirmation on a real device (#21).

## Licence

The files were taken from nitram509/gofritz, MIT licence, copyright (c) 2023 Martin W. Kirst; the
licence text is in [LICENSE-gofritz](LICENSE-gofritz). `wanpppconnSCPD.xml` and
`wanipconnSCPD.xml` were taken unchanged from udondan/fritz, Apache License 2.0; the licence
text is in [LICENSE-udondan-fritz](LICENSE-udondan-fritz). The service descriptions themselves are
AVM's published TR-064 interface specification.

### Layer3Forwarding (#149)

`layer3forwardingSCPD.xml` (Layer3Forwarding:1, the static IPv4 routes and the default
connection) is from the same gofritz dump and commit, byte for byte, for both versions.

## FRITZ!OS 7.29 and 6.83 (#413)

`fritzos-7.29/` is the files of a FRITZ!Box 7530 AX with FRITZ!OS 7.29 (`256.07.29`), byte for
byte from [chikenborgir/avmtools](https://github.com/chikenborgir/avmtools) (MIT), commit
`5a8140dbb9bd54277ca3a343d415d564a12f9079`, `docs/xml/<Service>/FRITZ_Box_7530_AX_07.29_*.xml`
and `docs/xml/FRITZ_Box_7530_AX_07.29_tr64desc.xml`, copied under the names the other
directories use. Only `presentationURL` of `tr64desc.xml` was neutralised
(`http://fritz.box` -> `http://192.0.2.1`). Against 7.57 the 7.29 files lack, among others,
`NewX_AVM-DE_IsDefaultPasswordActive`, `NewX_AVM-DE_FrequencyBand`,
`NewX_AVM-DE_AutoChannelEnabled`, `NewX_AVM-DE_WLANGlobalEnable`, `SetMyFRITZ`,
`SetLetsEncryptEnable`.

`fritzos-6.83/` is **derived, not a real box's files**: no 6.x service descriptions could be
found or fetched (AVM's pages are not reachable from the build environment). It is the 7.29 set
with these removals, which are guesses of what FRITZ!OS 6.83 lacks (#21): the actions
`X_AVM-DE_GetCurrentUser` and `X_AVM-DE_GetUserList` (LANConfigSecurity),
`X_AVM-DE_GetHostListPath` and `X_AVM-DE_GetMeshListPath` (Hosts), `X_AVM-DE_GetWLANExtInfo`
(WLANConfiguration), and the WPA3 beacon types `WPA3`, `11iandWPA3`, `OWE`, `OWETrans` from the
allowed values of `BeaconType`; `tr64desc.xml` shows `113.06.83` and `FRITZ!Box 7490`. Replace
the directory with a real box's files when one is available.
