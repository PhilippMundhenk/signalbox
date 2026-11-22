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

AVM also publishes the same descriptions as PDFs per service ("TR-064 First Steps" and the
`...SCPD.pdf` files on avm.de / fritz.support). When they can be reached, compare these files
with them; a difference is a bug in the simulator or the adapter.

## Changes to the upstream files

The SCPD files are byte for byte as in the source. In `tr64desc.xml` only device specific
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
6cd3b37ac1764e78d53c5aa7b691a6d9ace455bb84ac662f2af7ccde6808b102  7.57/tr64desc.xml (before neutralising)
b06d84466ee163ee6a8230385b73c9ceffae68d148e38bc41320ebe5936225ca  7.57/wlanconfigSCPD.xml
6698775c01958d7724172165f22cb34858790b7ce6493e9878f460b2e4c05280  8.02/deviceinfoSCPD.xml
c1af0e6a18c67690e130baa5f981ecf117dd60d7a212f00b2553a28594ed6507  8.02/ethifconfigSCPD.xml
703cd4a4f140a7ff65726559657c12a3a14c0f942b7ca840af77b442063a7806  8.02/hostsSCPD.xml
61d38470df5da85a7f8c51c125a308e20bf31dee91811e6a3b73cb4d7937d1cc  8.02/lanhostconfigmgmSCPD.xml
36ea90acc52f7bccfe67c807cee5e58371f5470bfd9ebbceab93335320bb2841  8.02/tr64desc.xml (before neutralising)
85c824ee7e52dc0c6ed490af7fd27c8dc612476c1969034b6b1ad65fd7b24457  8.02/wlanconfigSCPD.xml
```

## What the descriptions do not say

SCPD files list actions, arguments, data types and allowed values, not fault codes. The
simulator answers with the error codes of the UPnP Device Architecture that TR-064 uses
(401 Invalid Action, 402 Invalid Args, 501 Action Failed, 600 Argument Value Invalid,
601 Argument Value Out of Range, 606 Action Not Authorized, 713 SpecifiedArrayIndexInvalid,
714 NoSuchEntryInArray, 820 Internal Error). Which code a box gives for which mistake is
not specified there and still needs confirmation on a real device (#21).
