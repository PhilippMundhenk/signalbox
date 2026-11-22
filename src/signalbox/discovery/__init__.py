"""Device discovery (#203): find devices of the installed integrations, so the user only
enters the login.

Started by the user only ("Find devices" on the devices page, ``POST /api/discovery``), never in
the background, and can be turned off in the configuration (``discovery.enabled``). It looks
where Signalbox already knows the network, or where the user points it:

- addresses in :mod:`signalbox.discovery.targets`: gateway subnets of added routers (small ones
  completely), their clients, DHCP leases and LLDP neighbours, and ranges the user types;
- probes owned by the integrations (:meth:`signalbox.adapters.Adapter.discover` per address,
  :meth:`~signalbox.adapters.Adapter.discover_broadcast` for broadcast protocols), which only
  use the helpers in :mod:`signalbox.discovery.probe`;
- the run itself in :mod:`signalbox.discovery.engine`.

This module only exports the types an integration needs; it does not import the engine, so
adapters can import it without a cycle. What is sent is listed in docs/DISCOVERY.md.
"""

from signalbox.discovery.probe import (
    MAX_BYTES,
    BroadcastResult,
    Candidate,
    HostProbe,
    NetworkProbe,
    ProbeResponse,
    RateLimiter,
    clean,
)

__all__ = [
    "MAX_BYTES",
    "BroadcastResult",
    "Candidate",
    "HostProbe",
    "NetworkProbe",
    "ProbeResponse",
    "RateLimiter",
    "clean",
]
