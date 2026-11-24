"""Refusals of the logging and SNMP writers (#327), shared by the integrations.

The English text is the catalogue entry ``msg.<id>`` of ``web/static/i18n/en.json`` with its
placeholders filled in (a test compares them).
"""

from __future__ import annotations

from signalbox.adapters import AdapterError


def foreign_target(address: str) -> AdapterError:
    return AdapterError(
        f"The router already sends syslog to {address}, which Signalbox did not set up. "
        "List the address under adopt in the desired state to replace it.",
        message_id="log.foreignTarget",
        params={"address": address},
    )


def one_target(count: int) -> AdapterError:
    return AdapterError(
        f"This router stores one remote syslog target; {count} are declared. Declare one.",
        message_id="log.oneTarget",
        params={"count": count},
    )


def transport(name: str) -> AdapterError:
    return AdapterError(
        f"Remote syslog over {name} cannot be written (use udp or tcp).",
        message_id="log.transport",
        params={"transport": name},
    )


def no_agent(config: str) -> AdapterError:
    return AdapterError(
        f"The router has no {config} configuration to change (the snmpd package is not "
        "installed, or the login may not use it).",
        message_id="snmp.noAgent",
        params={"config": config},
    )


def v3_only() -> AdapterError:
    return AdapterError(
        "Signalbox does not create SNMPv3 users (that needs secrets), so it cannot write "
        "v3-only. Set up SNMPv3 on the device, or declare snmp: off.",
        message_id="snmp.v3Only",
    )
