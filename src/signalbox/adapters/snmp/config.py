"""The settings of the generic SNMP adapter."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import AdapterConfig


class SnmpConfig(AdapterConfig):
    address: str = Field(
        description="Address of the switch, for example 192.0.2.10 (an IPv6 address works too)",
        examples=["192.0.2.10"],
    )
    port: int = Field(
        default=161,
        ge=1,
        le=65535,
        description="UDP port of the SNMP agent",
        json_schema_extra={"advanced": True},
    )
    version: Literal["v3", "v2c"] = Field(
        default="v3",
        description="SNMP version. v3 with authentication and encryption (authPriv) is "
        "recommended; v2c sends its community in clear text (see the setup guide)",
    )
    community: SecretStr | None = Field(
        default=None,
        description="v2c only: the read-only community string. Never a read-write community: "
        "Signalbox only reads",
    )
    username: str | None = Field(default=None, description="v3 only: the SNMPv3 user name")
    auth_protocol: Literal["sha256", "sha"] = Field(
        default="sha256",
        description="v3 only: authentication algorithm of the user: sha256 (HMAC-SHA-256, "
        "preferred) or sha (HMAC-SHA-1, older switches)",
    )
    auth_password: SecretStr | None = Field(
        default=None, description="v3 only: the authentication password of the user (8 or more)"
    )
    priv_password: SecretStr | None = Field(
        default=None,
        description="v3 only: the privacy (encryption, AES-128) password of the user (8 or more)",
    )

    context_name: str = Field(
        default="",
        description="v3 only: the SNMP context name; almost every switch uses the empty one",
        json_schema_extra={"advanced": True},
    )

    @field_validator("address")
    @classmethod
    def _host(cls, value: str) -> str:
        host = value.strip()
        if not host or any(c in host for c in "/ @?#") or host.startswith("-"):
            raise ValueError("enter the switch's address, for example 192.0.2.10")
        return host

    @model_validator(mode="after")
    def _credentials(self) -> SnmpConfig:
        if self.version == "v2c":
            if self.community is None or not self.community.get_secret_value():
                raise ValueError("SNMP v2c needs the read-only community string")
            return self
        if not (self.username or "").strip():
            raise ValueError("SNMP v3 needs the user name")
        for name in ("auth_password", "priv_password"):
            secret = getattr(self, name)
            if secret is None or len(secret.get_secret_value()) < 8:
                raise ValueError(
                    "SNMP v3 authPriv needs the authentication and the privacy password "
                    "(8 characters or more each)"
                )
        return self
