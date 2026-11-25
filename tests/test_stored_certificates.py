"""Certificates stored on devices (#330): MikroTik and OPNsense readers, no key material, rules."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, device
from signalbox import certificates
from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.model import (
    Certificate,
    CertificateUse,
    DeviceRole,
    KeyType,
    Network,
    Snapshot,
)
from signalbox.rules import Finding, Rule, RuleSettings, Severity, evaluate
from signalbox.rules.stored_certificates import RULES, ca_expiring, vpn_expiring
from signalbox.sightings import History
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import serve
from signalbox.testing import assert_contract, certificate_problems
from test_certificates import NOW, make_cert

PEM_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"

MT = MikrotikSimulator()
OPN = OpnsenseSimulator()


@pytest.fixture(scope="module")
def mt_url() -> Iterator[str]:
    with serve(MT.app()) as url:
        yield url


@pytest.fixture(scope="module")
def opn_url() -> Iterator[str]:
    with serve(OPN.app()) as url:
        yield url


@pytest.fixture(autouse=True)
def fresh() -> None:
    MT.__dict__.update(MikrotikSimulator().__dict__)
    OPN.__dict__.update(OpnsenseSimulator().__dict__)


def mikrotik(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    ctx = AdapterContext(
        site_id="home",
        device_id="rt",
        device_name="Router",
        role=DeviceRole.GATEWAY,
        config=config,
        timeout=5.0,
    )
    return MikrotikAdapter(ctx)


def opnsense(url: str) -> OpnsenseAdapter:
    config = OpnsenseConfig(
        url=url,
        api_key=SecretStr(KEY),
        api_secret=SecretStr(SECRET),
        allow_insecure_http=True,
    )
    ctx = AdapterContext(
        site_id="home",
        device_id="fw",
        device_name="Firewall",
        role=DeviceRole.GATEWAY,
        config=config,
        timeout=5.0,
    )
    return OpnsenseAdapter(ctx)


async def read(adapter: Any) -> Snapshot:
    try:
        return await assert_contract(adapter)
    finally:
        await adapter.close()


# --- MikroTik ----------------------------------------------------------------------------------


async def test_mikrotik_certificates(mt_url: str) -> None:
    snap = await read(mikrotik(mt_url))
    by = {c.name: c for c in snap.certificates}
    assert set(by) == {"signalbox-ca", "signalbox-www", "vpn-gateway"}
    ca, www, vpn = by["signalbox-ca"], by["signalbox-www"], by["vpn-gateway"]
    assert ca.id == "rt/cert/signalbox-ca" and ca.ca and ca.self_signed
    assert ca.trusted_on_device is True and ca.has_private_key is True
    assert (ca.key_type, ca.key_bits, ca.signature_algorithm) == (KeyType.RSA, 2048, "sha256")
    assert not www.ca and not www.self_signed and www.issuer == "CN=signalbox-ca"
    assert www.san == ["router.lab.example", "192.0.2.1"]
    assert www.used_by == ["rt/service/www-ssl"] and www.uses == [CertificateUse.MANAGEMENT]
    assert vpn.uses == [CertificateUse.VPN] and vpn.used_by == [] and vpn.key_bits == 3072
    assert vpn.not_after == datetime(2031, 1, 1, tzinfo=UTC)
    assert ca.fingerprint_sha256 == "a1" * 32


async def test_mikrotik_reads_no_key_material(mt_url: str) -> None:
    """Rows that carry key material (an export, a passphrase) leave none of it in the model."""
    for row in MT.data["/rest/certificate"]:
        row["private-key-data"] = PEM_KEY
        row["key-passphrase"] = "hunter2-secret"
        row["comment"] = PEM_KEY
    snap = await read(mikrotik(mt_url))
    dump = snap.model_dump_json()
    assert snap.certificates
    assert "PRIVATE KEY" not in dump and "hunter2" not in dump and "MIIEvQ" not in dump
    assert all(c.vendor_extra == {} for c in snap.certificates)
    assert {p for p in MT.requests if "certificate" in p or "export" in p} == {"/rest/certificate"}


async def test_mikrotik_without_the_menu_or_with_odd_rows(mt_url: str) -> None:
    del MT.data["/rest/certificate"]
    assert (await read(mikrotik(mt_url))).certificates == []
    MT.data["/rest/certificate"] = [
        {"name": "request", "common-name": "x"},  # not signed yet: no validity
        {"invalid-after": "2031-01-01T00:00:00"},  # no name
        {
            "name": "cli-dates",
            "invalid-after": "jan/01/2031 00:00:00",
            "key-type": "ec",
            "key-size": "prime256v1",
            "akid": "aa",
            "skid": "aa",
            "common-name": "e",
        },
    ]
    snap = await read(mikrotik(mt_url))
    (cert,) = snap.certificates
    assert (cert.key_type, cert.key_bits, cert.self_signed) == (KeyType.EC, 256, True)
    assert cert.issuer == cert.subject == "CN=e"
    assert cert.not_before == cert.not_after == datetime(2031, 1, 1, tzinfo=UTC)


async def test_mikrotik_refused_menu_is_not_read(mt_url: str) -> None:
    MT.fail["/rest/certificate"] = 403
    snap = await read(mikrotik(mt_url))
    assert snap.certificates == []


# --- OPNsense ----------------------------------------------------------------------------------


async def test_opnsense_certificates(opn_url: str) -> None:
    snap = await read(opnsense(opn_url))
    by = {c.name: c for c in snap.certificates}
    assert set(by) == {"Lab CA", "Web GUI", "VPN server"}
    ca, web, vpn = by["Lab CA"], by["Web GUI"], by["VPN server"]
    assert ca.ca and ca.self_signed and ca.subject == "CN=lab-ca"
    assert not web.ca and web.issuer == "CN=lab-ca" and not web.self_signed
    assert web.in_use is True and vpn.in_use is False
    assert web.san == ["opnsense.lab.example"]
    assert web.not_after == datetime(2031, 1, 1, tzinfo=UTC)
    assert not any("/get/" in p or "export" in p for p in OPN.requests if "trust" in p)


async def test_opnsense_drops_key_material_and_reads_the_pem(opn_url: str) -> None:
    der = make_cert(cn="vpn.lab.example", end=NOW + timedelta(days=400))
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode()
    row = OPN.data["/api/trust/cert/search"]["rows"][1]
    row["crt_payload"] = pem + PEM_KEY  # a PEM bundle that also holds a private key
    row["prv_payload"] = PEM_KEY
    row["prv"] = PEM_KEY
    row["csr_payload"] = (
        "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----"
    )
    snap = await read(opnsense(opn_url))
    dump = snap.model_dump_json()
    assert "PRIVATE KEY" not in dump and "CERTIFICATE REQUEST" not in dump
    assert "BEGIN CERTIFICATE" not in dump and "MIIEvQ" not in dump
    cert = next(c for c in snap.certificates if c.name == "VPN server")
    assert cert.key_type is KeyType.EC and cert.key_bits == 256
    assert len(cert.fingerprint_sha256) == 64 and cert.vendor_extra == {}


async def test_opnsense_missing_and_refused_grids(opn_url: str) -> None:
    del OPN.data["/api/trust/ca/search"]
    snap = await read(opnsense(opn_url))
    assert {c.name for c in snap.certificates} == {"Web GUI", "VPN server"}
    # without the authority grid the issuer is unknown but the certificate is still there
    assert all(c.issuer == "" for c in snap.certificates)
    OPN.fail["/api/trust/cert/search"] = 403
    adapter = opnsense(opn_url)
    try:
        snap = await adapter.observe()  # not the contract check: the gap is a read error
    finally:
        await adapter.close()
    assert snap.certificates == []
    gap = next(e for e in snap.errors if "page-system-certmanager" in (e.fix or ""))
    assert gap.optional and gap.remedy == "privileges"


async def test_opnsense_duplicate_descriptions_and_bad_rows(opn_url: str) -> None:
    rows = OPN.data["/api/trust/cert/search"]["rows"]
    rows.append({**rows[0], "uuid": "u-3", "refid": "r3"})  # same description
    rows.append({"uuid": "u-4", "descr": "no dates"})
    rows.append({"uuid": "u-5", "valid_to": "1924992000"})  # no name at all
    snap = await read(opnsense(opn_url))
    names = sorted(c.name for c in snap.certificates)
    assert names == ["Lab CA", "VPN server", "Web GUI", "Web GUI-r3"]


def test_describe_pem_ignores_everything_but_the_certificate() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = make_cert(cn="x")
    pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode()
    parsed = certificates.describe_pem(PEM_KEY + "\n" + pem)
    assert parsed is not None and parsed[0].subject == "CN=x" and parsed[1] is False
    assert certificates.describe_pem(PEM_KEY) is None
    assert (
        certificates.describe_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
        is None
    )


# --- contract helper -----------------------------------------------------------------------


def cert(name: str, days: float, **kw: Any) -> Certificate:
    end = NOW + timedelta(days=days)
    values: dict[str, Any] = {
        "id": f"gw/cert/{name}",
        "device_id": "gw",
        "name": name,
        "fingerprint_sha256": "ab" * 32,
        "subject": f"CN={name}",
        "issuer": "CN=ca",
        "self_signed": False,
        "not_before": NOW - timedelta(days=10),
        "not_after": end,
        "key_type": KeyType.RSA,
        "key_bits": 2048,
        "signature_algorithm": "sha256",
    }
    return Certificate(**(values | kw))


def test_certificate_problems() -> None:
    from factories import snapshot

    ok = cert("a", 100, used_by=["gw/service/www-ssl"])
    snap = snapshot(device("gw")).model_copy(update={"certificates": [ok, ok]})
    problems = certificate_problems(snap)
    assert any("twice" in p for p in problems)
    assert any("unknown service gw/service/www-ssl" in p for p in problems)
    bad = cert("b", 100, id="gw/other/b", vendor_extra={"x": PEM_KEY})
    assert any(
        "is not gw/cert/" in p
        for p in certificate_problems(snap.model_copy(update={"certificates": [bad]}))
    )
    assert any(
        "key material" in p
        for p in certificate_problems(
            snap.model_copy(update={"certificates": [cert("k", 5, subject=PEM_KEY)]})
        )
    )


# --- rules -------------------------------------------------------------------------------------


def net_of(*certs: Certificate, **kw: Any) -> Network:
    return Network(
        sites=[SITE], devices=[device("gw", name="Gateway")], certificates=list(certs), **kw
    )


def run(
    rule_: Rule,
    n: Network,
    history: History | None = None,
    settings: dict[str, RuleSettings] | None = None,
) -> list[Finding]:
    h = history or History(now=NOW, since=NOW, observations=1)
    return [f for f in evaluate(n, [rule_], settings, h) if f.rule_id == rule_.id]


def vpn(days: float, **kw: Any) -> Certificate:
    return cert("vpn", days, uses=[CertificateUse.VPN], **kw)


def test_registered() -> None:
    assert {r.id for r in RULES} == {"cert.vpn-expiring", "cert.ca-expiring"}


def test_network_knows_certificates() -> None:
    n = net_of(cert("a", 5))
    assert n.knows("gw/cert/a") and n.certificates_of("gw")[0].name == "a"
    assert n.certificates_of("other") == []


def test_vpn_certificate_thresholds() -> None:
    assert run(vpn_expiring, net_of(vpn(100))) == []
    (warn,) = run(vpn_expiring, net_of(vpn(20)))
    assert warn.severity is Severity.WARNING and warn.message_id == "certificate.vpnExpiring"
    assert warn.params["days"] == 19 or warn.params["days"] == 20
    assert warn.objects == ["gw/cert/vpn", "gw"]
    (urgent,) = run(vpn_expiring, net_of(vpn(3)))
    assert urgent.severity is Severity.ERROR
    (gone,) = run(vpn_expiring, net_of(vpn(-2)))
    assert gone.severity is Severity.ERROR and gone.message_id == "certificate.vpnExpired"
    assert gone.params == {"device": "Gateway", "name": "vpn", "date": gone.params["date"]}


def test_vpn_thresholds_are_the_configured_ones() -> None:
    settings = {"cert.vpn-expiring": RuleSettings(params={"warn_days": 60, "urgent_days": 45})}
    (f,) = run(vpn_expiring, net_of(vpn(40)), settings=settings)
    assert f.severity is Severity.ERROR
    # the CA rule has its own parameters
    assert run(ca_expiring, net_of(vpn(40, ca=True)), settings=settings) == []


def test_vpn_rule_only_looks_at_vpn_certificates_and_needs_a_clock() -> None:
    web = cert("web", 3, uses=[CertificateUse.MANAGEMENT])
    unknown = cert("x", 3)
    authority = cert("ca", 3, ca=True, uses=[CertificateUse.VPN])
    assert run(vpn_expiring, net_of(web, unknown, authority)) == []
    assert run(vpn_expiring, net_of(vpn(3)), History(now=None, since=None, observations=0)) == []


def test_ca_expiring_counts_what_it_issued() -> None:
    ca = cert("ca", 20, ca=True, self_signed=True, subject="CN=ca", issuer="CN=ca")
    leaf1 = cert("a", 900)
    leaf2 = cert("b", 900, issuer="CN=ca,O=Lab")  # the device writes the issuer longer
    other = cert("c", 900, issuer="CN=other")
    (f,) = run(ca_expiring, net_of(ca, leaf1, leaf2, other))
    assert f.severity is Severity.WARNING and f.message_id == "certificate.caExpiring"
    assert f.params["issued"] == 2 and f.objects == ["gw/cert/ca", "gw"]
    assert "2 " in f.message or ": 2" in f.message or "2)" in f.message


def test_ca_expired_and_quiet_cases() -> None:
    ca = cert("ca", -1, ca=True, self_signed=True, subject="CN=ca", issuer="CN=ca")
    (f,) = run(ca_expiring, net_of(ca))
    assert f.severity is Severity.ERROR and f.message_id == "certificate.caExpired"
    assert run(ca_expiring, net_of(cert("ca", 400, ca=True))) == []
    assert run(ca_expiring, net_of(cert("leaf", 3))) == []
