"""Device TLS certificates (#174) and their checks (#121): reading, the card data, the rules.

Every certificate is generated here at run time; no key or certificate is stored as a file.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from factories import SITE, device
from signalbox import certificates
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    Capability,
    Manifest,
    SystemInfo,
    UntrustedCertificate,
)
from signalbox.adapters.https import fingerprint
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.config import Config
from signalbox.model import CertificateInfo, DeviceRole, DeviceStatus, KeyType, Network
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.certificate_checks import RULES, certificate_expiry, renewed, weak_key
from signalbox.runner import Runner
from signalbox.secrets import load_vault
from signalbox.sightings import History
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.store import DeviceRecord, Store

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
SHA256 = hashes.SHA256()


def make_cert(
    *,
    key: Any = None,
    hash_: hashes.HashAlgorithm | None = SHA256,
    start: datetime = NOW - timedelta(days=100),
    end: datetime = NOW + timedelta(days=300),
    san: list[x509.GeneralName] | None = None,
    cn: str = "router",
    issuer_cn: str | None = None,
    sha1: bool = False,
) -> bytes:
    if key is None:
        key = (
            rsa.generate_private_key(65537, 2048)
            if sha1
            else ec.generate_private_key(ec.SECP256R1())
        )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    der = builder.sign(key, hash_).public_bytes(serialization.Encoding.DER)
    if sha1:  # current OpenSSL cannot sign with SHA-1: relabel sha256WithRSA as sha1WithRSA
        sha256_rsa = bytes.fromhex("2a864886f70d01010b")
        sha1_rsa = bytes.fromhex("2a864886f70d010105")
        assert sha256_rsa in der
        der = der.replace(sha256_rsa, sha1_rsa)
    return der


def ipsan(text: str) -> x509.GeneralName:
    return x509.IPAddress(ipaddress.ip_address(text))


# --- reading ---------------------------------------------------------------------------------


def test_describe_ec_with_ip_san() -> None:
    der = make_cert(san=[ipsan("192.0.2.1"), x509.DNSName("router.example")])
    info = certificates.describe(der, "192.0.2.1")
    assert info.fingerprint_sha256 == fingerprint(der)
    assert info.key_type is KeyType.EC and info.key_bits == 256
    assert info.self_signed and info.subject == "CN=router"
    assert info.san == ["router.example", "192.0.2.1"]
    assert info.matches_management_address is True
    assert info.not_after == NOW + timedelta(days=300)
    assert "sha256" in info.signature_algorithm.lower()


def test_describe_address_mismatch_and_unknown() -> None:
    der = make_cert(san=[ipsan("192.0.2.1")])
    assert certificates.describe(der, "192.0.2.9").matches_management_address is False
    assert certificates.describe(der, None).matches_management_address is None


def test_describe_dns_names_wildcard_and_common_name() -> None:
    wild = make_cert(san=[x509.DNSName("*.lan.example")])
    assert certificates.describe(wild, "gw.lan.example").matches_management_address is True
    assert certificates.describe(wild, "a.b.lan.example").matches_management_address is False
    assert certificates.describe(wild, "192.0.2.1").matches_management_address is False
    only_cn = make_cert(cn="gw.example")  # no SAN: the common name counts
    assert certificates.describe(only_cn, "GW.example").matches_management_address is True


def test_describe_rsa_1024_sha1_and_issuer() -> None:
    der = make_cert(
        key=rsa.generate_private_key(65537, 1024),
        sha1=True,
        issuer_cn="Example CA",
    )
    info = certificates.describe(der, None)
    assert info.key_type is KeyType.RSA and info.key_bits == 1024
    assert not info.self_signed and info.issuer == "CN=Example CA"
    assert certificates.weak_signature(info.signature_algorithm)


def test_describe_ed25519() -> None:
    info = certificates.describe(
        make_cert(key=ed25519.Ed25519PrivateKey.generate(), hash_=None), None
    )
    assert info.key_type is KeyType.ED25519 and info.key_bits == 256
    assert not certificates.weak_signature(info.signature_algorithm)


def test_collecting_keeps_the_first_certificate_per_endpoint() -> None:
    certificates.report("192.0.2.1", 443, b"ignored")  # outside a block: nothing happens
    with certificates.collecting() as seen:
        certificates.report("192.0.2.1", 443, b"a")
        certificates.report("192.0.2.1", 443, b"b")
        certificates.report("192.0.2.1", 8443, b"c")
    assert seen == {("192.0.2.1", 443): b"a", ("192.0.2.1", 8443): b"c"}


# --- through the adapter base and a real TLS handshake ----------------------------------------

SIM = MikrotikSimulator()


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


async def read_over_tls(tls: TlsFiles, pin: str | None) -> Any:
    with serve(SIM.app(), tls=tls) as url:
        config = MikrotikConfig(url=url, password=SecretStr(PASSWORD))
        a = MikrotikAdapter(
            AdapterContext(
                site_id="home",
                device_id="rt",
                device_name="Router",
                role=DeviceRole.GATEWAY,
                config=config,
                pinned_fingerprint=pin,
                timeout=5.0,
            )
        )
        try:
            return await a.observe()
        finally:
            await a.close()


async def test_https_adapter_fills_the_certificate(tls: TlsFiles) -> None:
    snap = await read_over_tls(tls, tls.fingerprint)
    cert = snap.device.certificate
    assert snap.status is DeviceStatus.OK
    assert cert is not None and cert.trusted
    assert cert.fingerprint_sha256 == tls.fingerprint
    assert cert.matches_management_address is True  # the simulator's certificate names 127.0.0.1


async def test_untrusted_certificate_is_described_but_not_trusted(tls: TlsFiles) -> None:
    snap = await read_over_tls(tls, None)
    assert snap.status is DeviceStatus.UNTRUSTED
    assert snap.device.certificate is not None and not snap.device.certificate.trusted


# --- inventory: pinned_since and the previous certificate -------------------------------------


class Cfg(AdapterConfig):
    url: str


CERTS: dict[str, bytes] = {}


class Fake(Adapter):
    """Presents the certificate named by its url, like DeviceHttp does after its probe."""

    manifest = Manifest(
        id="fake",
        name="Fake",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.INTERFACES}),
        config=Cfg,
    )

    async def read_system(self) -> SystemInfo:
        cfg = self.context.config
        assert isinstance(cfg, Cfg)
        der = CERTS[cfg.url]
        certificates.report("192.0.2.1", 443, der)
        fp = fingerprint(der)
        if self.context.pinned_fingerprint != fp:
            raise UntrustedCertificate(fp, self.context.pinned_fingerprint)
        return SystemInfo(vendor="Example", management_address="192.0.2.1")

    async def read_interfaces(self) -> Any:
        from signalbox.adapters import Observation

        return Observation()


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def put(store: Store, url: str, pin: str | None = None) -> DeviceRecord:
    rec = DeviceRecord(
        id="gw",
        site_id="home",
        name="Gateway",
        role=DeviceRole.GATEWAY,
        adapter="fake",
        pinned_fingerprint=pin,
    )
    store.put_device(rec, {"url": url}, Cfg)
    stored = store.device("gw")
    assert stored is not None
    return stored


async def test_pinned_since_and_renewal_flow(store: Store) -> None:
    old = make_cert(end=NOW + timedelta(days=5))
    new = make_cert(end=NOW + timedelta(days=700))
    CERTS["old"], CERTS["new"] = old, new
    run = Runner(store=store, adapters={"fake": Fake}, rules=[], config=Config())

    rec = put(store, "old", fingerprint(old))
    assert rec.pinned_since is not None
    snap = await run.observe_device(rec)
    cert = snap.device.certificate
    assert cert is not None and cert.trusted and cert.pinned_since == rec.pinned_since

    # the device regenerates its certificate: not trusted, and the old one is remembered
    store.put_device(rec, {"url": "new"}, Cfg)
    rec = store.device("gw")  # type: ignore[assignment]
    for _ in range(2):  # a second failed observation keeps the memory
        snap = await run.observe_device(rec)
        cert = snap.device.certificate
        assert snap.status is DeviceStatus.UNTRUSTED
        assert cert is not None and not cert.trusted
        assert cert.previous_fingerprint_sha256 == fingerprint(old)
        assert cert.previous_not_after == NOW + timedelta(days=5)
    assert any(f.rule_id == "cert.renewed" for f in evaluate(run.network(), RULES))

    # the user trusts the new one: the memory is gone, pinned_since is new
    store.set_pending_fingerprint("gw", fingerprint(new))
    store.trust_fingerprint("gw", fingerprint(new))
    rec = store.device("gw")  # type: ignore[assignment]
    snap = await run.observe_device(rec)
    cert = snap.device.certificate
    assert cert is not None and cert.trusted and cert.previous_fingerprint_sha256 is None
    assert cert.pinned_since is not None and cert.pinned_since >= (rec.pinned_since or NOW)


async def test_first_certificate_is_not_a_renewal(store: Store) -> None:
    CERTS["first"] = make_cert()
    run = Runner(store=store, adapters={"fake": Fake}, rules=[], config=Config())
    snap = await run.observe_device(put(store, "first"))
    cert = snap.device.certificate
    assert snap.status is DeviceStatus.UNTRUSTED
    assert cert is not None and cert.previous_fingerprint_sha256 is None


def test_thresholds_reach_the_network(store: Store) -> None:
    from signalbox.config import CertificatesConfig

    cfg = Config(certificates=CertificatesConfig(warn_days=60, urgent_days=14))
    net = Runner(store=store, adapters={}, rules=[], config=cfg).network()
    assert (net.certificate_warn_days, net.certificate_urgent_days) == (60, 14)


# --- rules -----------------------------------------------------------------------------------


def info(**kw: Any) -> CertificateInfo:
    der = kw.pop("der", None) or make_cert()
    base = certificates.describe(der, "192.0.2.1")
    return base.model_copy(update=kw)


def net_of(cert: CertificateInfo | None, **kw: Any) -> Network:
    return Network(sites=[SITE], devices=[device("gw", name="Gateway", certificate=cert)], **kw)


def run(rule_: Rule, n: Network, history: History | None = None) -> list[Finding]:
    h = history or History(now=NOW, since=NOW, observations=1)
    return [f for f in evaluate(n, [rule_], None, h) if f.rule_id == rule_.id]


def expiry(days: float, **kw: Any) -> list[Finding]:
    end = NOW + timedelta(days=days)
    return run(certificate_expiry, net_of(info(der=make_cert(end=end)), **kw))


def test_registered() -> None:
    assert {r.id for r in RULES} == {"security.certificate-expiry", "cert.weak-key", "cert.renewed"}


def test_expired_is_an_error() -> None:
    (f,) = expiry(-2)
    assert f.severity is Severity.ERROR
    assert f.message_id == "certificate.expired" and f.params["device"] == "Gateway"
    assert f.fix is not None and "Renew" in f.fix


def test_expiring_soon_is_a_warning_then_an_error() -> None:
    (f,) = expiry(20.5)
    assert f.severity is Severity.WARNING and f.params["days"] == 20
    assert f.message_id == "certificate.expiring"
    (f,) = expiry(3)
    assert f.severity is Severity.ERROR


def test_far_from_expiry_is_quiet() -> None:
    assert expiry(200) == []


def test_thresholds_are_configurable() -> None:
    assert expiry(40) == []
    (f,) = expiry(40, certificate_warn_days=60)
    assert f.severity is Severity.WARNING
    (f,) = expiry(10, certificate_urgent_days=14)
    assert f.severity is Severity.ERROR


def test_expiry_quiet_without_certificate_clock_or_trust() -> None:
    assert run(certificate_expiry, net_of(None)) == []
    soon = info(der=make_cert(end=NOW + timedelta(days=2)))
    assert run(certificate_expiry, net_of(soon), History.empty()) == []
    assert run(certificate_expiry, net_of(soon.model_copy(update={"trusted": False}))) == []


def test_weak_rsa_key() -> None:
    weak = info(der=make_cert(key=rsa.generate_private_key(65537, 1024)))
    (f,) = run(weak_key, net_of(weak))
    assert f.message_id == "certificate.weakKey" and f.params["bits"] == 1024
    strong = info(key_type=KeyType.RSA, key_bits=2048)
    assert run(weak_key, net_of(strong)) == []


def test_sha1_signature() -> None:
    sha1 = info(der=make_cert(sha1=True))
    (f,) = run(weak_key, net_of(sha1))
    assert f.message_id == "certificate.weakSignature"


def test_weak_key_and_signature_are_two_findings() -> None:
    both = info(der=make_cert(key=rsa.generate_private_key(65537, 1024), sha1=True))
    assert len(run(weak_key, net_of(both))) == 2


def test_ec_and_ed25519_are_not_weak() -> None:
    assert run(weak_key, net_of(info())) == []
    assert (
        run(
            weak_key,
            net_of(info(der=make_cert(key=ed25519.Ed25519PrivateKey.generate(), hash_=None))),
        )
        == []
    )
    assert run(weak_key, net_of(None)) == []


def test_renewed_explains_the_new_certificate() -> None:
    new = info(
        trusted=False,
        previous_fingerprint_sha256="ab" * 32,
        previous_not_after=datetime(2026, 5, 30, tzinfo=UTC),
    )
    (f,) = run(renewed, net_of(new))
    assert f.severity is Severity.INFO and f.message_id == "certificate.renewed"
    assert f.params["old"] == "2026-05-30" and f.params["new"] == new.not_after.strftime("%Y-%m-%d")


def test_renewed_quiet_for_trusted_first_or_missing() -> None:
    assert run(renewed, net_of(info())) == []
    assert run(renewed, net_of(info(trusted=False))) == []
    assert run(renewed, net_of(None)) == []
