"""A Signalbox installation with one real device, for deployment round trips (#136).

    lab = Lab(tmp_path, OpenWrtAdapter, record, values, secrets={"psk": "..."})
    rec = await lab.deploy(DESIRED_YAML)           # plan -> prepare -> approve -> deploy
    assert rec.status is ChangeStatus.APPLIED
    back = await lab.revert(rec)                   # the inverse plan, deployed the same way

Everything goes through the same code as the web interface: :class:`signalbox.deploy.Deployer`
with backup, apply, verification by reading the device again, confirm or restore.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from signalbox.adapters import Adapter, AdapterConfig
from signalbox.changes import Plan, plan
from signalbox.deploy import Deployer
from signalbox.desired import parse
from signalbox.history import ChangeRecord
from signalbox.model import Network, Site
from signalbox.rules.builtin import RULES
from signalbox.service import Services, build
from signalbox.store import DeviceRecord

ENV = {"SIGNALBOX_AUTH_PASSWORD": "integration-test", "SIGNALBOX_DEPLOY_ENABLED": "true"}
OVERRIDE = "integration test against a lab device"


class Lab:
    def __init__(
        self,
        data: Path,
        adapter: type[Adapter],
        record: DeviceRecord,
        values: dict[str, Any],
        config: type[AdapterConfig],
        *,
        site: Site | None = None,
        secrets: dict[str, str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.services: Services = build(
            data,
            env={**ENV, **(env or {})},
            adapters={record.adapter: adapter},
            rules=RULES,
            link_sources=[],
        )
        store = self.services.store
        store.put_site(site or Site(id=record.site_id, name=record.site_id))
        store.put_device(record, values, config)
        for name, value in (secrets or {}).items():
            store.set_secret(name, value)
        self.deployer = Deployer(self.services.runner)

    def close(self) -> None:
        self.services.close()

    async def observe(self) -> Network:
        await self.services.runner.observe_all()
        return self.services.runner.network()

    async def plan(self, desired: str) -> Plan:
        net = await self.observe()
        return plan(parse(desired), net, RULES, secret=self.services.store.get_secret)

    async def run(self, rec: ChangeRecord) -> ChangeRecord:
        override = OVERRIDE if rec.plan.blocking else None
        self.deployer.approve(rec.id, "integration", override=override)
        return await self.deployer.deploy(rec.id)

    async def deploy(self, desired: str, reason: str = "integration test") -> ChangeRecord:
        p = await self.plan(desired)
        assert p.changes, "the desired state plans no change"
        return await self.run(await self.deployer.prepare(p, reason, "integration"))

    async def revert(self, rec: ChangeRecord) -> ChangeRecord:
        await self.observe()
        back = await self.deployer.revert(rec.id, "integration test: undo", "integration")
        return await self.run(back)
