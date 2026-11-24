"""Change tracking (component "change tracking", issue #39).

Every deployment is a :class:`ChangeRecord`: who, when, why, the desired-state version, the plan,
the vendor calls, the backups and the result per device. Records are never deleted; their
progress is written to an append-only event log (the audit trail).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from signalbox.adapters import VendorCall
from signalbox.changes import Plan


class ChangeStatus(StrEnum):
    PLANNED = "planned"  # waiting for approval
    APPROVED = "approved"  # may be deployed
    DEPLOYING = "deploying"
    APPLIED = "applied"  # every device changed, verified and confirmed
    ROLLED_BACK = "rolled-back"  # a device failed; every device is back where it was
    FAILED = "failed"  # a device failed and could not be rolled back completely: act now
    REJECTED = "rejected"  # not deployed


class DeviceStatus(StrEnum):
    PENDING = "pending"
    SKIPPED = "skipped"  # not reached because an earlier device failed
    BACKED_UP = "backed-up"
    APPLIED = "applied"
    CONFIRMED = "confirmed"
    FAILED = "failed"  # failed before anything was changed on it
    ROLLED_BACK = "rolled-back"
    ROLLBACK_FAILED = "rollback-failed"


class DeviceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    status: DeviceStatus = DeviceStatus.PENDING
    calls: list[VendorCall] = Field(default_factory=list)
    backup_id: str | None = None
    error: str | None = None
    #: Translation of ``error`` (#204): the stage that failed (``msg.deploy.stage.<stage>`` wraps
    #: the cause), the cause in English and, where it has one, its id and values.
    error_stage: str | None = None
    error_detail: str | None = None
    error_id: str | None = None
    error_params: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ChangeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    created_at: datetime
    author: str
    reason: str = Field(min_length=1)
    status: ChangeStatus = ChangeStatus.PLANNED
    plan: Plan
    desired_commit: str | None = None
    #: Override of blocking findings, with the reason the approver gave.
    override: str | None = None
    #: The approver allowed a plan that may cut Signalbox off from a device (#295).
    allow_lockout: bool = False
    devices: list[DeviceResult] = Field(default_factory=list)
    #: This record undoes another one.
    reverts: str | None = None
    #: Set on the original record when it was reverted.
    reverted_by: str | None = None
    #: Restoring a device backup instead of applying changes.
    restore_backup_id: str | None = None
    #: Change id -> name of the secret version (``<name>@<change id>``) holding the passphrase
    #: the change replaced; the inverse sets it again (#188). Names only, never values.
    passphrase_versions: dict[str, str] = Field(default_factory=dict)

    def result(self, device_id: str) -> DeviceResult:
        for r in self.devices:
            if r.device_id == device_id:
                return r
        raise KeyError(device_id)


class ChangeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int
    change_id: str
    at: datetime
    device_id: str | None
    event: str
    detail: str


class BackupInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    device_id: str
    change_id: str | None
    taken_at: datetime
    format: str
    size: int
