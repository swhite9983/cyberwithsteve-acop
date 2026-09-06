"""Input and output models for the catalog.

Every model sets ``extra="forbid"``. That is not tidiness - it is import rule
12, and it is what makes an injected field such as ``api_key`` a **rejection**
rather than something merely redacted downstream. A model that silently drops
unknown keys would let a prompt-injected payload reach the framework, be
stripped, and leave no trace that anything was attempted.

Notice what no input model here contains: no host, no address, no URL, no
command, no credential. Import rules 9, 10 and 11 refuse those field names at
startup, so the absence is enforced rather than merely observed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_FORBID = ConfigDict(extra="forbid")


class EmptyInput(BaseModel):
    """No parameters. Used by tools that ask ACOP about itself."""

    model_config = _FORBID


# ---------------------------------------------------------------------------
# acop.system.health
# ---------------------------------------------------------------------------


class ComponentSummary(BaseModel):
    model_config = _FORBID

    name: str
    status: str
    latency_ms: float | None = None


class HealthSummaryOut(BaseModel):
    model_config = _FORBID

    status: str
    environment: str
    checked_at: datetime
    components: list[ComponentSummary]


# ---------------------------------------------------------------------------
# acop.test.echo_metadata
# ---------------------------------------------------------------------------


class EchoIn(BaseModel):
    model_config = _FORBID

    note: str = Field(min_length=1, max_length=200)


class EchoOut(BaseModel):
    model_config = _FORBID

    note: str
    tool_name: str
    tool_version: str
    invocation_id: str
    observed_at: datetime


# ---------------------------------------------------------------------------
# test.device.status
# ---------------------------------------------------------------------------


class FactSummary(BaseModel):
    """A predicate and how far it is trusted. Deliberately no value.

    A fact value can be anything a collector saw, including a configuration
    line. Naming what is known is a different disclosure from returning it, and
    the CMDB API is where values are read under their own authorization.
    """

    model_config = _FORBID

    predicate: str
    verification_status: str


class DeviceStatusIn(BaseModel):
    model_config = _FORBID

    include_facts: bool = False


class DeviceStatusOut(BaseModel):
    model_config = _FORBID

    asset_id: str
    display_name: str
    asset_type: str
    reachable: bool
    facts: list[FactSummary] | None = None
    observed_at: datetime


# ---------------------------------------------------------------------------
# test.service.restart
# ---------------------------------------------------------------------------


class ServiceRestartIn(BaseModel):
    model_config = _FORBID

    graceful: bool = True
    drain_seconds: int = Field(default=0, ge=0, le=30)


class ServiceRestartOut(BaseModel):
    model_config = _FORBID

    asset_id: str
    restart_initiated: bool
    previous_state: str
    simulated_pid: int
    initiated_at: datetime


# ---------------------------------------------------------------------------
# test.security.rotate_key
# ---------------------------------------------------------------------------


class RotateKeyIn(BaseModel):
    model_config = _FORBID

    key_slot: Literal["primary", "secondary"]


class RotateKeyOut(BaseModel):
    """The result of a rotation.

    ``key_identifier`` is an **opaque handle**, not key material and not
    derived from any. There is no field on this model that could carry a
    secret, which is a stronger guarantee than a sanitizer that removes one.
    """

    model_config = _FORBID

    asset_id: str
    key_slot: str
    key_identifier: str
    rotated_at: datetime


# ---------------------------------------------------------------------------
# test.prohibited.shell_exec
# ---------------------------------------------------------------------------


class ProhibitedIn(BaseModel):
    """Input for the tool that must never run.

    ``intent`` is prose describing what someone wanted, not a command. The
    distinction is load-bearing: a field named ``command`` would be refused by
    import rule 11 and this tool could not be declared at all, so there would
    be nothing to prove the prohibition mechanism against.
    """

    model_config = _FORBID

    intent: str = Field(min_length=1, max_length=200)


class NeverOut(BaseModel):
    """The output of a tool that never produces output."""

    model_config = _FORBID


__all__ = [
    "ComponentSummary",
    "DeviceStatusIn",
    "DeviceStatusOut",
    "EchoIn",
    "EchoOut",
    "EmptyInput",
    "FactSummary",
    "HealthSummaryOut",
    "NeverOut",
    "ProhibitedIn",
    "RotateKeyIn",
    "RotateKeyOut",
    "ServiceRestartIn",
    "ServiceRestartOut",
]
