"""Tests for adapter base contract and safety invariants."""

import pytest
from pydantic import BaseModel

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    ExecutionContext,
    ExecutionResult,
    HealthResult,
)
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.store.artifacts import ArtifactStore


class DummyParams(BaseModel):
    profile: str = "default"


class ConcreteLiveAdapter(BaseAdapter):
    name = "dummy_live"
    status = AdapterStatus.LIVE
    params_model = DummyParams

    async def healthcheck(self) -> HealthResult:
        return HealthResult(status="healthy", message="Ready")

    async def run(self, step: PlanStep, ctx: ExecutionContext) -> ExecutionResult:
        return ExecutionResult(
            status="succeeded",
            stdout="sample output",
            stderr="",
            exit_code=0,
            duration_seconds=1.0,
        )

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        return []


class ConcreteImportAdapter(BaseAdapter):
    name = "dummy_import"
    status = AdapterStatus.IMPORT_ONLY
    params_model = DummyParams

    async def healthcheck(self) -> HealthResult:
        return HealthResult(status="healthy", message="File parser available")

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        return []


def test_base_adapter_cannot_be_instantiated_directly():
    """BaseAdapter is abstract and cannot be instantiated without implementations."""
    with pytest.raises(TypeError):
        BaseAdapter()  # type: ignore


def test_live_adapter_contract():
    """Live adapter properly implements healthcheck and run."""
    adapter = ConcreteLiveAdapter()
    assert adapter.name == "dummy_live"
    assert adapter.status == AdapterStatus.LIVE


def test_import_only_adapter_rejects_run_execution(tmp_path):
    """Safety rule: Import-only adapters must strictly reject live run() requests."""
    adapter = ConcreteImportAdapter()
    assert adapter.status == AdapterStatus.IMPORT_ONLY

    step = PlanStep(
        step_id="step-1",
        tool="nessus_import",
        action_class=ActionClass.IMPORT,
        target="10.0.0.1",
        rationale="Import scan",
        expected_outcome="Observations",
        nist_phase="discovery",
    )
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    ctx = ExecutionContext(artifact_store=store)

    coro = adapter.run(step, ctx)
    with pytest.raises(NotImplementedError, match="cannot be executed live"):
        coro.send(None)
