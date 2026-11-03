"""Tests for Failure and Chaos Modes (Task A14, Master Plan §7 Day 6).

Invariants:
- Chaos switches: kill ZAP mid-scan, slow Nmap (timeout), malformed XML, LLM down, NVD down.
- Tool failures/timeouts never crash the assessment; step is recorded as failed/timed_out.
- Malformed XML is handled safely by defusedxml without crashing; noted in limitations.
- LLM down triggers the deterministic rule-based planner with a visible banner.
- NVD down triggers offline fallback or un-enriched monotonic scoring without crashing.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.enrichment.service import EnrichmentService
from cipher_lens.models.assessment import Assessment, AssessmentStatus
from cipher_lens.models.findings import Evidence
from cipher_lens.orchestrator.chaos import ChaosManager
from cipher_lens.planner.models import StateSummary
from cipher_lens.planner.planner import AdaptivePlanner
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.db import connect, init_db
from cipher_lens.store.repository import AssessmentRepository


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(tmp_path / "chaos_test.db")
    init_db(conn)
    return conn


@pytest.fixture
def repo(db_conn: sqlite3.Connection) -> AssessmentRepository:
    return AssessmentRepository(db_conn)


@pytest.fixture
def chaos_manager() -> ChaosManager:
    return ChaosManager()


@pytest.fixture
def sample_assessment(repo: AssessmentRepository) -> Assessment:
    assm = Assessment(
        id="assm-chaos-001",
        title="Chaos Resilience Assessment",
        target="10.0.0.5",
        scope_id="scope-chaos",
        status=AssessmentStatus.IN_PROGRESS,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    repo.create_assessment(assm)
    return assm


def test_chaos_kill_zap_mid_scan(chaos_manager: ChaosManager) -> None:
    """When kill_zap_mid_scan is active, ZAP execution is terminated with exit code 137 and status failed."""
    chaos_manager.config.kill_zap_mid_scan = True

    intercepted, result = chaos_manager.intercept_tool_execution(
        tool="zap",
        argv=["zap.sh", "-daemon"],
    )

    assert intercepted is True
    assert result is not None
    assert result.status == "failed"
    assert result.exit_code == 137
    assert "SIGKILL" in result.stderr or "killed" in result.stderr.lower()


def test_chaos_slow_nmap_timeout(chaos_manager: ChaosManager) -> None:
    """When slow_nmap is active, Nmap execution times out with status timed_out."""
    chaos_manager.config.slow_nmap = True

    intercepted, result = chaos_manager.intercept_tool_execution(
        tool="nmap",
        argv=["nmap", "-sV", "10.0.0.5"],
    )

    assert intercepted is True
    assert result is not None
    assert result.status == "timed_out"
    assert "timed out" in result.stderr.lower() or "timeout" in result.stderr.lower()


def test_chaos_malformed_xml_handling(chaos_manager: ChaosManager) -> None:
    """When malformed_xml is active, XML is corrupted and adapter catches it safely without unhandled crash."""
    chaos_manager.config.malformed_xml = True

    corrupted_bytes = chaos_manager.corrupt_content(
        content=b"<?xml version='1.0'?><nmaprun><host></host></nmaprun>",
        tool="nmap",
    )
    assert b"corrupted" in corrupted_bytes or b"unclosed" in corrupted_bytes

    ev_meta = Evidence(
        id="ev-corrupt-1",
        source_tool="nmap",
        run_id="run-1",
        artifact_id="art-1",
        locator="/",
        raw_sha256="abc",
        snippet="",
        observed_at=datetime.now(UTC),
        origin="live",
    )

    adapter = NmapAdapter()
    findings, error = chaos_manager.safe_parse(adapter, corrupted_bytes, ev_meta)
    assert len(findings) == 0
    assert error is not None, "Error should be recorded for limitations"
    assert "parse" in error.lower() or "syntax" in error.lower() or "element" in error.lower()


def test_chaos_llm_down_fallback(
    chaos_manager: ChaosManager,
    db_conn: sqlite3.Connection,
) -> None:
    """When llm_down is active, AdaptivePlanner falls back to rule-based planner with banner."""
    chaos_manager.config.llm_down = True

    # Use a dummy client that checks chaos_manager
    class ChaosLlmClient:
        provider = "gemini"

        def complete_json(self, *args, fallback_factory=None, **kwargs):
            if chaos_manager.config.llm_down:
                if fallback_factory:
                    res = fallback_factory()
                    from cipher_lens.planner.llm import LlmResponse
                    return LlmResponse(
                        data=res,
                        label="rule-based",
                        provider="fallback",
                        model="deterministic",
                    )
                raise RuntimeError("Simulated LLM outage")
            raise NotImplementedError()

    now = datetime.now(UTC)
    scope = Scope(
        id="scope-chaos",
        name="Chaos Lab",
        authorization_reference="AUTH-CHAOS",
        targets=["10.0.0.5"],
        window_start=now,
        window_end=now,
    )
    registry = ScopeRegistry()
    registry.register(scope)
    gate = PolicyGate(registry=registry)

    planner = AdaptivePlanner(llm_client=ChaosLlmClient(), gate=gate)
    state = StateSummary(
        scope_target="10.0.0.5",
        allowed_tools=["nmap", "nikto", "zap"],
        observations=[],
        findings=[],
        done_steps=[],
        failures=[],
        remaining_budget=30,
        evidence_ids=["scope"],
    )

    proposal = planner.plan_next_steps(state)
    assert proposal is not None
    assert proposal.planner_source == "rule-based"
    assert len(proposal.steps) > 0


def test_chaos_nvd_down_fallback(
    chaos_manager: ChaosManager,
    tmp_path: Path,
) -> None:
    """When nvd_down is active, enrichment service handles outage and returns enrichment_unavailable."""
    chaos_manager.config.nvd_down = True

    class FailingClient:
        async def get(self, *args, **kwargs):
            raise Exception("Connection refused (chaos: nvd_down)")

    svc = EnrichmentService(client=FailingClient(), offline_mode=False)
    import asyncio
    enrichment = asyncio.run(svc.enrich_cve("CVE-2021-44228"))
    assert enrichment.status == "enrichment_unavailable"
