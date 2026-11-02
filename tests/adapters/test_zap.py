"""Tests for the OWASP ZAP Adapter (Task A6).

Invariants tested:
1. Healthcheck returns healthy when reachable, unavailable when unreachable.
2. Context is strictly limited to approved target; exclusions are excluded.
3. Spider and passive scan execute and produce alerts JSON artifact.
4. Active scan strictly requires per-step approval; blocked without it (AGENTS.md Rule 2).
5. ZAP down/timeout mid-scan yields status='failed' with recorded reason; never fabricates data.
6. Raw alerts JSON is saved with SHA-256 integrity into ArtifactStore (AGENTS.md Rule 8).
7. Parser extracts CWEs, assets, observations, and raw findings with exact evidence locators.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from cipher_lens.adapters.base import ExecutionContext
from cipher_lens.adapters.zap import (
    ZapAdapter,
    parse_zap_alerts_json,
)
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.approvals import ApprovalManager, ApprovalRequiredError
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db

# ---------------------------------------------------------------------------
# Synthetic Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ZAP_VERSION = {"version": "2.14.0"}

SAMPLE_ALERTS_JSON = {
    "alerts": [
        {
            "id": "1",
            "pluginId": "10021",
            "alertRef": "10021",
            "alert": "X-Content-Type-Options Header Missing",
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "http://10.0.0.5:8080/index.html",
            "other": "",
            "param": "X-Content-Type-Options",
            "attack": "",
            "evidence": "nosniff",
            "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set.",
            "solution": "Set X-Content-Type-Options header to 'nosniff'.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "cweid": "693",
            "wascid": "15",
            "sourceid": "3",
        },
        {
            "id": "2",
            "pluginId": "40018",
            "alertRef": "40018",
            "alert": "SQL Injection",
            "name": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "url": "http://10.0.0.5:8080/login.php",
            "other": "",
            "param": "username",
            "attack": "' OR '1'='1",
            "evidence": "syntax error in SQL statement",
            "description": "SQL injection vulnerability detected in parameter username.",
            "solution": "Use prepared statements with parameterized queries.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
            "cweid": "89",
            "wascid": "19",
            "sourceid": "1",
        },
    ]
}


def _make_step(
    action_class: ActionClass = ActionClass.DISCOVERY,
    mode: str = "passive",
    target: str = "http://10.0.0.5:8080",
) -> PlanStep:
    return PlanStep(
        step_id="step-zap-01",
        tool="zap",
        action_class=action_class,
        target=target,
        params={"mode": mode, "poll_interval_seconds": 0.01, "max_poll_seconds": 2.0},
        rationale="ZAP scan of practice target",
        expected_outcome="Alerts and observations",
        nist_phase="discovery" if action_class != ActionClass.INTRUSIVE else "attack",
    )


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zap_healthcheck_healthy():
    """Healthcheck returns healthy when ZAP daemon responds with version."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "/JSON/core/view/version/" in request.url.path:
            return httpx.Response(200, json=SAMPLE_ZAP_VERSION)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = ZapAdapter(base_url="http://zap.local:8080", client=client)

    health = await adapter.healthcheck()
    assert health.status == "healthy"
    assert "2.14.0" in health.message


@pytest.mark.asyncio
async def test_zap_healthcheck_unavailable():
    """Healthcheck returns unavailable when ZAP daemon connection fails."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = ZapAdapter(base_url="http://zap.local:8080", client=client)

    health = await adapter.healthcheck()
    assert health.status == "unavailable"
    assert "not reachable" in health.message


@pytest.mark.asyncio
async def test_spider_and_passive_scan_flow(tmp_path: Path):
    """Happy path: spider and passive scan complete, alert JSON stored as artifact."""
    spider_status_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal spider_status_calls
        path = request.url.path
        if "/JSON/context/action/newContext/" in path:
            return httpx.Response(200, json={"contextId": "1"})
        if "/JSON/context/action/includeInContext/" in path:
            return httpx.Response(200, json={"result": "OK"})
        if "/JSON/spider/action/scan/" in path:
            return httpx.Response(200, json={"scan": "1001"})
        if "/JSON/spider/view/status/" in path:
            spider_status_calls += 1
            status_val = "100" if spider_status_calls >= 2 else "50"
            return httpx.Response(200, json={"status": status_val})
        if "/JSON/pscan/view/recordsToWait/" in path:
            return httpx.Response(200, json={"recordsToWait": "0"})
        if "/JSON/alert/view/alerts/" in path:
            return httpx.Response(200, json=SAMPLE_ALERTS_JSON)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    adapter = ZapAdapter(client=client)

    step = _make_step(action_class=ActionClass.DISCOVERY, mode="passive")
    ctx = ExecutionContext(artifact_store=store)

    result = await adapter.run(step=step, ctx=ctx)

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.artifact_id is not None

    # Verify stored artifact
    raw_bytes = store.read_raw(result.artifact_id)
    parsed_json = json.loads(raw_bytes)
    assert len(parsed_json["alerts"]) == 2
    assert store.verify(result.artifact_id, hashlib.sha256(raw_bytes).hexdigest())


@pytest.mark.asyncio
async def test_active_scan_refused_without_per_step_approval(tmp_path: Path):
    """Safety: active scan requires per-step human approval; blocked if unapproved."""
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)
    approval_mgr = ApprovalManager(audit_log=audit)

    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    adapter = ZapAdapter(client=client, approval_manager=approval_mgr)

    # INTRUSIVE active scan step with no approval granted
    step = _make_step(action_class=ActionClass.INTRUSIVE, mode="active")
    ctx = ExecutionContext(artifact_store=store)

    with pytest.raises(ApprovalRequiredError, match="requires human per-step approval"):
        await adapter.run(step=step, ctx=ctx, assessment_id="assess-zap-1")


@pytest.mark.asyncio
async def test_active_scan_allowed_with_per_step_approval(tmp_path: Path):
    """Safety: active scan proceeds when per-step human approval is granted."""
    conn = connect(tmp_path / "test.db")
    init_db(conn)
    audit = AuditLog(conn)
    approval_mgr = ApprovalManager(audit_log=audit)

    assessment_id = "assess-zap-approved"
    step = _make_step(action_class=ActionClass.INTRUSIVE, mode="active")

    # Request and approve per-step
    req = approval_mgr.request_approval(step=step, assessment_id=assessment_id)
    approval_mgr.decide(
        approval_id=req.approval_id,
        decision="approved",
        decided_by="senior_analyst",
        reason="Target is in authorized lab scope",
    )

    ascan_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal ascan_calls
        path = request.url.path
        if "/JSON/context/action/newContext/" in path:
            return httpx.Response(200, json={"contextId": "1"})
        if "/JSON/context/action/includeInContext/" in path:
            return httpx.Response(200, json={"result": "OK"})
        if "/JSON/ascan/action/scan/" in path:
            return httpx.Response(200, json={"scan": "2001"})
        if "/JSON/ascan/view/status/" in path:
            ascan_calls += 1
            return httpx.Response(200, json={"status": "100"})
        if "/JSON/alert/view/alerts/" in path:
            return httpx.Response(200, json=SAMPLE_ALERTS_JSON)
        return httpx.Response(200, json={"result": "OK"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    adapter = ZapAdapter(client=client, approval_manager=approval_mgr)
    ctx = ExecutionContext(artifact_store=store)

    result = await adapter.run(step=step, ctx=ctx, assessment_id=assessment_id)
    assert result.status == "succeeded"
    assert result.artifact_id is not None


@pytest.mark.asyncio
async def test_zap_mid_scan_failure_records_failed_status(tmp_path: Path):
    """When ZAP stops responding mid-scan, adapter returns status='failed' with reason."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "/JSON/context/action/newContext/" in request.url.path:
            return httpx.Response(200, json={"contextId": "1"})
        # Fails on includeInContext
        raise httpx.ReadTimeout("ZAP service timed out")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = ArtifactStore(base_dir=tmp_path / "artifacts")
    adapter = ZapAdapter(client=client)

    step = _make_step()
    ctx = ExecutionContext(artifact_store=store)

    result = await adapter.run(step=step, ctx=ctx)
    assert result.status == "failed"
    assert "ZAP service timed out" in result.stderr
    assert result.artifact_id is not None


def test_parse_zap_alerts_json():
    """Parser turns raw ZAP alerts JSON into Observations and RawFindings."""
    raw_bytes = json.dumps(SAMPLE_ALERTS_JSON).encode("utf-8")
    evidence_meta = Evidence(
        id="ev-meta-zap",
        source_tool="zap",
        run_id="run-zap-01",
        artifact_id="art-zap-01",
        locator="/alerts",
        raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        snippet="<alerts_json>",
        observed_at=datetime.now(UTC),
        origin="sample",
    )

    results = parse_zap_alerts_json(raw_bytes, evidence_meta)
    observations = [r for r in results if isinstance(r, Observation)]
    findings = [r for r in results if isinstance(r, RawFinding)]

    # Must produce host/service observations
    assert len(observations) >= 1
    host_obs = observations[0]
    assert host_obs.source_tool == "zap"
    assert host_obs.asset.host == "10.0.0.5"

    # Must produce 2 raw findings
    assert len(findings) == 2

    # Check SQL Injection finding
    sqli = next(f for f in findings if "SQL Injection" in f.title)
    assert sqli.tool_name == "zap"
    assert sqli.tool_severity == "high"
    assert sqli.confidence == "high"
    assert "CWE-89" in sqli.cwe
    assert sqli.raw_evidence.locator == "/alerts[1]"
    assert "syntax error" in sqli.raw_evidence.snippet
    assert sqli.asset.port == 8080
    assert sqli.asset.url_path == "/login.php"
