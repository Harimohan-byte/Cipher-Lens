"""Day 1 Vertical Slice Integration Test.

Validates the complete pipeline:
  ScopeRegistry → PolicyGate.authorize() → ApprovalManager.require()
  → ArtifactStore.save_raw() → NmapAdapter.parse()
  → AuditLog.append() → AuditLog.verify_chain()

This test uses only synthetic/sample fixtures and an in-memory SQLite database.
No live tools are executed and no external targets are contacted.
"""

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.approvals import ApprovalManager, ApprovalRequiredError
from cipher_lens.policy.gate import PolicyGate
from cipher_lens.policy.scope import Scope, ScopeRegistry
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.tables import SCHEMA_STATEMENTS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_audit_log() -> AuditLog:
    """Create an isolated in-memory SQLite AuditLog (no file I/O)."""
    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=True)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    for stmt in SCHEMA_STATEMENTS:
        conn.execute(stmt)
    return AuditLog(conn=conn)


def make_scope(target_ip: str = "10.0.0.5") -> Scope:
    now = datetime.now(UTC)
    return Scope(
        id="scope-day1-slice",
        owner="lab-analyst",
        authorization_reference="AUTHORIZED-LAB-SELF-HOSTED-PRACTICE-TARGET",
        allowed_targets=[target_ip],
        exclusions=[],
        allowed_ports=[],  # empty = all ports allowed per scope spec
        tool_allowlist=["nmap"],
        valid_from=now - timedelta(hours=1),
        valid_to=now + timedelta(hours=8),
    )


def make_step(target: str = "10.0.0.5") -> PlanStep:
    return PlanStep(
        step_id="slice-step-01",
        tool="nmap",
        action_class=ActionClass.DISCOVERY,
        target=target,
        params={"ports": "80,443", "profile": "discovery"},
        rationale="Day 1 vertical slice discovery pass",
        expected_outcome="Open port observations for practice target",
        nist_phase="discovery",
    )


SYNTHETIC_NMAP_PATH = Path(__file__).parent / "fixtures" / "nmap_synthetic.xml"


# ---------------------------------------------------------------------------
# Vertical Slice Test
# ---------------------------------------------------------------------------


class TestDay1VerticalSlice:
    """End-to-end pipeline test connecting all Day 1 components."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path: Path):
        # Infrastructure
        self.audit_log = make_audit_log()
        self.artifact_store = ArtifactStore(base_dir=tmp_path / "artifacts")

        # Person A components
        self.registry = ScopeRegistry()
        self.scope = make_scope()
        self.registry.register(self.scope)

        self.gate = PolicyGate(
            registry=self.registry,
            audit_log=self.audit_log,
            # DECISION: override DNS resolver so test never makes a real DNS call
            resolver=lambda host: [host],  # IP-literal targets bypass DNS
        )
        self.approval_manager = ApprovalManager(audit_log=self.audit_log)

        # Person B component
        self.adapter = NmapAdapter()

        # Approve the plan (prerequisite for DISCOVERY steps)
        self.assessment_id = "assessment-day1-slice"
        self.approval_manager.approve_plan(
            assessment_id=self.assessment_id,
            decided_by="lab-analyst",
            reason="Day 1 vertical slice integration test",
        )

    def test_full_pipeline_succeeds(self):
        """Happy-path: authorize → approve → store artifact → parse → audit chain valid."""
        step = make_step()

        # 1. Policy gate MUST authorize the in-scope IP target
        decision = self.gate.authorize(
            target=step.target,
            tool=step.tool,
            action_class=step.action_class,
            assessment_id=self.assessment_id,
        )
        assert decision.allowed, f"Gate denied in-scope target: {decision.reason}"

        # 2. Approval gate MUST pass for an approved DISCOVERY step
        self.approval_manager.require(step, assessment_id=self.assessment_id)

        # 3. Store the synthetic Nmap XML as a raw artifact
        raw_bytes = SYNTHETIC_NMAP_PATH.read_bytes()
        artifact_meta = self.artifact_store.save_raw(
            content=raw_bytes,
            source_tool="nmap",
            run_id="run-day1-slice",
            extension="xml",
        )
        assert artifact_meta.sha256_hash == hashlib.sha256(raw_bytes).hexdigest()
        assert self.artifact_store.verify(artifact_meta.artifact_id, artifact_meta.sha256_hash)

        # 4. Build the evidence record referencing the stored artifact
        evidence = Evidence(
            id="ev-slice-01",
            source_tool="nmap",
            run_id="run-day1-slice",
            artifact_id=artifact_meta.artifact_id,
            locator="/nmaprun/host[1]",
            raw_sha256=artifact_meta.sha256_hash,
            snippet="<host>...</host>",
            observed_at=datetime.now(UTC),
            origin="sample",
        )

        # 5. Parse the raw XML into observations and raw findings
        results = self.adapter.parse(raw_bytes, evidence)
        observations = [r for r in results if isinstance(r, Observation)]
        raw_findings = [r for r in results if isinstance(r, RawFinding)]

        assert len(observations) >= 1, "Parser must emit at least one host observation"
        assert any(o.asset.ip == "10.0.0.5" for o in observations), (
            "Host observation must match fixture IP"
        )
        assert any("CVE-2021-41773" in rf.cve for rf in raw_findings), (
            "Parser must extract CVE-2021-41773 from synthetic fixture"
        )

        # 6. Record artifact and finding events to the audit log
        # (Note: PolicyGate.authorize() and ApprovalManager already appended their events)
        self.audit_log.append(
            actor="artifact_store",
            event_type="raw_artifact_saved",
            payload={
                "artifact_id": artifact_meta.artifact_id,
                "source_tool": artifact_meta.source_tool,
                "sha256_hash": artifact_meta.sha256_hash,
                "size_bytes": artifact_meta.size_bytes,
            },
            assessment_id=self.assessment_id,
        )
        for rf in raw_findings:
            self.audit_log.append(
                actor="nmap_adapter",
                event_type="raw_finding_parsed",
                payload={
                    "title": rf.title,
                    "tool": rf.tool_name,
                    "host": rf.asset.host,
                    "port": rf.asset.port,
                    "cve": rf.cve,
                    "severity": rf.tool_severity,
                    # AGENTS.md §4: evidence artifact_id is logged, raw snippet is NOT
                    "evidence_artifact_id": rf.raw_evidence.artifact_id,
                },
                assessment_id=self.assessment_id,
            )

        # 7. Verify the entire audit hash chain is intact
        verification = self.audit_log.verify_chain()
        assert verification.ok, (
            f"Audit chain BROKEN at row {verification.first_bad_id}: {verification.reason}"
        )
        assert verification.rows_checked >= 4, (
            f"Expected at least 4 audit events, got {verification.rows_checked}"
        )

    def test_out_of_scope_target_is_denied_and_audited(self):
        """Safety: A target not in scope is denied by the gate and logged."""
        step = make_step(target="8.8.8.8")  # External, not in scope

        decision = self.gate.authorize(
            target=step.target,
            tool=step.tool,
            action_class=step.action_class,
            assessment_id=self.assessment_id,
        )
        assert not decision.allowed, "Gate must deny out-of-scope target"
        assert "8.8.8.8" in decision.reason or "NOT_IN_SCOPE" in decision.rule_id

        # Verify the denial event was written to the audit log
        cursor = self.audit_log.conn.cursor()
        cursor.execute(
            "SELECT payload FROM audit_log WHERE event_type = 'policy_decision' ORDER BY id DESC LIMIT 1"
        )
        last_event = cursor.fetchone()
        assert last_event is not None
        assert '"allowed":false' in last_event[0]
        assert "8.8.8.8" in last_event[0]

        # Chain must still be intact after a denied decision
        verification = self.audit_log.verify_chain()
        assert verification.ok

    def test_unapproved_plan_blocks_discovery_step(self):
        """Safety: A DISCOVERY step against a fresh unapproved assessment is blocked."""
        # New assessment with no plan approval
        unapproved_manager = ApprovalManager(audit_log=self.audit_log)
        step = make_step()

        with pytest.raises(ApprovalRequiredError, match="requires plan approval"):
            unapproved_manager.require(step, assessment_id="assessment-unapproved")

    def test_artifact_tamper_detected_before_parse(self, tmp_path: Path):
        """Safety: A tampered artifact file is caught before being passed to the parser."""
        raw_bytes = SYNTHETIC_NMAP_PATH.read_bytes()
        store = ArtifactStore(base_dir=tmp_path / "tamper_test")
        meta = store.save_raw(raw_bytes, source_tool="nmap", run_id="run-tamper")
        saved_hash = meta.sha256_hash

        # Tamper on disk
        artifact_path = store.get_path(meta.artifact_id)
        with open(artifact_path, "wb") as f:
            f.write(b"TAMPERED DATA")

        assert not store.verify(meta.artifact_id, saved_hash), (
            "Verification must fail for tampered artifact"
        )

    def test_audit_log_no_update_trigger_blocks_tampering(self):
        """Safety: SQLite trigger prevents any UPDATE on the audit_log table (strongest tamper protection).

        This test verifies the append-only SQLite trigger is enforced,
        which is a stronger guarantee than hash-chain detection alone.
        The trigger fires before any row modification, so even a privileged
        SQL UPDATE cannot alter a committed audit record.
        """
        self.audit_log.append(
            actor="test",
            event_type="test_event",
            payload={"k": "v"},
            assessment_id=self.assessment_id,
        )

        # Attempting to UPDATE any row MUST raise an IntegrityError due to the
        # `audit_log_no_update` trigger. This is the primary tamper barrier.
        with pytest.raises(sqlite3.IntegrityError, match="audit_log is append-only"):
            self.audit_log.conn.execute(
                'UPDATE audit_log SET payload = \'{"k":"TAMPERED"}\' '
                "WHERE id = (SELECT MAX(id) FROM audit_log)"
            )

        # Chain must remain intact since the UPDATE was rejected
        verification = self.audit_log.verify_chain()
        assert verification.ok, (
            f"Chain should be intact after blocked tamper attempt: {verification.reason}"
        )

    def test_audit_log_no_delete_trigger_blocks_row_removal(self):
        """Safety: SQLite trigger prevents any DELETE on the audit_log table."""
        self.audit_log.append(
            actor="test",
            event_type="test_event_delete_check",
            payload={"k": "v"},
            assessment_id=self.assessment_id,
        )

        with pytest.raises(sqlite3.IntegrityError, match="audit_log is append-only"):
            self.audit_log.conn.execute(
                "DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)"
            )

        verification = self.audit_log.verify_chain()
        assert verification.ok
