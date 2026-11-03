"""Tests for Replay Mode (Task A14, Master Plan §7 Day 6).

Invariants:
- Recorded artifacts run through the real parse -> normalize -> correlate -> score -> report pipeline.
- Every replayed evidence record is explicitly labeled origin="replayed" (AGENTS.md Rule 8).
- Audit trail records tool_run_replayed with origin="replayed" (AGENTS.md Rule 7).
- Replay does not require live scanner binaries (safe offline execution).
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipher_lens.adapters.imports.burp import BurpImporter
from cipher_lens.adapters.nikto import NiktoAdapter
from cipher_lens.adapters.nmap import NmapAdapter
from cipher_lens.adapters.zap import ZapAdapter
from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.models.assessment import Assessment, AssessmentStatus
from cipher_lens.orchestrator.replay import ReplayRunner
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.db import connect, init_db
from cipher_lens.store.repository import AssessmentRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(tmp_path / "replay_test.db")
    init_db(conn)
    return conn


@pytest.fixture
def repo(db_conn: sqlite3.Connection) -> AssessmentRepository:
    return AssessmentRepository(db_conn)


@pytest.fixture
def audit_log(db_conn: sqlite3.Connection) -> AuditLog:
    return AuditLog(db_conn)


@pytest.fixture
def artifact_store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "artifacts")


@pytest.fixture
def replay_runner(
    repo: AssessmentRepository,
    artifact_store: ArtifactStore,
    audit_log: AuditLog,
) -> ReplayRunner:
    adapters = {
        "nmap": NmapAdapter(),
        "nikto": NiktoAdapter(),
        "zap": ZapAdapter(),
        "burp": BurpImporter(),
        "burp_import": BurpImporter(),
    }
    return ReplayRunner(
        repository=repo,
        artifact_store=artifact_store,
        adapters=adapters,
        risk_scorer=RiskScorer(),
        audit_log=audit_log,
    )


@pytest.fixture
def sample_assessment(repo: AssessmentRepository) -> Assessment:
    assm = Assessment(
        id="assm-replay-001",
        title="Replay Demonstration Assessment",
        target="10.0.0.5",
        scope_id="scope-default",
        status=AssessmentStatus.IN_PROGRESS,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    repo.create_assessment(assm)
    return assm


def test_replay_nmap_artifact_labels_evidence_replayed(
    replay_runner: ReplayRunner,
    repo: AssessmentRepository,
    audit_log: AuditLog,
    sample_assessment: Assessment,
) -> None:
    """Replaying Nmap XML parses real observations/findings and stamps origin='replayed'."""
    nmap_xml = (FIXTURES_DIR / "nmap_synthetic.xml").read_bytes()

    findings = replay_runner.replay_artifact(
        assessment_id=sample_assessment.id,
        tool_name="nmap",
        raw_content=nmap_xml,
    )

    assert len(findings) > 0
    for f in findings:
        assert len(f.evidence) > 0
        for ev in f.evidence:
            assert ev.origin == "replayed", f"Evidence {ev.id} must be labeled 'replayed'"
        assert f.risk is not None, "Replayed findings must have risk score calculated"

    # Verify audit event
    events = audit_log.query(assessment_id=sample_assessment.id, event_type="tool_run_replayed")
    assert len(events) == 1
    assert events[0].payload["tool"] == "nmap"
    assert events[0].payload["origin"] == "replayed"


def test_replay_multiple_tools_deduplicates_and_correlates(
    replay_runner: ReplayRunner,
    repo: AssessmentRepository,
    sample_assessment: Assessment,
) -> None:
    """Replaying both Nmap and Nikto correlates findings into assessment."""
    nmap_xml = (FIXTURES_DIR / "nmap_synthetic.xml").read_bytes()
    nikto_xml = (FIXTURES_DIR / "nikto_synthetic.xml").read_bytes()

    replay_runner.replay_artifact(
        assessment_id=sample_assessment.id,
        tool_name="nmap",
        raw_content=nmap_xml,
    )
    replay_runner.replay_artifact(
        assessment_id=sample_assessment.id,
        tool_name="nikto",
        raw_content=nikto_xml,
    )

    all_findings = repo.list_findings(sample_assessment.id)
    assert len(all_findings) > 0

    sources = {src for f in all_findings for src in f.sources}
    assert "nmap" in sources
    assert "nikto" in sources

    # Every finding in repository has replayed evidence
    for f in all_findings:
        for ev in f.evidence:
            assert ev.origin == "replayed"


def test_replay_fixture_files_by_path(
    replay_runner: ReplayRunner,
    repo: AssessmentRepository,
    sample_assessment: Assessment,
) -> None:
    """replay_fixtures parses list of fixture paths, auto-detecting tools."""
    paths = [
        FIXTURES_DIR / "nmap_synthetic.xml",
        FIXTURES_DIR / "nikto_synthetic.xml",
        FIXTURES_DIR / "burp_synthetic.xml",
    ]
    findings = replay_runner.replay_fixtures(
        assessment_id=sample_assessment.id,
        fixture_paths=paths,
    )

    assert len(findings) > 0
    all_findings = repo.list_findings(sample_assessment.id)
    assert len(all_findings) >= len(findings)
