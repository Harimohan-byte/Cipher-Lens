"""Replay Mode Execution Coordinator (Task A14, Master Plan §7 Day 6).

Invariants:
1. Recorded scan artifacts run through the real parse -> normalize -> correlate -> score pipeline.
2. Every generated Evidence record carries origin="replayed" (AGENTS.md Rule 8).
3. Audit log records tool_run_replayed with origin="replayed" (AGENTS.md Rule 7).
4. Full offline safety: execution never spawns live scanner processes.
"""

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cipher_lens.adapters.base import BaseAdapter
from cipher_lens.adapters.imports.common import is_target_in_scope
from cipher_lens.correlate.dedup import correlate_findings
from cipher_lens.correlate.risk import RiskScorer
from cipher_lens.enrichment.service import EnrichmentService
from cipher_lens.models.assessment import StepRun
from cipher_lens.models.findings import Evidence, Finding, RawFinding
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.scope import Scope
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog
from cipher_lens.store.repository import AssessmentRepository

logger = logging.getLogger(__name__)


def detect_tool_from_path(path: Path | str) -> str:
    """Infers scanner tool name from filename convention or extension."""
    name = Path(path).name.lower()
    if "nmap" in name:
        return "nmap"
    if "nikto" in name:
        return "nikto"
    if "zap" in name:
        return "zap"
    if "burp" in name:
        return "burp"
    if "nessus" in name:
        return "nessus"
    if "openvas" in name:
        return "openvas"
    return "unknown"


class ReplayRunner:
    """Coordinates replaying recorded scanner artifacts through the verification pipeline."""

    def __init__(
        self,
        repository: AssessmentRepository,
        artifact_store: ArtifactStore,
        adapters: dict[str, BaseAdapter],
        risk_scorer: RiskScorer | None = None,
        enrichment_service: EnrichmentService | None = None,
        audit_log: AuditLog | None = None,
        scope: Scope | None = None,
    ) -> None:
        self.repository = repository
        self.artifact_store = artifact_store
        self.adapters = adapters
        self.risk_scorer = risk_scorer
        self.enrichment_service = enrichment_service
        self.audit_log = audit_log
        self.scope = scope

    def replay_artifact(
        self,
        assessment_id: str,
        tool_name: str,
        raw_content: bytes,
        filename: str = "recorded_output.xml",
    ) -> list[Finding]:
        """Ingests a recorded scan output artifact with origin='replayed'.

        Verifies SHA-256 before parsing and applies drop/warn/audit scope filtering (ERR-05).
        """
        ext = filename.split(".")[-1] if "." in filename else "txt"
        stored_art = self.artifact_store.save_raw(
            content=raw_content,
            source_tool=tool_name,
            run_id=f"replay_{tool_name}_{uuid.uuid4().hex[:6]}",
            extension=ext,
        )

        # Integrity check: verify stored SHA-256 matches content (ERR-05)
        calc_sha = hashlib.sha256(raw_content).hexdigest()
        if calc_sha != stored_art.sha256_hash:
            raise ValueError(
                f"Artifact integrity failure (ERR-05): calculated SHA-256 {calc_sha} "
                f"does not match stored artifact SHA-256 {stored_art.sha256_hash}"
            )

        ev_meta = Evidence(
            id=f"ev_rep_{uuid.uuid4().hex[:8]}",
            source_tool=tool_name,
            run_id=f"run_replay_{tool_name}",
            artifact_id=stored_art.artifact_id,
            locator=f"/{tool_name}/replayed",
            raw_sha256=stored_art.sha256_hash,
            snippet=raw_content[:500].decode("utf-8", errors="replace"),
            observed_at=datetime.now(UTC),
            origin="replayed",
        )

        adapter = self.adapters.get(tool_name)
        if not adapter:
            logger.warning("No adapter registered for tool '%s' during replay", tool_name)
            return []

        parsed_items: list[Any] = adapter.parse(raw_content, ev_meta)
        raw_findings = [p for p in parsed_items if isinstance(p, RawFinding)]

        if not raw_findings:
            return []

        # Scope filtering: drop, warn, and audit out-of-scope targets (ERR-05)
        filtered_raw_findings: list[RawFinding] = []
        for rf in raw_findings:
            target_str = rf.asset.ip or rf.asset.host or ""
            if self.scope is not None and not is_target_in_scope(target_str, self.scope):
                logger.warning(
                    "Replay dropped out-of-scope finding '%s' for target '%s'",
                    rf.title,
                    target_str,
                )
                if self.audit_log is not None:
                    self.audit_log.append(
                        actor="replay_runner",
                        event_type="replay_finding_dropped_out_of_scope",
                        payload={
                            "tool": tool_name,
                            "target": target_str,
                            "finding_title": rf.title,
                            "scope_id": self.scope.id,
                        },
                        assessment_id=assessment_id,
                    )
                continue
            filtered_raw_findings.append(rf)

        if not filtered_raw_findings:
            return []

        # 1. Normalize with replayed origin stamp
        for rf in filtered_raw_findings:
            rf.raw_evidence.origin = "replayed"

        # 2. Correlate
        correlated = correlate_findings(filtered_raw_findings)

        # 3. Score & Persist (merging with existing findings by correlation_key)
        existing_findings = {
            f.correlation_key: f for f in self.repository.list_findings(assessment_id)
        }
        current_count = len(existing_findings)

        saved_findings: list[Finding] = []
        for f in correlated:
            for ev in f.evidence:
                ev.origin = "replayed"

            if f.correlation_key in existing_findings:
                existing = existing_findings[f.correlation_key]
                existing.sources = sorted(set(existing.sources + f.sources))
                existing_ev_ids = {e.id for e in existing.evidence}
                for ev in f.evidence:
                    if ev.id not in existing_ev_ids:
                        existing.evidence.append(ev)
                existing.cve = sorted(set(existing.cve + f.cve))
                existing.cwe = sorted(set(existing.cwe + f.cwe))
                if self.risk_scorer:
                    existing.risk = self.risk_scorer.score_finding(existing)
                self.repository.save_finding(assessment_id, existing)
                saved_findings.append(existing)
            else:
                current_count += 1
                f.id = f"VAPT-{current_count:04d}"
                if self.risk_scorer:
                    f.risk = self.risk_scorer.score_finding(f)
                self.repository.save_finding(assessment_id, f)
                existing_findings[f.correlation_key] = f
                saved_findings.append(f)

        # 4. Record step and run records
        step_id = f"step-replay-{tool_name}-{uuid.uuid4().hex[:6]}"
        act_class = ActionClass.DISCOVERY if tool_name == "nmap" else ActionClass.SCAN
        tool_map = {
            "nmap": "nmap",
            "nikto": "nikto",
            "zap": "zap",
            "burp": "burp_import",
            "burp_import": "burp_import",
            "nessus": "nessus_import",
            "nessus_import": "nessus_import",
            "openvas": "openvas_import",
            "openvas_import": "openvas_import",
        }
        mapped_tool = tool_map.get(tool_name.lower(), "nmap")

        step = PlanStep(
            step_id=step_id,
            tool=mapped_tool,  # type: ignore[arg-type]
            action_class=act_class,
            target="replayed_target",
            params={"replay": True, "artifact_id": stored_art.artifact_id},
            rationale=f"Replayed scan from recorded {tool_name} artifact",
            expected_outcome="Parse recorded artifact into findings",
            nist_phase="discovery",
        )
        self.repository.save_step(assessment_id, step, status="completed")

        run = StepRun(
            run_id=f"run_{step_id}",
            assessment_id=assessment_id,
            step_id=step_id,
            tool_name=tool_name,
            status="success",
            exit_code=0,
            stdout_artifact_id=stored_art.artifact_id,
            raw_sha256=stored_art.sha256_hash,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
            duration_ms=45,
        )
        self.repository.save_run(run)

        # 5. Audit Logging
        if self.audit_log is not None:
            self.audit_log.append(
                actor="replay_runner",
                event_type="tool_run_replayed",
                payload={
                    "tool": tool_name,
                    "artifact_id": stored_art.artifact_id,
                    "sha256": stored_art.sha256_hash,
                    "findings_count": len(saved_findings),
                    "origin": "replayed",
                },
                assessment_id=assessment_id,
            )

        return saved_findings

    def replay_fixtures(
        self,
        assessment_id: str,
        fixture_paths: list[Path | str],
    ) -> list[Finding]:
        """Replays multiple fixture files into the assessment."""
        all_findings: list[Finding] = []
        for p in fixture_paths:
            path_obj = Path(p)
            if not path_obj.exists():
                logger.warning("Fixture path does not exist: %s", path_obj)
                continue
            tool = detect_tool_from_path(path_obj)
            if tool == "unknown":
                logger.warning("Could not detect tool for fixture %s", path_obj)
                continue
            raw_data = path_obj.read_bytes()
            findings = self.replay_artifact(
                assessment_id=assessment_id,
                tool_name=tool,
                raw_content=raw_data,
                filename=path_obj.name,
            )
            all_findings.extend(findings)

        return all_findings
