"""Human-in-the-loop manual validation workflow (Task A13, Master Plan §7 & §13).

Invariants:
- AGENTS.md Rule 2: Every action goes through policy authorization and approval gating.
- AGENTS.md Rule 3: Never fabricate CVE IDs, ports, evidence, or scanner outputs.
- Master Plan §0 & §7: The app NEVER launches Metasploit. Analyst tests manually in the lab.
- Master Plan §7 A13: A finding becomes confirmed only on an analyst-attested success with an attached artifact.
- Denied validation requests cannot proceed.
"""

import re
import uuid
from datetime import UTC, datetime
from typing import Literal

from cipher_lens.models.approvals import ApprovalDecision, ApprovalRequest
from cipher_lens.models.findings import Evidence, Finding, ValidationRecord
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.approvals import ApprovalManager
from cipher_lens.store.artifacts import ArtifactStore
from cipher_lens.store.audit import AuditLog


def request_validation(
    finding: Finding,
    requested_by: str,
    reason: str,
    potential_impact: str,
    approval_manager: ApprovalManager,
    assessment_id: str | None = None,
) -> ApprovalRequest:
    """Submits a human approval request for manual lab validation of a finding."""
    step_id = f"val-{finding.id}-{uuid.uuid4().hex[:6]}"
    step = PlanStep(
        step_id=step_id,
        tool="manual_validation",
        action_class=ActionClass.VALIDATION,
        target=finding.asset.host,
        params={"finding_id": finding.id, "potential_impact": potential_impact},
        rationale=reason,
        expected_outcome="Verify finding through manual lab testing",
        nist_phase="attack",
    )

    req = approval_manager.request_approval(step, assessment_id=assessment_id)

    if approval_manager.audit_log is not None:
        approval_manager.audit_log.append(
            actor=requested_by,
            event_type="validation_requested",
            payload={
                "finding_id": finding.id,
                "approval_id": req.approval_id,
                "reason": reason,
                "potential_impact": potential_impact,
                "target": finding.asset.host,
            },
            assessment_id=assessment_id,
        )

    return req


def decide_validation_request(
    approval_id: str,
    decision: Literal["approved", "rejected"],
    decided_by: str,
    reason: str,
    approval_manager: ApprovalManager,
    assessment_id: str | None = None,
) -> ApprovalDecision:
    """Records an immutable approval or rejection decision for a validation request."""
    return approval_manager.decide(
        approval_id=approval_id,
        decision=decision,
        decided_by=decided_by,
        reason=reason,
    )


def record_validation_outcome(
    finding: Finding,
    approval_decision: ApprovalDecision,
    outcome: Literal["not_run", "succeeded", "failed", "inconclusive"],
    attested_by: str,
    evidence_bytes: bytes | str | None,
    artifact_store: ArtifactStore,
    audit_log: AuditLog | None = None,
    assessment_id: str | None = None,
    approval_request: ApprovalRequest | None = None,
) -> Finding:
    """Attests manual validation results and transitions finding status accordingly.

    Safety:
    - Denied validation requests strictly cannot proceed.
    - Succeeded outcome MANDATES an attached evidence artifact (Master Plan §7 A13).
    - Metasploit is NEVER executed by the platform.
    - Approval must belong to the finding and cannot be reused or misapplied.
    """
    if approval_decision.decision != "approved":
        raise PermissionError(
            f"Cannot record validation outcome for denied or unapproved request '{approval_decision.approval_id}'"
        )

    if (
        finding.validation is not None
        and finding.validation.approval_id == approval_decision.approval_id
    ):
        raise ValueError("Validation outcome already recorded for this approval")

    if approval_request is not None:
        if approval_request.approval_id != approval_decision.approval_id:
            raise PermissionError("Approval decision does not match approval request")
        if approval_request.action_class != ActionClass.VALIDATION:
            raise PermissionError(
                f"Approval action class '{approval_request.action_class}' is not VALIDATION"
            )
        if not re.fullmatch(rf"val-{re.escape(finding.id)}-[0-9a-f]{{6}}", approval_request.step_id):
            raise PermissionError(
                f"Approval request '{approval_request.approval_id}' does not belong to finding '{finding.id}'"
            )
    else:
        if approval_decision.approval_id.startswith("plan_"):
            raise PermissionError(
                "Plan approval cannot be used for validation outcome recording; VALIDATION approval required"
            )
        if not re.search(rf"(?:^|_)val-{re.escape(finding.id)}-[0-9a-f]{{6}}(?:_|$)", approval_decision.approval_id):
            raise PermissionError(
                f"Approval '{approval_decision.approval_id}' does not belong to finding '{finding.id}'"
            )

    if outcome == "succeeded" and not evidence_bytes:
        raise ValueError(
            "Successful validation strictly requires an attached output artifact (Master Plan §7 A13)"
        )

    artifact_id: str | None = None
    if evidence_bytes:
        content_bytes = (
            evidence_bytes.encode("utf-8")
            if isinstance(evidence_bytes, str)
            else evidence_bytes
        )
        stored_artifact = artifact_store.save_raw(
            content=content_bytes,
            source_tool="manual_validation",
            run_id=approval_decision.approval_id,
            extension="txt",
        )
        artifact_id = stored_artifact.artifact_id
        snippet_text = content_bytes[:500].decode("utf-8", errors="replace")

        new_evidence = Evidence(
            id=f"ev-val-{uuid.uuid4().hex[:6]}",
            source_tool="manual_validation",
            run_id=approval_decision.approval_id,
            artifact_id=artifact_id,
            locator="/manual_attestation",
            raw_sha256=stored_artifact.sha256_hash,
            snippet=snippet_text,
            observed_at=datetime.now(UTC),
            origin="live",
        )
        finding.evidence.append(new_evidence)

    val_record = ValidationRecord(
        approval_id=approval_decision.approval_id,
        outcome=outcome,
        attested_by=attested_by,
        evidence_artifact_id=artifact_id,
        recorded_at=datetime.now(UTC),
    )
    finding.validation = val_record

    # Status & confidence transitions
    if outcome == "succeeded":
        finding.status = "confirmed"
        finding.confidence = "high"
        finding.status_reason = (
            f"Confirmed via human-attested manual lab validation by {attested_by} "
            f"with artifact {artifact_id}."
        )
    elif outcome == "failed":
        finding.status = "false_positive"
        finding.status_reason = (
            f"Marked false positive after manual validation by {attested_by} failed to reproduce."
        )
    elif outcome == "inconclusive":
        finding.status = "suspected"
        finding.status_reason = (
            f"Manual validation by {attested_by} was inconclusive."
        )

    if audit_log is not None:
        audit_log.append(
            actor=attested_by,
            event_type="validation_outcome_recorded",
            payload={
                "finding_id": finding.id,
                "approval_id": approval_decision.approval_id,
                "outcome": outcome,
                "artifact_id": artifact_id,
                "new_status": finding.status,
            },
            assessment_id=assessment_id,
        )

    return finding
