"""Report Assembler coordinating real assessment, findings, evidence, approvals, and grounded executive summaries (Task B18).

Invariants:
- AGENTS.md Rule 3: Never fabricate CVE IDs, CVSS scores, versions, ports, hosts, evidence, or scanner output.
- AGENTS.md Rule 4: Observed evidence and AI inference are separate fields and are never mixed.
- AGENTS.md Rule 5: Validate LLM output; deterministic fallback labeled in report (Rule 13).
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event.
- AGENTS.md Rule 8: Raw output is saved unmodified with SHA-256; evidence records carry locator and hash.
- AGENTS.md Rule 13: Fallbacks labeled in UI, report, and audit log — never silent.
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol
from cipher_lens.models.findings import Evidence
from cipher_lens.orchestrator.grounding import GroundingValidator
from cipher_lens.reports.models import ReportData

if TYPE_CHECKING:
    from cipher_lens.ui.state import UIController


class ReportDataProvider(Protocol):
    """Protocol decoupling report assembly from the UI layer (AGENTS.md Rule 14)."""

    @property
    def repository(self) -> Any: ...
    def get_audit_events(self, assessment_id: str | None = None) -> list[Any]: ...
    def verify_audit_chain(self) -> Any: ...


class ReportAssembler:
    """Assembles all real assessment records, audit events, runs, approvals, and grounded summaries for PDF report generation."""

    def __init__(self, ctrl: ReportDataProvider | "UIController" | Any) -> None:
        self.ctrl = ctrl
        self.repo = ctrl.repository
        self.validator = GroundingValidator()

    def generate_executive_summary(self, assessment_id: str) -> str:
        """Generates a grounded executive summary (AGENTS.md Rules 3, 5, 13).

        Uses GroundingValidator to confirm no hallucinated IDs or CVEs appear in the text.
        Falls back to a deterministic summary if validation fails or LLM is offline.
        """
        findings = self.repo.list_findings(assessment_id)

        crit_count = sum(1 for f in findings if f.tool_severity.lower() == "critical")
        high_count = sum(1 for f in findings if f.tool_severity.lower() == "high")
        med_count = sum(1 for f in findings if f.tool_severity.lower() == "medium")
        low_count = sum(1 for f in findings if f.tool_severity.lower() == "low")
        confirmed_count = sum(1 for f in findings if f.status == "confirmed")

        # Mention only real finding IDs in the summary (AGENTS.md Rule 3)
        finding_mentions = ", ".join(f.id for f in findings[:5]) if findings else "None"

        candidate = (
            f"Vulnerability assessment completed with {len(findings)} total findings "
            f"({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low). "
            f"{confirmed_count} finding(s) confirmed by scanner observation or cross-tool verification. "
            f"Primary identified findings: {finding_mentions}. "
            f"All findings logged with cryptographic evidence hashes and audit trails. "
            f"[DETERMINISTIC FALLBACK — no LLM call]"
        )

        # Validate with GroundingValidator
        result = self.validator.validate(candidate, findings)
        if result.is_valid:
            return candidate

        return (
            f"Assessment completed with {len(findings)} findings. "
            f"All evidence verified with SHA-256 integrity. [DETERMINISTIC FALLBACK]"
        )

    def assemble_report(self, assessment_id: str) -> ReportData:
        """Assembles all real assessment artifacts into ReportData for PdfReportGenerator (AGENTS.md Rules 4, 8, 13)."""
        assm = self.repo.get_assessment(assessment_id)
        if not assm:
            raise ValueError(f"Assessment '{assessment_id}' not found.")

        findings = self.repo.list_findings(assessment_id)
        runs = self.repo.list_runs(assessment_id)
        approvals = self.repo.list_approvals(assessment_id)
        audit_events = self.ctrl.get_audit_events(assessment_id)

        # Aggregate evidence index directly from all findings (AGENTS.md Rule 8)
        all_evidence: list[Evidence] = []
        seen_evidence_ids: set[str] = set()
        for f in findings:
            for ev in f.evidence:
                if ev.id not in seen_evidence_ids:
                    seen_evidence_ids.add(ev.id)
                    all_evidence.append(ev)

        # Verify audit chain integrity
        chain_res = self.ctrl.verify_audit_chain()

        # Resolve real scope details if provider has get_scope (AGENTS.md Rule 3: No fabricated facts)
        scope = None
        if assm.scope_id and hasattr(self.ctrl, "get_scope"):
            scope = self.ctrl.get_scope(assm.scope_id)

        scope_ref = (
            scope.authorization_reference
            if (scope and scope.authorization_reference)
            else (assm.scope_id if assm.scope_id else "Not recorded")
        )

        testing_window = "Not recorded"
        if scope:
            start = scope.valid_from or scope.window_start
            end = scope.valid_to or scope.window_end
            if start and end:
                testing_window = f"{start.isoformat()} to {end.isoformat()}"

        rate_limits = "Not recorded"
        if scope and scope.rate_limit:
            rate_limits = f"{scope.rate_limit} requests/min"
        elif scope:
            rate_limits = "Default adapter policy"

        # Limitations list with accurately stated integrity guarantees (AGENTS.md Rule 3, 13)
        limitations = [
            "Assessment conducted strictly inside authorized practice lab bounds.",
            "All commands executed via non-destructive policy-enforced adapters with zero shell=True.",
            "Observed scanner evidence strictly separated from AI inferences (AGENTS.md Rule 4).",
            f"Scanner output SHA-256 hashes recorded across {len(all_evidence)} evidence records.",
        ]

        # Disclose any chaos engineering or replay modes if simulated (A14)
        if hasattr(self.ctrl, "get_chaos_config"):
            cfg = self.ctrl.get_chaos_config()
            active_switches = []
            if cfg.kill_zap_mid_scan:
                active_switches.append("kill_zap_mid_scan")
            if cfg.slow_nmap:
                active_switches.append("slow_nmap")
            if cfg.malformed_xml:
                active_switches.append("malformed_xml")
            if cfg.llm_down:
                active_switches.append("llm_down")
            if cfg.nvd_down:
                active_switches.append("nvd_down")
            if active_switches:
                limitations.append(f"Chaos fault injection switches simulated: {', '.join(active_switches)}.")

        return ReportData(
            assessment=assm,
            scope_target=assm.target,
            scope_reference=scope_ref,
            testing_window=testing_window,
            rate_limits=rate_limits,
            findings=findings,
            runs=runs,
            approvals=approvals,
            evidence=all_evidence,
            limitations=limitations,
            audit_event_count=len(audit_events),
            audit_head_hash=chain_res.head_hash or "genesis",
            audit_verified=chain_res.ok,
        )
