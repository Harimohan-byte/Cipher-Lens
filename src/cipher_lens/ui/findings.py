"""Findings UI views, filtering, badges, standards mapping, and triage handling (Task B17).

Invariants:
- AGENTS.md Rule 4: Observed evidence and AI inference are strictly separated.
- AGENTS.md Rule 7: Every triage change writes a hash-chained audit event.
- AGENTS.md Rule 13: Fallbacks and imported/replayed data are prominently labeled.
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
"""

from typing import Literal

import streamlit as st

from cipher_lens.correlate.standards import StandardsMapper
from cipher_lens.models.findings import Finding
from cipher_lens.ui.state import UIController


def filter_and_sort_findings(
    findings: list[Finding],
    severity_filter: list[str] | None = None,
    status_filter: list[str] | None = None,
    tool_filter: list[str] | None = None,
    sort_by: str = "risk_desc",
) -> list[Finding]:
    """Filters and sorts findings based on user criteria."""
    result = list(findings)

    if severity_filter:
        sev_set = {s.lower() for s in severity_filter}
        result = [
            f for f in result
            if f.tool_severity and f.tool_severity.lower() in sev_set
        ]

    if status_filter:
        status_set = {st.lower() for st in status_filter}
        result = [
            f for f in result
            if f.status and f.status.lower() in status_set
        ]

    if tool_filter:
        tool_set = {t.lower() for t in tool_filter}
        result = [
            f for f in result
            if any(ev.source_tool.lower() in tool_set for ev in f.evidence)
        ]

    if sort_by == "risk_desc":
        result.sort(key=lambda f: f.risk.total if f.risk else 0.0, reverse=True)
    elif sort_by == "risk_asc":
        result.sort(key=lambda f: f.risk.total if f.risk else 0.0, reverse=False)
    elif sort_by == "severity_desc":
        sev_order = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        result.sort(key=lambda f: sev_order.get(f.tool_severity.lower(), 0) if f.tool_severity else 0, reverse=True)

    return result


def apply_triage_decision(
    ctrl: UIController,
    assessment_id: str,
    finding_id: str,
    new_status: Literal["confirmed", "suspected", "false_positive", "accepted_risk"],
    rationale: str,
    actor: str = "security-analyst",
) -> bool:
    """Applies a human triage override, updating repository and writing an audit event (AGENTS.md Rule 7)."""
    if not rationale.strip():
        return False

    repo = ctrl.repository
    finding = repo.get_finding(assessment_id, finding_id)
    if not finding:
        return False

    old_status = finding.status
    updated_reason = f"{finding.status_reason} | Triaged ({new_status}): {rationale}"

    # Update in DB repository
    conn = ctrl.conn
    with conn:
        conn.execute(
            "UPDATE findings SET status = ?, status_reason = ? WHERE assessment_id = ? AND id = ?",
            (new_status, updated_reason, assessment_id, finding_id),
        )

    # Record hash-chained audit event (AGENTS.md Rule 7)
    ctrl.audit_log.append(
        event_type="finding_triaged",
        actor=actor,
        payload={
            "finding_id": finding_id,
            "title": finding.title,
            "old_status": old_status,
            "new_status": new_status,
            "rationale": rationale,
        },
        assessment_id=assessment_id,
    )
    return True


def render_findings_view(ctrl: UIController, active_id: str) -> None:
    """Streamlit view rendering correlated findings, risk breakdown, standards, and triage controls."""
    findings = ctrl.list_findings(active_id)
    if not findings:
        st.info(f"No findings recorded yet for assessment `{active_id}`. Once tools execute or reports are imported, findings appear here.")
        return

    # Filter Controls
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        severities = st.multiselect(
            "Filter Severity",
            options=["critical", "high", "medium", "low", "info"],
            default=[],
        )
    with col_f2:
        statuses = st.multiselect(
            "Filter Status",
            options=["confirmed", "suspected", "false_positive", "accepted_risk"],
            default=[],
        )
    with col_f3:
        all_tools = sorted({ev.source_tool for f in findings for ev in f.evidence if ev.source_tool})
        tools = st.multiselect(
            "Filter Tool",
            options=all_tools,
            default=[],
        )
    with col_f4:
        sort_choice = st.selectbox(
            "Sort Order",
            options=["Risk Score (High to Low)", "Risk Score (Low to High)", "Severity (High to Low)"],
            index=0,
        )

    sort_map = {
        "Risk Score (High to Low)": "risk_desc",
        "Risk Score (Low to High)": "risk_asc",
        "Severity (High to Low)": "severity_desc",
    }

    filtered = filter_and_sort_findings(
        findings,
        severity_filter=severities,
        status_filter=statuses,
        tool_filter=tools,
        sort_by=sort_map[sort_choice],
    )

    st.write(f"Showing **{len(filtered)}** of **{len(findings)}** findings:")

    mapper = StandardsMapper()

    for f in filtered:
        # Determine status badge
        status_str = f.status.upper() if f.status else "UNKNOWN"
        status_color = "🟢" if status_str == "CONFIRMED" else ("🟠" if status_str == "SUSPECTED" else "⚪")

        with st.expander(f"{status_color} [{f.tool_severity.upper() if f.tool_severity else 'INFO'}] {f.title} ({f.id})", expanded=False):
            col_d1, col_d2 = st.columns([3, 1])
            with col_d1:
                st.markdown(f"**Asset:** `{f.asset.host}:{f.asset.port or 'N/A'}`")
                st.markdown(f"**CVEs:** {', '.join(f.cve) if f.cve else 'None reported'}")
                st.markdown(f"**CWEs:** {', '.join(f.cwe) if f.cwe else 'None reported'}")

                # Standards Mappings
                owasp_list = []
                for cwe_id in f.cwe:
                    mapped_owasp = mapper.cwe_to_owasp(cwe_id)
                    if mapped_owasp:
                        owasp_list.append(f"{mapped_owasp.id} - {mapped_owasp.title}")
                if owasp_list:
                    st.markdown(f"**OWASP Top 10 (2021):** {', '.join(set(owasp_list))}")

                st.markdown(f"**Status:** `{status_str}` | **Confidence:** `{f.confidence.upper() if f.confidence else 'MEDIUM'}`")
                st.caption(f"Reason: {f.status_reason}")
                if f.related_ids:
                    st.caption(f"Merged Finding IDs: {', '.join(f.related_ids)}")

            with col_d2:
                if f.risk:
                    has_kev = bool(f.risk.factors.get("kev_boost"))
                    kev_badge = "🔥 CISA KEV Boost" if has_kev else ""
                    st.metric("Risk Score", f"{f.risk.total:.1f}/100", f"{f.risk.band.upper()} {kev_badge}")
                else:
                    st.metric("Severity", f.tool_severity.upper() if f.tool_severity else "INFO")

            st.markdown("---")
            # AGENTS.md Rule 4: Observed Scanner Evidence vs AI Inference strictly separated
            col_ev, col_inf = st.columns(2)
            with col_ev:
                st.subheader("🔍 Observed Scanner Evidence")
                if f.evidence:
                    for ev in f.evidence:
                        st.caption(f"Tool: `{ev.source_tool}` | Locator: `{ev.locator}` | Origin: `{ev.origin}`")
                        st.code(ev.snippet or "(Raw snippet empty)", language="text")
                        st.caption(f"SHA-256 Hash: `{ev.raw_sha256}`")
                else:
                    st.caption("No raw evidence records attached.")

            with col_inf:
                st.subheader("🤖 AI Inferences (Untrusted Input)")
                if f.inferences:
                    for inf in f.inferences:
                        st.info(f"**Inference:** {inf.text}\n\n*Source:* {inf.provider} ({inf.label})")
                else:
                    st.caption("No AI inferences attached.")

            st.markdown("---")
            # Human Triage Actions (AGENTS.md Rule 2, 7)
            st.subheader("🛡️ Human Triage Actions")
            col_t1, col_t2 = st.columns(2)
            with col_t1:
                with st.form(f"triage_fp_{f.id}"):
                    fp_reason = st.text_input("False Positive Rationale", placeholder="Reason verified by analyst...")
                    submit_fp = st.form_submit_button("Mark as False Positive")
                    if submit_fp:
                        if apply_triage_decision(ctrl, active_id, f.id, "false_positive", fp_reason):
                            st.success("Finding marked as False Positive. Audit event logged.")
                            st.rerun()
                        else:
                            st.error("Rationale is required.")
            with col_t2:
                with st.form(f"triage_ar_{f.id}"):
                    ar_reason = st.text_input("Accepted Risk Rationale", placeholder="Business justification...")
                    submit_ar = st.form_submit_button("Accept Risk")
                    if submit_ar:
                        if apply_triage_decision(ctrl, active_id, f.id, "accepted_risk", ar_reason):
                            st.success("Finding marked as Accepted Risk. Audit event logged.")
                            st.rerun()
                        else:
                            st.error("Rationale is required.")

    # Limitations box at bottom
    st.markdown("---")
    st.info(
        "ℹ️ **Assessment Limitations & Non-Destructive Invariants:**\n\n"
        "All vulnerability assessment checks and tools executed strictly within authorized practice lab bounds. "
        "Every finding retains SHA-256 evidence integrity and cryptographic audit trace."
    )
