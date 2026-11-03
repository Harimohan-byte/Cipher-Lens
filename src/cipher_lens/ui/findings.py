"""Findings UI views, filtering, badges, standards mapping, and triage handling (Task B17 & A13).

Invariants:
- AGENTS.md Rule 2: Every tool run goes through policy.authorize() and approvals.require().
- AGENTS.md Rule 3: Never fabricate CVE IDs, versions, or evidence.
- AGENTS.md Rule 4: Observed evidence and AI inference are strictly separated.
- AGENTS.md Rule 7: Every triage change and validation outcome writes a hash-chained audit event.
- AGENTS.md Rule 13: Fallbacks and imported/replayed data are prominently labeled.
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
"""

from pathlib import Path
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
    return ctrl.triage_finding(
        assessment_id=assessment_id,
        finding_id=finding_id,
        new_status=new_status,
        rationale=rationale,
        actor=actor,
    )


@st.cache_resource
def _load_standards_mapper() -> tuple[StandardsMapper, bool]:
    """Loads StandardsMapper from config/mappings.yaml with caching across reruns."""
    config_path = Path("config/mappings.yaml")
    if config_path.exists():
        return StandardsMapper.load(config_path), True
    return StandardsMapper({}), False


def render_findings_view(ctrl: UIController, active_id: str) -> None:
    """Streamlit view rendering correlated findings, risk breakdown, standards, triage, and validation."""
    findings = ctrl.list_findings(active_id)
    if not findings:
        st.info(f"No findings recorded yet for assessment `{active_id}`. Once tools execute or reports are imported, findings appear here.")
        return

    # Filter & Sort Controls
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

    mapper, has_config = _load_standards_mapper()
    if not has_config:
        st.warning(
            "⚠️ Standards mapping configuration ('config/mappings.yaml') was not found. "
            "OWASP Top 10 and NIST CSF mappings are unavailable [AGENTS.md Rule 13: Fallback active]."
        )

    for f in filtered:
        status_str = f.status.upper() if f.status else "UNKNOWN"
        status_color = "🟢" if status_str == "CONFIRMED" else ("🟠" if status_str == "SUSPECTED" else "⚪")

        with st.expander(f"{status_color} [{f.tool_severity.upper() if f.tool_severity else 'INFO'}] {f.title} ({f.id})", expanded=False):
            col_d1, col_d2 = st.columns([3, 1])
            with col_d1:
                st.markdown(f"**Asset:** `{f.asset.host}:{f.asset.port or 'N/A'}`")
                st.markdown(f"**CVEs:** {', '.join(f.cve) if f.cve else 'None reported'}")
                st.markdown(f"**CWEs:** {', '.join(f.cwe) if f.cwe else 'None reported'}")

                mapping = mapper.map_finding(f.cwe)
                if mapping.owasp_top_10:
                    st.markdown(f"**OWASP Top 10 (2021):** {', '.join(mapping.owasp_top_10)}")

                st.markdown(f"**Status:** `{status_str}` | **Confidence:** `{f.confidence.upper() if f.confidence else 'MEDIUM'}`")
                st.caption(f"Reason: {f.status_reason}")
                if f.related_ids:
                    st.caption(f"Merged Finding IDs: {', '.join(f.related_ids)}")

            with col_d2:
                if f.risk:
                    has_kev = bool(f.risk.factors.get("kev_boost"))
                    kev_badge = "🔥 CISA KEV Boost" if has_kev else ""
                    st.metric("Risk Score", f"{f.risk.total:.1f}/100", f"{f.risk.band.upper()} {kev_badge}".strip())
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

            st.markdown("---")
            # Manual Lab Validation Workflow (Task A13)
            st.subheader("🧪 Manual Lab Validation (Task A13)")
            st.info(
                "🛡️ **Safety Policy Notice (AGENTS.md & Master Plan §0 & §7):** "
                "The Cipher-Lens platform **NEVER** launches Metasploit or automated exploit payloads. "
                "The analyst conducts manual testing strictly in the authorized lab and attests evidence here."
            )

            if f.validation:
                val = f.validation
                badge_color = {
                    "succeeded": "green",
                    "failed": "red",
                    "inconclusive": "orange",
                }.get(val.outcome, "gray")
                st.markdown(f"**Validation Status:** :{badge_color}[**{val.outcome.upper()}**]")
                st.markdown(f"**Attested By:** `{val.attested_by}` | **Recorded At:** `{val.recorded_at.isoformat()}`")
                if val.evidence_artifact_id:
                    st.markdown(f"**Attached Evidence Artifact:** `{val.evidence_artifact_id}`")
                st.caption(f"Status Note: {f.status_reason}")
            else:
                app_record = ctrl.get_validation_approval_for_finding(active_id, f.id)
                if app_record is None:
                    # Step 1: Request Validation
                    with st.form(f"request_val_form_{f.id}"):
                        st.markdown("##### Request Validation Approval Gate")
                        v_analyst = st.text_input("Analyst Requesting", value="analyst_operator", key=f"req_by_{f.id}")
                        v_reason = st.text_input(
                            "Testing Rationale / Hypothesis",
                            value=f"Manual lab reproduction test for finding {f.title}",
                            key=f"req_reason_{f.id}",
                        )
                        v_impact = st.text_input(
                            "Potential Impact in Lab",
                            value="Read-only HTTP inspection; minimal load on target",
                            key=f"req_impact_{f.id}",
                        )
                        req_submit = st.form_submit_button("Request Validation Gate 🔒", type="primary")
                        if req_submit:
                            ctrl.request_validation(
                                assessment_id=active_id,
                                finding_id=f.id,
                                requested_by=v_analyst,
                                reason=v_reason,
                                potential_impact=v_impact,
                            )
                            st.success("Validation approval requested! Gate is pending.")
                            st.rerun()
                else:
                    req, dec = app_record
                    if dec is None:
                        # Step 2: Pending Approval Gate
                        st.warning(f"⏳ **Validation Pending Human Gate** (Approval ID: `{req.approval_id}`)")
                        st.markdown(f"**Requested Target:** `{req.target}` | **Rationale:** {req.rationale}")
                        with st.form(f"gate_val_form_{req.approval_id}"):
                            g_analyst = st.text_input("Approving Lead", value="lead_analyst", key=f"gate_analyst_{req.approval_id}")
                            g_reason = st.text_input("Decision Reason", value="Approved for safe manual execution in lab", key=f"gate_reason_{req.approval_id}")
                            col_g1, col_g2 = st.columns(2)
                            with col_g1:
                                approve_val = st.form_submit_button("Approve Validation Gate ✅", type="primary")
                            with col_g2:
                                reject_val = st.form_submit_button("Reject Validation Gate ❌")

                            if approve_val:
                                ctrl.decide_validation(
                                    assessment_id=active_id,
                                    approval_id=req.approval_id,
                                    decision="approved",
                                    decided_by=g_analyst,
                                    reason=g_reason,
                                )
                                st.success("Validation gate approved! Proceed to record outcome.")
                                st.rerun()
                            elif reject_val:
                                ctrl.decide_validation(
                                    assessment_id=active_id,
                                    approval_id=req.approval_id,
                                    decision="rejected",
                                    decided_by=g_analyst,
                                    reason=g_reason,
                                )
                                st.error("Validation gate rejected. Lab execution blocked.")
                                st.rerun()
                    elif dec.decision == "rejected":
                        st.error(
                            f"❌ **Validation Gate Denied** by `{dec.decided_by}`: {dec.reason}\n\n"
                            "Per safety policy, outcome recording is strictly blocked for rejected validation gates."
                        )
                    elif dec.decision == "approved":
                        # Step 3: Record Outcome & Attestation
                        st.success(f"✅ **Validation Gate Approved** by `{dec.decided_by}`. Ready for analyst lab execution attestation.")
                        with st.form(f"outcome_val_form_{f.id}"):
                            st.markdown("##### Record Validation Outcome & Artifact Attestation")
                            out_choice = st.selectbox(
                                "Outcome",
                                options=["succeeded", "failed", "inconclusive"],
                                format_func=lambda o: {
                                    "succeeded": "🟢 Succeeded (Confirms finding, requires attached artifact)",
                                    "failed": "🔴 Failed (Marks finding as False Positive)",
                                    "inconclusive": "🟡 Inconclusive (Leaves finding as Suspected)",
                                }[o],
                                key=f"out_choice_{f.id}",
                            )
                            out_analyst = st.text_input("Attesting Analyst", value="analyst_operator", key=f"out_analyst_{f.id}")
                            out_upload = st.file_uploader(
                                "Attach Evidence Artifact (terminal log, output file, etc.)",
                                key=f"out_file_{f.id}",
                            )
                            out_text = st.text_area(
                                "Or Paste Raw Terminal / Tool Output Evidence",
                                placeholder="Paste raw response, curl output, or terminal session log here...",
                                key=f"out_text_{f.id}",
                            )
                            out_attest = st.checkbox(
                                "I attest that this validation was executed manually in an authorized lab and this evidence is authentic (AGENTS.md Rule 3 & 4)",
                                key=f"out_attest_{f.id}",
                            )
                            submit_outcome = st.form_submit_button("Record Attested Outcome 📝", type="primary")

                            if submit_outcome:
                                if not out_attest:
                                    st.error("You must check the attestation box to certify authentic lab evidence.")
                                else:
                                    evidence_payload: bytes | str | None = None
                                    if out_upload is not None:
                                        evidence_payload = out_upload.getvalue()
                                    elif out_text.strip():
                                        evidence_payload = out_text.strip()

                                    if out_choice == "succeeded" and not evidence_payload:
                                        st.error("A successful validation outcome strictly requires an attached evidence artifact (Master Plan §7 A13).")
                                    else:
                                        try:
                                            ctrl.record_validation(
                                                assessment_id=active_id,
                                                finding_id=f.id,
                                                approval_decision=dec,
                                                outcome=out_choice,  # type: ignore[arg-type]
                                                attested_by=out_analyst,
                                                evidence_bytes=evidence_payload,
                                            )
                                            st.success(f"Validation outcome recorded! Finding is now {f.status}.")
                                            st.rerun()
                                        except Exception as exc:
                                            st.error(f"Failed to record validation: {exc}")

    st.markdown("---")
    st.info(
        "ℹ️ **Assessment Limitations & Non-Destructive Invariants:**\n\n"
        "All vulnerability assessment checks and tools executed strictly within authorized practice lab bounds. "
        "Every finding retains SHA-256 evidence integrity and cryptographic audit trace."
    )
