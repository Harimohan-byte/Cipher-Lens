"""Streamlit Core Dashboard for Cipher-Lens (Task A12, Master Plan §7 & §13).

Invariants:
- AGENTS.md Rule 2: Every action goes through policy authorization and approval gating.
- AGENTS.md Rule 4: Observed evidence and AI inference are separate fields and never mixed.
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event. Every LLM call writes a trace.
- AGENTS.md Rule 13: Fallbacks and sample imports are prominently labeled.
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import streamlit as st

from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.scope import Scope
from cipher_lens.reports.generator import PdfReportGenerator
from cipher_lens.reports.models import ReportData
from cipher_lens.ui.state import UIController

# Configure page layout and title
st.set_page_config(
    page_title="Cipher-Lens | VAPT Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_controller() -> UIController:
    """Initializes or retrieves the persistent UIController instance in session state."""
    if "controller" not in st.session_state:
        db_path = os.environ.get("CIPHER_LENS_DB", "local_data/cipher_lens.db")
        artifacts_dir = os.environ.get("CIPHER_LENS_ARTIFACTS", "local_data/artifacts")
        llm_provider = os.environ.get("LLM_PROVIDER", "gemini")
        st.session_state.controller = UIController(
            db_path=db_path,
            artifacts_dir=artifacts_dir,
            llm_provider=llm_provider,
        )
    return st.session_state.controller


def render_sidebar(ctrl: UIController) -> str:
    """Renders the global sidebar with system status and page navigation."""
    st.sidebar.title("🛡️ Cipher-Lens")
    st.sidebar.caption("Authorized-Lab VAPT Assistant · v2.1")
    st.sidebar.markdown("---")

    # Scope health badge
    scopes = ctrl.list_scopes()
    if scopes:
        active_scope = scopes[0]
        st.sidebar.success(f"**Active Scope:** `{active_scope.id}`")
        st.sidebar.caption(f"Ref: `{active_scope.authorization_reference}`")
        st.sidebar.caption(f"Targets: {', '.join(active_scope.allowed_targets)}")
    else:
        st.sidebar.warning("⚠️ No Scope Registered")
        st.sidebar.caption("Register an authorized lab scope before running scans.")

    st.sidebar.markdown("---")
    menu = st.sidebar.radio(
        "Navigation",
        [
            "1. Scope Boundary",
            "2. Natural Intake & Plan",
            "3. Plan Approvals & Execution",
            "4. Findings & Risk Prioritization",
            "5. Audit Log & LLM Traces",
            "6. Executive PDF Report",
        ],
        index=0,
    )

    st.sidebar.markdown("---")
    st.sidebar.caption("🔒 Safety Invariants Enforced:")
    st.sidebar.caption("• Zero `shell=True`\n• Strict Hash-Chained Audit Trail\n• Policy Gate Gated Execution\n• Prompt Injection Sanitization")
    return menu


def render_scope_page(ctrl: UIController) -> None:
    """Page 1: Scope Registration and Authorization Boundaries (Master Plan §7 Day 1 & Day 5)."""
    st.header("1. Target Scope & Authorization Registry")
    st.write(
        "Define strict target boundaries, exclusions, allowed ports, and validity windows. "
        "Any scan proposal outside this boundary will be authoritatively rejected by the policy gate."
    )

    col1, col2 = st.columns([3, 2])

    with col1:
        st.subheader("Register Authorized Lab Scope")
        with st.form("scope_registration_form"):
            scope_id = st.text_input("Scope ID", value="scope-lab-01", help="Unique identifier for the engagement boundary")
            name = st.text_input("Engagement Name / Owner", value="Authorized Practice Target Lab")
            auth_ref = st.text_input(
                "Authorization Reference",
                value="AUTH-LAB-2026-PRACTICE",
                help="Written authorization reference or rules of engagement ticket",
            )

            targets_input = st.text_area(
                "Authorized Targets (IPs, CIDRs, Hostnames, URLs - one per line)",
                value="10.0.0.0/24\nlab.local\n192.168.1.10",
                height=100,
            )

            exclusions_input = st.text_area(
                "Exclusions (Forbidden Hosts/IPs - one per line)",
                value="10.0.0.254\n192.168.1.1",
                height=70,
                help="Hosts strictly excluded from scanning. Exclusions override allowed targets.",
            )

            ports_input = st.text_input("Allowed Ports (comma-separated)", value="80, 443, 8080, 8443")
            tool_choices = st.multiselect("Allowed Tools", ["nmap", "nikto", "zap"], default=["nmap", "nikto", "zap"])

            col_w1, col_w2 = st.columns(2)
            with col_w1:
                start_days = st.number_input("Valid From (Hours ago)", value=1, min_value=0)
            with col_w2:
                end_days = st.number_input("Valid To (Hours from now)", value=24, min_value=1)

            submit_scope = st.form_submit_button("Register Authorized Scope", type="primary")

            if submit_scope:
                try:
                    targets = [t.strip() for t in targets_input.splitlines() if t.strip()]
                    exclusions = [e.strip() for e in exclusions_input.splitlines() if e.strip()]
                    ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]

                    now = datetime.now(UTC)
                    new_scope = Scope(
                        id=scope_id.strip(),
                        name=name.strip(),
                        authorization_reference=auth_ref.strip(),
                        targets=targets,
                        exclusions=exclusions,
                        allowed_ports=ports,
                        tool_allowlist=tool_choices,
                        window_start=now - timedelta(hours=int(start_days)),
                        window_end=now + timedelta(hours=int(end_days)),
                    )
                    ctrl.register_scope(new_scope)
                    st.success(f"✅ Scope `{new_scope.id}` registered successfully! Audit event committed.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to register scope: {exc}")

    with col2:
        st.subheader("Registered Active Scopes")
        scopes = ctrl.list_scopes()
        if not scopes:
            st.info("No authorized scopes currently registered.")
        else:
            for s in scopes:
                with st.expander(f"📌 {s.id} — {s.name or s.owner}", expanded=True):
                    st.markdown(f"**Authorization Ref:** `{s.authorization_reference}`")
                    st.markdown(f"**Allowed Targets:** {', '.join(s.allowed_targets)}")
                    if s.exclusions:
                        st.markdown(f"**🚫 Excluded Targets:** {', '.join(s.exclusions)}")
                    st.markdown(f"**Allowed Ports:** {', '.join(map(str, s.allowed_ports))}")
                    st.markdown(f"**Allowed Tools:** {', '.join(s.tool_allowlist) if s.tool_allowlist else 'All registered'}")
                    valid = s.is_valid_at()
                    badge = "🟢 ACTIVE" if valid else "🔴 EXPIRED"
                    st.markdown(f"**Validity Window:** {badge}")


def render_assessment_page(ctrl: UIController) -> None:
    """Page 2: Natural Language Intake & Adaptive Plan Proposal (Task A11)."""
    st.header("2. Natural Language Intake & Plan Proposal")
    st.write(
        "Enter assessment objectives in natural language. The intake parser extracts targets, "
        "validates them against registered scope boundaries, and flags any off-scope hosts."
    )

    scopes = ctrl.list_scopes()
    if not scopes:
        st.warning("⚠️ Please register an authorized scope in '1. Scope Boundary' first.")
        return

    # Assessment selection or creation
    assessments = ctrl.list_assessments()
    assm_options = {a.id: f"{a.title} ({a.id}) - Target: {a.target}" for a in assessments}
    assm_options["__new__"] = "➕ Create New Assessment..."

    selected_assm_key = st.selectbox(
        "Select Active Assessment Context",
        list(assm_options.keys()),
        format_func=lambda k: assm_options[k],
        index=0 if assessments else 0,
    )

    if selected_assm_key == "__new__":
        st.subheader("Start New Assessment via Natural Language")
        with st.form("intake_form"):
            title = st.text_input("Assessment Title", value="Staging Environment Security Audit")
            user_prompt = st.text_area(
                "Assessment Request (Natural Language)",
                value="Please perform a security assessment on 10.0.0.5 and 8.8.8.8 for open ports and OWASP Top 10 web flaws.",
                height=100,
                help="Notice what happens when 8.8.8.8 (out of scope) is entered!",
            )
            scope_choice = st.selectbox("Assign to Scope", [s.id for s in scopes])
            submit_intake = st.form_submit_button("Submit Request & Parse Scope", type="primary")

            if submit_intake:
                with st.spinner("Analyzing intake and verifying scope boundary..."):
                    assm, req, refused = ctrl.submit_intake(
                        user_request=user_prompt,
                        title=title,
                        scope_id=scope_choice,
                    )
                    st.session_state.current_assm_id = assm.id
                    st.session_state.last_intake_req = req
                    st.session_state.last_refused = refused
                    st.success(f"Assessment `{assm.id}` created!")
                    st.rerun()

    active_id = getattr(st.session_state, "current_assm_id", selected_assm_key if selected_assm_key != "__new__" else None)

    if active_id and active_id != "__new__":
        st.subheader(f"Assessment Workspace: `{active_id}`")

        # Display Intake Scope Validation Results if available
        if hasattr(st.session_state, "last_refused") and st.session_state.last_refused:
            st.error("### 🚫 Policy Gate Refusal (Out-of-Scope Targets Detected)")
            for ref_msg in st.session_state.last_refused:
                st.markdown(f"- ❌ **Refused:** `{ref_msg}`")
            st.caption("Policy refusals are recorded as immutable audit events. Scans will strictly proceed on in-scope targets only.")

        # Plan Generation Section
        st.markdown("---")
        st.subheader("Adaptive Plan Proposal")
        col_p1, col_p2 = st.columns([2, 1])

        with col_p1:
            st.write("Generate or update the adaptive execution plan based on current observations and policy constraints.")
        with col_p2:
            gen_plan_btn = st.button("Generate Adaptive Plan 🧠", type="primary")

        if gen_plan_btn:
            with st.spinner("LLM generating plan proposal with authoritative server-side validation..."):
                try:
                    proposal = ctrl.generate_plan(active_id)
                    st.session_state.current_proposal = proposal
                    st.success(f"Plan proposed successfully! Source: `{proposal.planner_source}`")
                except Exception as exc:
                    st.error(f"Error generating plan: {exc}")

        # Render Proposed Steps
        proposal = getattr(st.session_state, "current_proposal", None)
        if proposal and proposal.steps:
            st.markdown(f"**Planner Source:** `{proposal.planner_source.upper()}`")
            for idx, step in enumerate(proposal.steps, start=1):
                badge_color = {
                    ActionClass.DISCOVERY: "blue",
                    ActionClass.SCAN: "orange",
                    ActionClass.INTRUSIVE: "red",
                    ActionClass.IMPORT: "violet",
                    ActionClass.VALIDATION: "green",
                }.get(step.action_class, "gray")

                with st.expander(f"Step {idx}: `{step.tool}` on `{step.target}` [{step.action_class.value.upper()}]", expanded=True):
                    col_s1, col_s2 = st.columns(2)
                    with col_s1:
                        st.markdown(f"**Step ID:** `{step.step_id}`")
                        st.markdown(f"**Action Class:** :{badge_color}[{step.action_class.value.upper()}]")
                        st.markdown(f"**NIST Phase:** `{step.nist_phase}`")
                    with col_s2:
                        st.markdown(f"**Rationale:** {step.rationale}")
                        st.markdown(f"**Triggered By Evidence:** `{', '.join(step.triggered_by)}`")
                        st.markdown(f"**Expected Outcome:** {step.expected_outcome}")

            st.markdown("---")
            st.subheader("Human-In-The-Loop Plan Approval")
            with st.form("plan_approval_form"):
                analyst = st.text_input("Analyst Sign-off", value="analyst_operator")
                reason = st.text_input("Approval Justification", value="Plan reviewed and approved within authorized practice scope.")
                approve_btn = st.form_submit_button("Approve Plan for Execution ✅", type="primary")
                if approve_btn:
                    ctrl.approve_plan(active_id, decided_by=analyst, reason=reason)
                    st.success("✅ Plan approved! Transitioned to execution phase. Head to '3. Plan Approvals & Execution'.")


def render_execution_page(ctrl: UIController) -> None:
    """Page 3: Live Execution, Approvals, and Step Orchestration (Task A12 & B15)."""
    st.header("3. Plan Execution & Approval Checkpoint")
    st.write(
        "Monitor execution tree, inspect live decision reasoning, and resolve pending approval gates "
        "for intrusive or validation operations."
    )

    assessments = ctrl.list_assessments()
    if not assessments:
        st.info("No assessments found. Create one in '2. Natural Intake & Plan'.")
        return

    assm_map = {a.id: f"{a.title} ({a.id}) - Status: {a.status.value}" for a in assessments}
    active_id = st.selectbox("Active Assessment", list(assm_map.keys()), format_func=lambda k: assm_map[k])

    assm = ctrl.repository.get_assessment(active_id)
    if not assm:
        return

    st.markdown(f"**Status:** `{assm.status.value.upper()}` | **Target:** `{assm.target}` | **Scope:** `{assm.scope_id}`")

    # Pending Approvals Gate (Master Plan §5.7 Human-in-the-loop)
    approvals = ctrl.repository.list_approvals(active_id)
    pending_approvals = [req for req, dec in approvals if dec is None]

    if pending_approvals:
        st.warning("### ⚠️ Actions Awaiting Human Approval")
        for req in pending_approvals:
            with st.form(f"approve_gate_{req.approval_id}"):
                st.write(f"**Action Class:** `{req.action_class.value.upper()}` | **Tool:** `{req.tool}`")
                st.write(f"**Target:** `{req.target}` | **Rationale:** {req.rationale}")
                analyst = st.text_input("Approver Name", value="lead_analyst")
                col_b1, col_b2 = st.columns(2)
                with col_b1:
                    app_btn = st.form_submit_button("Approve Action ✅", type="primary")
                with col_b2:
                    rej_btn = st.form_submit_button("Reject Action ❌")

                if app_btn:
                    ctrl.decide_validation(
                        assessment_id=active_id,
                        approval_id=req.approval_id,
                        decision="approved",
                        decided_by=analyst,
                        reason="Analyst granted execution approval",
                    )
                    st.success("Action approved!")
                    st.rerun()
                elif rej_btn:
                    ctrl.decide_validation(
                        assessment_id=active_id,
                        approval_id=req.approval_id,
                        decision="rejected",
                        decided_by=analyst,
                        reason="Analyst denied execution",
                    )
                    st.warning("Action rejected and blocked from execution.")
                    st.rerun()
    else:
        st.info("No actions currently awaiting per-step approval.")

    # Execution Steps and History
    st.subheader("Assessment Steps Tree")
    steps = ctrl.repository.get_steps(active_id)
    if not steps:
        st.caption("No steps generated yet for this assessment.")
    else:
        for s in steps:
            with st.expander(f"Step `{s.step_id}`: {s.tool} on {s.target} ({s.action_class.value})"):
                st.write(f"**Rationale:** {s.rationale}")
                st.write(f"**Expected Outcome:** {s.expected_outcome}")
                st.write(f"**Triggered By:** `{s.triggered_by}`")
                st.write(f"**Idempotency Key:** `{s.idempotency_key}`")


def render_findings_page(ctrl: UIController) -> None:
    """Page 4: Findings, 0-100 Risk Prioritization, and CISA KEV Badges (Task B14)."""
    st.header("4. Correlated Findings & Risk Prioritization")
    st.write(
        "Findings prioritized by reproducible 0–100 risk scoring with CISA KEV exploitability boosts. "
        "Strict separation of observed scanner evidence from AI inferences (AGENTS.md Rule 4)."
    )

    assessments = ctrl.list_assessments()
    if not assessments:
        st.info("No assessments found.")
        return

    assm_map = {a.id: f"{a.title} ({a.id})" for a in assessments}
    active_id = st.selectbox("Select Assessment", list(assm_map.keys()), format_func=lambda k: assm_map[k])

    findings = ctrl.list_findings(active_id)
    if not findings:
        st.info(f"No findings recorded yet for assessment `{active_id}`. Once tools execute or reports are imported, findings appear here.")
    else:
        for f in findings:
            with st.expander(f"[{f.tool_severity.upper() if f.tool_severity else 'FINDING'}] {f.title} ({f.id})", expanded=True):
                col_f1, col_f2 = st.columns([3, 1])
                with col_f1:
                    st.markdown(f"**Asset:** `{f.asset.host}:{f.asset.port or 'N/A'}`")
                    st.markdown(f"**CVEs:** {', '.join(f.cve) if f.cve else 'None reported'}")
                    st.markdown(f"**CWEs:** {', '.join(f.cwe) if f.cwe else 'None reported'}")
                    st.markdown(f"**Status:** `{f.status.upper()}` | **Confidence:** `{f.confidence.upper()}`")
                with col_f2:
                    if f.risk:
                        st.metric("Risk Score", f"{f.risk.total:.1f}/100", f.risk.band.upper())
                    else:
                        st.metric("Severity", f.tool_severity.upper() if f.tool_severity else "HIGH")

                st.markdown("---")
                # AGENTS.md Rule 4: Observed Evidence vs AI Inference strictly separated
                col_ev, col_inf = st.columns(2)
                with col_ev:
                    st.subheader("🔍 Observed Scanner Evidence")
                    if f.evidence:
                        for ev in f.evidence:
                            st.caption(f"Source Tool: `{ev.source_tool}` | Locator: `{ev.locator}` | Origin: `{ev.origin}`")
                            st.code(ev.snippet or "(Raw snippet empty)", language="text")
                            st.caption(f"SHA-256: `{ev.raw_sha256}`")
                    else:
                        st.caption("No raw evidence records attached.")

                with col_inf:
                    st.subheader("🤖 AI Inferences (Untrusted)")
                    if f.inferences:
                        for inf in f.inferences:
                            st.info(f"**Inference:** {inf.summary}\n\n*Confidence:* {inf.confidence:.2f}")
                    else:
                        st.caption("No AI inferences attached to this finding.")

                st.markdown("---")
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


def render_audit_trace_page(ctrl: UIController) -> None:
    """Page 5: Hash-Chained Audit Trail & LLM Trace Inspection (Task A2, A10, A12)."""
    st.header("5. Immutable Audit Log & LLM Traces")
    st.write(
        "Cryptographically hash-chained audit log guaranteeing non-repudiation (AGENTS.md Rule 7), "
        "and complete SQLite LLM trace inspection for AI transparency."
    )

    tab_audit, tab_traces = st.tabs(["📜 Hash-Chained Audit Trail", "🧠 LLM Query Traces"])

    with tab_audit:
        col_a1, col_a2 = st.columns([3, 1])
        with col_a1:
            st.write("Every state change, policy decision, approval, and plan generation writes an append-only audit event.")
        with col_a2:
            verify_btn = st.button("Verify Audit Integrity 🔍", type="primary")

        if verify_btn:
            res = ctrl.verify_audit_chain()
            if res.ok:
                st.success(f"✅ Cryptographic integrity verified! Checked {res.rows_checked} events. Hash chain is intact.")
                st.caption(f"Current Head Hash: `{res.head_hash}`")
            else:
                st.error(f"❌ AUDIT CHAIN INTEGRITY COMPROMISED! Bad event ID: `{res.first_bad_id}`. Reason: {res.reason}")

        events = ctrl.get_audit_events()
        if not events:
            st.info("Audit log is currently empty.")
        else:
            event_rows = []
            for e in reversed(events):
                event_rows.append(
                    {
                        "ID": e.id,
                        "Timestamp": e.ts,
                        "Actor": e.actor,
                        "Event Type": e.event_type,
                        "Assessment ID": e.assessment_id or "global",
                        "Row Hash": f"{e.row_hash[:16]}...",
                        "Prev Hash": f"{e.prev_hash[:16]}...",
                    }
                )
            st.dataframe(event_rows, use_container_width=True)

            with st.expander("Inspect Raw Audit Event Payloads"):
                for e in reversed(events[-10:]):
                    st.caption(f"Event #{e.id} [{e.event_type}] by `{e.actor}` at {e.ts}")
                    st.json(e.payload)

    with tab_traces:
        st.subheader("LLM Call Traces (SQLite Backed)")
        st.write("Complete transparency into every model prompt, output, latency, and classification label.")
        traces = ctrl.get_llm_traces()
        if not traces:
            st.info("No LLM calls recorded in `llm_traces` table yet.")
        else:
            trace_table = []
            for t in traces:
                trace_table.append(
                    {
                        "ID": t["id"],
                        "Timestamp": t["timestamp"],
                        "Provider": t["provider"],
                        "Model": t["model"],
                        "Label": t["label"].upper(),
                        "Outcome": t["outcome"],
                        "Latency (ms)": t["latency_ms"],
                        "Prompt Hash": f"{t['prompt_hash'][:12]}...",
                    }
                )
            st.dataframe(trace_table, use_container_width=True)

            with st.expander("Inspect Recent LLM Prompt & Output"):
                for t in traces[:5]:
                    st.markdown(f"**Trace #{t['id']} [{t['label']}]** — Model: `{t['model']}` ({t['outcome']})")
                    st.caption(f"Prompt Summary: {t['input_summary']}")
                    st.code(t["output"], language="json")


def render_reports_page(ctrl: UIController) -> None:
    """Page 6: Official NIST SP 800-115 PDF Report Generation (Task A9)."""
    st.header("6. Executive Assessment Report (PDF)")
    st.write(
        "Generate a publication-ready penetration testing and vulnerability assessment report "
        "conforming to NIST SP 800-115 standards using ReportLab."
    )

    assessments = ctrl.list_assessments()
    if not assessments:
        st.info("No assessments found.")
        return

    assm_map = {a.id: f"{a.title} ({a.id})" for a in assessments}
    active_id = st.selectbox("Select Assessment for Report", list(assm_map.keys()), format_func=lambda k: assm_map[k])

    assm = ctrl.repository.get_assessment(active_id)
    if not assm:
        return

    findings = ctrl.list_findings(active_id)
    st.markdown(f"**Assessment Title:** {assm.title}")
    st.markdown(f"**Target Host:** `{assm.target}` | **Findings Count:** `{len(findings)}`")

    col_r1, col_r2 = st.columns(2)
    with col_r1:
        st.text_input("Lead Security Auditor", value="Lead Security Specialist")
        st.text_input("Target Organization", value="Authorized Practice Target")
    with col_r2:
        st.selectbox("Classification Level", ["Confidential", "Internal Use Only", "Restricted"], index=0)

    gen_pdf_btn = st.button("Generate Official PDF Report 📄", type="primary")

    if gen_pdf_btn:
        with st.spinner("Compiling findings, evidence hashes, and severity metrics into PDF..."):
            try:
                reports_dir = Path("local_data/reports")
                reports_dir.mkdir(parents=True, exist_ok=True)
                pdf_output_path = reports_dir / f"assessment_{assm.id}.pdf"

                generator = PdfReportGenerator()
                report_data = ReportData(
                    assessment=assm,
                    scope_target=assm.target,
                    scope_reference=assm.scope_id or "Authorized Practice Target",
                    testing_window="Authorized practice testing window",
                    findings=findings,
                    limitations=[
                        "Assessment conducted inside authorized educational practice target environment.",
                        "All scanner outputs and raw evidence hashes preserved with SHA-256 integrity.",
                    ],
                    audit_event_count=len(ctrl.get_audit_events(assm.id)),
                )
                generator.generate_to_file(report_data, pdf_output_path)

                st.success(f"✅ Report generated successfully at `{pdf_output_path}`!")
                with open(pdf_output_path, "rb") as f:
                    pdf_bytes = f.read()
                st.download_button(
                    label="Download Official Report PDF ⬇️",
                    data=pdf_bytes,
                    file_name=f"Cipher_Lens_Report_{assm.id}.pdf",
                    mime="application/pdf",
                )
            except Exception as exc:
                st.error(f"Error generating PDF report: {exc}")


def main() -> None:
    """Streamlit Application Entrypoint."""
    ctrl = get_controller()
    selected_page = render_sidebar(ctrl)

    if selected_page == "1. Scope Boundary":
        render_scope_page(ctrl)
    elif selected_page == "2. Natural Intake & Plan":
        render_assessment_page(ctrl)
    elif selected_page == "3. Plan Approvals & Execution":
        render_execution_page(ctrl)
    elif selected_page == "4. Findings & Risk Prioritization":
        render_findings_page(ctrl)
    elif selected_page == "5. Audit Log & LLM Traces":
        render_audit_trace_page(ctrl)
    elif selected_page == "6. Executive PDF Report":
        render_reports_page(ctrl)


if __name__ == "__main__":
    main()
