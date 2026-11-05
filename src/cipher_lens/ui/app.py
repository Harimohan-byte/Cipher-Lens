"""Streamlit Core Dashboard for Cipher-Lens (Task A12, Master Plan §7 & §13).

Invariants:
- AGENTS.md Rule 2: Every action goes through policy authorization and approval gating.
- AGENTS.md Rule 4: Observed evidence and AI inference are separate fields and never mixed.
- AGENTS.md Rule 7: Every state change writes a hash-chained audit event. Every LLM call writes a trace.
- AGENTS.md Rule 13: Fallbacks and sample imports are prominently labeled.
- AGENTS.md Rule 14: Dependencies flow downward: ui -> orchestrator -> policy/adapters/correlate -> store/models.
"""

import hmac
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import streamlit as st

from cipher_lens.config import get_settings
from cipher_lens.models.plan import ActionClass
from cipher_lens.policy.gate import parse_target
from cipher_lens.policy.scope import Scope
from cipher_lens.reports.assembly import ReportAssembler
from cipher_lens.reports.generator import PdfReportGenerator
from cipher_lens.ui.findings import render_findings_view
from cipher_lens.ui.state import UIController

# Configure page layout and title
st.set_page_config(
    page_title="Cipher-Lens | VAPT Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _load_env_file() -> None:
    """Loads environment variables from .env if present and not already set."""
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v


def get_controller() -> UIController:
    """Initializes or retrieves the persistent UIController instance in session state."""
    _load_env_file()
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


def get_current_user() -> dict[str, str] | None:
    """Returns the authenticated user dict from session state (ERR-01)."""
    return st.session_state.get("authenticated_user")


def render_auth_barrier() -> bool:
    """Renders authentication barrier if session user is not authenticated (ERR-01).

    Enforces token validation and role assignment (operator, lead_analyst, auditor).
    """
    if st.session_state.get("authenticated_user"):
        return True

    settings = get_settings()

    st.title("🛡️ Cipher-Lens Access Control")
    st.write(
        "Authorized-Lab VAPT Assistant · Please authenticate with your role to enter the secure workspace."
    )

    with st.form("auth_login_form"):
        st.subheader("Session Authentication")
        username = st.text_input("Username", value="", placeholder="e.g. alice, bob, auditor")
        role = st.selectbox(
            "Assigned Role",
            options=["operator", "lead_analyst", "auditor"],
            format_func=lambda r: {
                "operator": "Operator / Pen-Tester (Scope & Scans)",
                "lead_analyst": "Lead Security Analyst (Plan Approver)",
                "auditor": "Security Auditor (Read-Only Findings & Logs)",
            }.get(r, r),
        )
        token = st.text_input(
            "Security Token / Password",
            type="password",
            help="Required if configured via environment variables (ADMIN_TOKEN / OPERATOR_TOKEN / AUDITOR_TOKEN)",
        )
        submit_btn = st.form_submit_button("Sign In 🔐", type="primary")

        if submit_btn:
            clean_user = username.strip()
            if not clean_user:
                st.error("Username cannot be empty.")
                return False

            required_token = None
            if role == "lead_analyst":
                required_token = settings.admin_token
            elif role == "operator":
                required_token = settings.operator_token or settings.admin_token
            elif role == "auditor":
                required_token = settings.auditor_token or settings.admin_token

            if required_token:
                if not token:
                    st.error(f"Security token is required for role '{role}'.")
                    return False
                if not hmac.compare_digest(token.encode("utf-8"), required_token.encode("utf-8")):
                    st.error("Invalid security token.")
                    return False

            st.session_state["authenticated_user"] = {
                "username": clean_user,
                "role": role,
            }
            st.success(f"Authenticated as {clean_user} ({role})")
            st.rerun()

    return False


def render_sidebar(ctrl: UIController) -> str:
    """Renders the global sidebar with system status and page navigation."""
    st.sidebar.title("🛡️ Cipher-Lens")
    st.sidebar.caption("Authorized-Lab VAPT Assistant · v2.1")
    st.sidebar.markdown("---")

    user = get_current_user()
    if user:
        role_label = {
            "operator": "Operator",
            "lead_analyst": "Lead Analyst",
            "auditor": "Auditor",
        }.get(user["role"], user["role"])
        st.sidebar.markdown(f"👤 **{user['username']}** `[{role_label}]`")
        if st.sidebar.button("Sign Out 🚪", key="sign_out_btn"):
            st.session_state["authenticated_user"] = None
            st.rerun()
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
        key="main_navigation_radio",
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

    user = get_current_user()
    role = user["role"] if user else "auditor"

    with col1:
        st.subheader("Register Authorized Lab Scope")
        if role == "auditor":
            st.info("ℹ️ Auditor mode: Scope registration is disabled (Read-Only).")
        else:
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
                        raw_targets = re.split(r"[,\n\r]+", targets_input)
                        cleaned_targets: list[str] = []
                        ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]
                        for t in raw_targets:
                            t_str = t.strip()
                            if not t_str:
                                continue
                            if "/" in t_str and not t_str.startswith("http://") and not t_str.startswith("https://"):
                                cleaned_targets.append(t_str)
                            else:
                                try:
                                    pt = parse_target(t_str)
                                    if pt.host:
                                        cleaned_targets.append(pt.host)
                                        if pt.port and pt.port not in ports:
                                            ports.append(pt.port)
                                    else:
                                        cleaned_targets.append(t_str)
                                except Exception:
                                    cleaned_targets.append(t_str)

                        # Deduplicate while preserving order
                        seen_targets: set[str] = set()
                        targets = []
                        for ct in cleaned_targets:
                            if ct not in seen_targets:
                                seen_targets.add(ct)
                                targets.append(ct)

                        exclusions = [e.strip() for e in re.split(r"[,\n\r]+", exclusions_input) if e.strip()]

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

    user = get_current_user()
    role = user["role"] if user else "auditor"

    if selected_assm_key == "__new__":
        st.subheader("Start New Assessment via Natural Language")
        if role == "auditor":
            st.info("ℹ️ Auditor mode: Assessment intake is disabled (Read-Only).")
        else:
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

        # Multi-Turn Conversational Dialogue & Clarification Assistant
        st.markdown("---")
        st.markdown("### 💬 Conversational Intake & Clarification Assistant")
        st.caption("Converse with Cipher-Lens to clarify scope boundaries, refine target parameters, or ask assessment questions.")

        hist_key = f"dialogue_history_{active_id}"
        if hist_key not in st.session_state:
            initial_msgs = []
            if hasattr(st.session_state, "last_intake_req") and st.session_state.last_intake_req:
                req_obj = st.session_state.last_intake_req
                if req_obj.is_ambiguous and req_obj.clarifying_question:
                    initial_msgs.append({
                        "role": "assistant",
                        "content": f"👋 **Clarification Needed:** {req_obj.clarifying_question}",
                    })
                elif req_obj.targets:
                    initial_msgs.append({
                        "role": "assistant",
                        "content": f"👋 **Intake Initialized:** Target `{', '.join(req_obj.targets)}` identified with `{req_obj.depth}` depth. Feel free to ask questions, clarify targets, or proceed to plan generation.",
                    })
            st.session_state[hist_key] = initial_msgs

        dialogue = st.session_state[hist_key]
        for dmsg in dialogue:
            with st.chat_message(dmsg["role"]):
                st.markdown(dmsg["content"])

        chat_input_val = st.chat_input("Ask a question, clarify target details, or adjust scope...", key=f"chat_{active_id}")
        if chat_input_val:
            dialogue.append({"role": "user", "content": chat_input_val})
            with st.chat_message("user"):
                st.markdown(chat_input_val)

            with st.chat_message("assistant"):
                with st.spinner("Analyzing message against scope boundaries..."):
                    curr_assm = ctrl.repository.get_assessment(active_id)
                    reply_text, parsed_req = ctrl.converse_intake(
                        history=dialogue,
                        new_message=chat_input_val,
                        scope_id=getattr(curr_assm, "scope_id", None) if curr_assm else None,
                        assessment_id=active_id,
                    )
                    st.markdown(reply_text)
                    dialogue.append({"role": "assistant", "content": reply_text})
                    if parsed_req and not parsed_req.is_ambiguous and parsed_req.targets:
                        st.session_state.last_intake_req = parsed_req

        # Plan Generation Section
        st.markdown("---")
        st.subheader("Adaptive Plan Proposal")
        if ctrl.get_chaos_config().llm_down:
            st.warning("⚠️ **LLM Outage Injected (Chaos Switch):** Operating with deterministic rule-based planner fallback.")

        col_p1, col_p2 = st.columns([2, 1])

        with col_p1:
            st.write("Generate or update the adaptive execution plan based on current observations and policy constraints.")
        with col_p2:
            gen_plan_btn = st.button("Generate Adaptive Plan 🧠", type="primary", disabled=(role == "auditor"))

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
            if role != "lead_analyst":
                st.warning("⚠️ Plan approval requires sign-off from a Lead Security Analyst. Operators and Auditors cannot approve plans (ERR-20).")
            else:
                with st.form("plan_approval_form"):
                    st.caption(f"Approving as Lead Analyst: **{user['username']}**")
                    reason = st.text_input("Approval Justification", value="Plan reviewed and approved within authorized practice scope.")
                    approve_btn = st.form_submit_button("Approve Plan for Execution ✅", type="primary")
                    if approve_btn:
                        try:
                            ctrl.approve_plan(active_id, decided_by=user["username"], reason=reason)
                            st.success("✅ Plan approved! Transitioned to execution phase. Head to '3. Plan Approvals & Execution'.")
                        except Exception as exc:
                            st.error(f"Approval failed: {exc}")


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

    user = get_current_user()
    role = user["role"] if user else "auditor"

    # Pending Approvals Gate (Master Plan §5.7 Human-in-the-loop)
    approvals = ctrl.repository.list_approvals(active_id)
    pending_approvals = [req for req, dec in approvals if dec is None]

    if pending_approvals:
        st.warning("### ⚠️ Actions Awaiting Human Approval")
        for req in pending_approvals:
            with st.form(f"approve_gate_{req.approval_id}"):
                st.write(f"**Action Class:** `{req.action_class.value.upper()}` | **Tool:** `{req.tool}`")
                st.write(f"**Target:** `{req.target}` | **Rationale:** {req.rationale}")
                if role != "lead_analyst":
                    st.info("⚠️ Only a Lead Security Analyst can decide intrusive action approvals (ERR-20).")
                else:
                    st.caption(f"Deciding as Lead Analyst: **{user['username']}**")
                    col_b1, col_b2 = st.columns(2)
                    with col_b1:
                        app_btn = st.form_submit_button("Approve Action ✅", type="primary")
                    with col_b2:
                        rej_btn = st.form_submit_button("Reject Action ❌")

                    if app_btn:
                        try:
                            ctrl.decide_validation(
                                assessment_id=active_id,
                                approval_id=req.approval_id,
                                decision="approved",
                                decided_by=user["username"],
                                reason="Lead Analyst granted execution approval",
                            )
                            st.success("Action approved!")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Approval failed: {exc}")
                    elif rej_btn:
                        try:
                            ctrl.decide_validation(
                                assessment_id=active_id,
                                approval_id=req.approval_id,
                                decision="rejected",
                                decided_by=user["username"],
                                reason="Lead Analyst rejected intrusive action",
                            )
                            st.info("Action rejected.")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Rejection failed: {exc}")
    else:
        st.info("No actions currently awaiting per-step approval.")

    # Execution Steps and History
    st.subheader("Assessment Steps Tree")
    steps = ctrl.repository.get_steps(active_id)
    if not steps:
        st.caption("No steps generated yet for this assessment.")
    else:
        col_e1, col_e2 = st.columns([3, 1])
        with col_e1:
            st.write("Execute approved steps against authorized target(s) using subprocess runners (Nmap, Nikto, ZAP).")
        with col_e2:
            exec_all_btn = st.button("Execute Approved Steps 🚀", key="exec_all_steps_btn", type="primary", disabled=(role == "auditor"))

        if exec_all_btn:
            with st.spinner("Executing live scanner steps and ingesting findings..."):
                try:
                    new_findings = ctrl.execute_all_steps(active_id)
                    st.success(f"Execution cycle complete! Ingested {len(new_findings)} findings.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Execution error: {exc}")

        for s, status in steps:
            with st.expander(f"Step `{s.step_id}`: {s.tool} on {s.target} [{status.upper()}]"):
                st.write(f"**Status:** `{status.upper()}` | **Action Class:** `{s.action_class.value.upper()}`")
                st.write(f"**Rationale:** {s.rationale}")
                st.write(f"**Expected Outcome:** {s.expected_outcome}")
                st.write(f"**Triggered By:** `{s.triggered_by}`")
                st.write(f"**Idempotency Key:** `{s.idempotency_key}`")
                if status != "completed" and role != "auditor":
                    if st.button(f"Execute Step `{s.step_id}` ⚡", key=f"exec_btn_{s.step_id}"):
                        with st.spinner(f"Running {s.tool} on {s.target}..."):
                            try:
                                res, f_list = ctrl.execute_step(active_id, s.step_id)
                                if res.status == "succeeded":
                                    st.success(f"Step {s.step_id} completed successfully! ({res.duration_seconds}s)")
                                else:
                                    st.warning(f"Step status: {res.status}. Output: {res.stderr or res.stdout}")
                                st.rerun()
                            except Exception as exc:
                                st.error(f"Step execution failed: {exc}")

    # Offline Replay Mode (Task A14)
    st.markdown("---")
    st.subheader("🔄 Offline Replay Mode (Task A14)")
    st.caption(
        "Execute the real parse → normalize → correlate → score pipeline on recorded scanner artifacts (Nmap, Nikto, Burp) "
        "with every evidence record stamped origin='replayed' (AGENTS.md Rule 8)."
    )
    col_rep1, col_rep2 = st.columns([3, 1])
    with col_rep1:
        st.write("Replay pre-recorded synthetic/sanitized scan output to verify end-to-end data processing offline.")
    with col_rep2:
        replay_btn = st.button("Replay Fixture Scans 🔄", key="replay_fixtures_btn", type="primary")

    if replay_btn:
        with st.spinner("Replaying recorded scan artifacts..."):
            replayed_findings = ctrl.replay_fixtures(active_id)
            st.success(f"Replay completed! Ingested and correlated {len(replayed_findings)} findings with origin='replayed'.")
            st.rerun()

    # Chaos Engineering & Failure Switches (Task A14)
    # Gated behind ENABLE_CHAOS configuration flag to prevent unauthorized disruption in production (ERR-06)
    settings = get_settings()
    if settings.enable_chaos:
        st.markdown("---")
        st.subheader("⚡ Chaos Engineering & Failure Injection Switches (Task A14)")
        st.caption("Simulate real-world failure modes to demonstrate platform fault-tolerance and safety.")
        cfg = ctrl.get_chaos_config()
        c1, c2, c3 = st.columns(3)
        with c1:
            kz = st.checkbox("Kill ZAP mid-scan (exit 137)", value=cfg.kill_zap_mid_scan, key="chaos_kz")
            if kz != cfg.kill_zap_mid_scan:
                ctrl.set_chaos_switch("kill_zap_mid_scan", kz)
                st.rerun()
            sn = st.checkbox("Slow Nmap (timeout)", value=cfg.slow_nmap, key="chaos_sn")
            if sn != cfg.slow_nmap:
                ctrl.set_chaos_switch("slow_nmap", sn)
                st.rerun()
        with c2:
            mx = st.checkbox("Malformed XML Output", value=cfg.malformed_xml, key="chaos_mx")
            if mx != cfg.malformed_xml:
                ctrl.set_chaos_switch("malformed_xml", mx)
                st.rerun()
            llm_d = st.checkbox("LLM Backend Outage", value=cfg.llm_down, key="chaos_llm")
            if llm_d != cfg.llm_down:
                ctrl.set_chaos_switch("llm_down", llm_d)
                st.rerun()
        with c3:
            nvd_d = st.checkbox("NVD / EPSS Outage", value=cfg.nvd_down, key="chaos_nvd")
            if nvd_d != cfg.nvd_down:
                ctrl.set_chaos_switch("nvd_down", nvd_d)
                st.rerun()


def render_findings_page(ctrl: UIController) -> None:
    """Page 4: Findings, 0-100 Risk Prioritization, and CISA KEV Badges (Task B14 & B17)."""
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

    render_findings_view(ctrl, active_id)


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

                assembler = ReportAssembler(ctrl)
                report_data = assembler.assemble_report(active_id)

                generator = PdfReportGenerator()
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

    # Enforce session authentication barrier (ERR-01)
    if not render_auth_barrier():
        return

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
