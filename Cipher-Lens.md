# Cipher-Lens: AI-Powered Unified VAPT Assistant

> **Classification:** Authorized Practice Lab & Cyber Range VAPT Platform  
> **Standards Conformance:** NIST SP 800-115, OWASP Top 10 (2021/2025), NIST CSF 2.0, CWE, MITRE ATT&CK  
> **Reference Document:** DataOps Innovation Hackathon Problem Statement (`PROBLEM-STATEMENT.pdf`)

---

## 1. Executive Summary & Project Vision

**Cipher-Lens** is an autonomous, conversational, and deterministic Vulnerability Assessment and Penetration Testing (VAPT) assistant designed specifically for security teams, ethical hackers, and students operating within authorized cyber ranges and staging labs.

### The Problem Space
Traditional penetration testing workflows suffer from five systemic inefficiencies:
1. **Tool Sprawl & Fragmentation:** Analysts juggle CLI tools (Nmap, Nikto), enterprise proxies (Burp Suite, OWASP ZAP), and vulnerability scanners (Nessus, OpenVAS), each emitting incompatible output formats.
2. **Alert Fatigue & Inconsistent Deduplication:** Scanning the same asset across multiple engines generates redundant alerts, inflating report volumes by 300–500% without adding actionable insight.
3. **Uncontrolled & Dangerous Tool Execution:** Autonomous AI agents executing raw shell commands (`shell=True`) risk runaway execution, SSRF into cloud metadata (`169.254.169.254`), and unauthorized scanning of third-party IP addresses.
4. **AI Hallucination & Disinformation:** LLMs frequently invent nonexistent CVEs, fabricate CVSS scores, and hallucinate open ports, destroying the integrity of security audits.
5. **Lack of Auditability & Evidence Traceability:** Reports often state vulnerabilities without cryptographic proof or clear separation between what was *directly observed* by a scanner and what was *inferred* by artificial intelligence.

### The Cipher-Lens Solution
Cipher-Lens addresses each challenge through a unified 6-page interactive interface and downward-flowing modular backend:
- **Strict Evidence-Inference Segregation:** Observed tool output and AI reasoning are stored in distinct model fields; AI inference is never counted as scanner evidence.
- **Deterministic Policy Enforcement:** Every packet and command passes through an authoritative `PolicyGate` enforcing CIDR containment, private network boundaries, and exclusion lists.
- **Zero `shell=True` Subprocess Execution:** Scanner adapters build immutable argument vectors (`argv` lists) directly without invoking shell interpreters.
- **Dual-Model Gemini High-Availability Failover:** Leverages free-tier Google Gemini Developer API models (`gemini-3.5-flash-lite` primary, `gemini-3.1-flash-lite` fallback) with automatic failover to a deterministic rule-based planner.
- **Tamper-Evident Hash-Chained Audit Log:** Every decision, scan step, policy denial, and LLM prompt/response is logged into a SHA-256 hash-chained ledger backed by SQLite database triggers that physically prevent row modification or deletion.

---

## 2. Compliance with Hackathon Problem Statement Requirements

Cipher-Lens was built from the ground up to fulfill every requirement specified in `PROBLEM-STATEMENT.pdf` (DataOps Innovation Hackathon). Below is the comprehensive requirement-to-implementation mapping:

| Workflow Step (`PROBLEM-STATEMENT.pdf`) | Cipher-Lens Implementation | Verification & Evidence |
| :--- | :--- | :--- |
| **Step 1: Analyst Request** | Natural language intake parser + multi-turn conversational assistant with intent extraction (target, scan depth, objectives) and instant scope verification. | Page 2 of UI (`app.py`), `intake.py`, `test_intake.py` |
| **Step 2: Adaptive Planning** | Multi-round adaptive state machine proposing progressive steps (Discovery $\to$ Vulnerability Scan $\to$ Targeted Probing) within budget limits. | `planner.py`, `rules_planner.py`, `test_adaptive_loop_integration.py` |
| **Step 3: Scan Orchestration** | Asynchronous subprocess runner executing Nmap, Nikto, and ZAP via strict argv vectors with zero `shell=True` and real-time process monitoring. | `runner.py`, `engine.py`, `test_engine.py` |
| **Step 4: Result Ingestion** | Hardened XML/JSON ingestion using `defusedxml` to block XXE attacks; raw scanner outputs preserved with SHA-256 hash and locator metadata. | `artifacts.py`, `test_importers.py`, `test_artifacts.py` |
| **Step 5: AI-Driven Correlation** | Multi-tool deduplication merging identical CVE/CWE findings on the same asset into unified findings while preserving all evidence locators. | `dedup.py`, `standards.py`, `test_correlate.py` |
| **Step 6: Risk Prioritization** | CVSS v3.1 base scoring combined with contextual asset criticality, exploitability metrics (CISA KEV, EPSS), and false-positive pruning. | `engine.py`, `service.py`, `test_engine.py` |
| **Step 7: Human-in-the-Loop Review** | Explicit approval checkpoints for `INTRUSIVE` and `VALIDATION` actions; state transitions strictly bound to human authorization decisions. | `approvals.py`, `validation.py`, Page 3 of UI |
| **Step 8: Unified VAPT Reporting** | Comprehensive ReportLab PDF generator containing Executive Summary, Scope Summary, Correlated Findings, Risk Matrix, Remediation Roadmap, and Evidence Index. | `generator.py`, `assembly.py`, `test_pdf_report.py` |

---

## 3. Comprehensive Feature Catalog

### 3.1. Dual-Model Gemini Developer API Architecture & Capacity Failover
- **Supported Models:** Built exclusively for Google Gemini Developer API free-tier models:
  - **Primary Model:** `gemini-3.5-flash-lite` (High-speed structured output generation)
  - **Secondary Model:** `gemini-3.1-flash-lite` (Automatic failover on 503 capacity spikes, 429 rate limits, or transient API timeouts)
  - **Multi-Modal / Extended Vision:** `gemini-2.5-flash`
  - **Text-to-Speech:** `gemini-2.5-flash-preview-tts`
- **Developer API Schema Compatibility:** All Pydantic models (such as `StepParams`, `AssessmentRequest`, `PlanProposal`) strictly avoid unconstrained dictionary schemas (`additionalProperties`), ensuring flawless JSON Schema generation in Gemini Developer API mode.
- **Prompt Injection Sanitization:** Untrusted inputs (such as HTTP banners, XML fields, scanner stdout) are sanitized and isolated within `<tool_output>` XML delimiters. System prompts strictly instruct the LLM to treat content inside these tags as untrusted data rather than instructions.

### 3.2. Offline Deterministic Rule-Based Fallback Planner
- When API keys are missing, quota is exhausted, or the operator toggles the UI Chaos Switch (`llm_down=True`), Cipher-Lens immediately falls back to a deterministic rule-based planner.
- Implements a progressive 3-phase security state machine:
  1. **Phase 1 (Network Discovery):** Enumerate open ports and services using Nmap discovery profiles restricted to allowed scope ports.
  2. **Phase 2 (Web Assessment):** If open web ports (80, 443, 3000, 8080, etc.) are discovered, automatically propose Nikto and ZAP passive scans triggered by verified observation evidence IDs.
  3. **Phase 3 (Completion):** When all allowed tools have evaluated discovered assets, issues `stop=True` with a transparent explanation.

### 3.3. Deterministic PolicyGate & Boundary Defense
- **Authoritative Enforcement:** Every single proposed scan step and target must pass `PolicyGate.authorize()` before execution. No tool can run without gate authorization.
- **CIDR Containment:** Validates whether targets fall inside registered IPv4/IPv6 CIDR ranges (`10.0.0.0/24`, `127.0.0.1/32`).
- **Exclusion Precedence:** Exclusions explicitly override allowed targets. If an IP or subnet is listed in `exclusions`, it is unconditionally denied.
- **Private & Loopback Safeguards:** Routable public IP ranges (e.g. `8.8.8.8`) are denied by default unless the scope record explicitly carries `allow_public_targets=True`.
- **Hard-Deny Cloud Metadata:** Access to cloud metadata IP `169.254.169.254` (AWS/GCP/Azure instance credentials) is permanently hard-coded as prohibited and cannot be bypassed.
- **SSRF & DNS Rebinding Protection:** Target domains are resolved and pinned prior to execution. If a domain's IP resolves to a disallowed or excluded range, or changes between planning and execution, the action is rejected.
- **URL & Userinfo Sanitization:** Defends against RFC 3986 userinfo trickery (e.g. `http://evil.com@10.0.0.5`), trailing dot bypasses (`10.0.0.5.`), IPv4-mapped IPv6 evasion (`::ffff:10.0.0.5`), and IDN homograph domain attacks.

### 3.4. Multi-Scanner Tool Adapters & Subprocess Runner
- **Live Scanner Adapters:**
  - **Nmap Adapter:** Supports discovery (`-sS -Pn`), service version enumeration (`-sV`), and script scans (`--script`) restricted to a safe script allowlist. Enforces `--max-rate` to throttle network impact.
  - **Nikto Adapter:** Web vulnerability scanner evaluating dangerous files, outdated server banners, and missing headers. Supports SSL toggling and custom port targetting.
  - **OWASP ZAP Adapter:** Interacts with the OWASP ZAP API daemon. Orchestrates context creation, URL inclusion regexes, exclusion regexes, spider scanning, and passive rule evaluation.
- **Enterprise Artifact Importers (Offline Ingestion):**
  - **Tenable Nessus (`.nessus` XML):** Ingests NessusClientData_v2 XML reports with CVSS v2/v3 vectors and plugin output.
  - **Greenbone OpenVAS (`.xml`):** Ingests OpenVAS report exports, mapping NVT OIDs, CVEs, and CVSS scores.
  - **PortSwigger Burp Suite (`.xml`):** Ingests Burp Scanner XML issue exports. Automatically redacts sensitive HTTP headers (`Authorization: Bearer ...`, `Cookie: ...`, `Set-Cookie: ...`) from evidence snippets before storage.
- **XML Security:** All XML parsing is strictly delegated to `defusedxml.ElementTree` to prevent XML Entity Expansion (Billion Laughs) and external entity loading (XXE).

### 3.5. Cross-Tool Correlation & Risk Prioritization
- **Deterministic Correlation Key:** Correlates findings using normalized tuples of `(asset.canonical_ip, asset.port, cve_id | cwe_id | normalized_title)`.
- **Multi-Tool Finding Merging:** When Nmap and Nessus both detect the same CVE on the same port, Cipher-Lens merges them into a single consolidated finding with `status='confirmed'`, combining both evidence records into a verifiable evidence trail.
- **Location Differentiation:** Findings with the same CWE on different URL paths (e.g., `/search` vs `/login`) are intentionally kept separate to preserve remediation clarity, but linked via `related_ids`.
- **Standards Mapping:** Built-in YAML mapping matrix maps CWE identifiers to:
  - OWASP Top 10 (2021 & 2025 Release)
  - NIST SP 800-115 Phase Classification
  - NIST CSF 2.0 Categories (PR.DS, PR.IP, DE.CM)
  - MITRE ATT&CK Enterprise Techniques

### 3.6. Tamper-Evident Hash-Chained Audit Trail & LLM Traces
- **Cryptographic Chaining:** Every state modification, scope registration, scan execution, policy denial, and human approval writes an immutable audit record where:
  $$\text{RowHash}_i = \text{SHA-256}(\text{RowHash}_{i-1} \parallel \text{Timestamp}_i \parallel \text{EventType}_i \parallel \text{Actor}_i \parallel \text{CanonicalJSON}(\text{Payload}_i))$$
- **Database Trigger Defense:** SQLite triggers permanently abort any `UPDATE` or `DELETE` statement executed against the `audit_events` table, guaranteeing physical immutability even against direct SQL queries.
- **Cryptographic Verification:** One-click chain verification validates all SHA-256 links from the genesis block (`0000...`) to the chain head. Any tampering immediately identifies the exact corrupted row.
- **Full LLM Observability:** Every interaction with Gemini logs prompt tokens, completion tokens, duration, model version, exact input prompt, and raw response.

---

## 4. The 6-Page Streamlit Architecture

Cipher-Lens presents an intuitive, dark-themed 6-page workflow that maps directly to standard penetration testing methodology (NIST SP 800-115):

```
+-----------------------------------------------------------------------------------+
|                            Cipher-Lens Web Console                                |
+-----------------------------------------------------------------------------------+
|  [Page 1] Scope Boundary & Target Authorization                                   |
|    - Register IP/CIDR/Hostname boundaries, exclusions, allowed ports and tools.   |
|    - Instant PolicyGate validation and cryptographic audit record creation.       |
+-----------------------------------------------------------------------------------+
|  [Page 2] Natural Language Intake & Conversational Dialogue                       |
|    - Analyst enters intent (e.g. "Assess 127.0.0.1 for web flaws").                |
|    - Multi-turn conversational assistant clarifies scope and refines parameters.  |
|    - One-click Adaptive Plan generation with server-side validation.             |
+-----------------------------------------------------------------------------------+
|  [Page 3] Plan Approvals & Execution Orchestration                                |
|    - Visual hierarchical step execution tree.                                     |
|    - Human-in-the-loop approval gate for intrusive operations.                     |
|    - Live subprocess execution of Nmap, Nikto, and ZAP with real-time logs.       |
+-----------------------------------------------------------------------------------+
|  [Page 4] Findings, Evidence Segregation & Risk Prioritization                    |
|    - Comprehensive vulnerability inventory filtered by tool, severity, status.    |
|    - Verbatim raw scanner evidence snippets strictly segregated from AI notes.    |
|    - Analyst triage workflow (Confirm, False Positive, Accept Risk) with audit.   |
+-----------------------------------------------------------------------------------+
|  [Page 5] Immutable Hash-Chained Audit Log & LLM Traces                           |
|    - Cryptographic verification of audit event chain integrity.                   |
|    - Full LLM trace telemetry: model, tokens, latency, prompt/response inspection.|
|    - Live chaos switches to simulate scanner timeouts or LLM outages.             |
+-----------------------------------------------------------------------------------+
|  [Page 6] Executive & Technical PDF Report Generator                              |
|    - Generates client-ready, NIST/OWASP-compliant ReportLab PDF reports.          |
|    - AI-generated executive summary with server-side hallucination validation.   |
|    - Complete Evidence Index mapping finding IDs to SHA-256 artifact hashes.      |
+-----------------------------------------------------------------------------------+
```

### Detailed Breakdown of the 6 Pages:

#### Page 1: Target Scope & Authorization Registry
- **Purpose:** Enforces legal and contractual Rules of Engagement (ROE) before any packet is transmitted.
- **Features:**
  - Scope Registration Form: Scope ID, Engagement Name, Authorization Ticket / Ticket Reference.
  - Multi-target parser: Accepts IPs (`127.0.0.1`), CIDRs (`10.0.0.0/24`), hostnames (`lab-target.local`), and URLs (`http://127.0.0.1:3000`). Automatically extracts hosts and allowed ports.
  - Exclusion list: Strictly blocks forbidden infrastructure (e.g., gateway `192.168.1.1` or broadcast addresses).
  - Allowed tools selection and validity window definition (start and expiration times).
  - Audit: Every registered scope commits an immutable `scope_registered` event to the audit trail.

#### Page 2: Natural Intake & Conversational Dialogue Assistant
- **Purpose:** Translates high-level analyst requests into structured, verified assessment parameters.
- **Features:**
  - Natural Language Assessment Intake: Parses objectives, targets, and desired scan depth (`quick`, `standard`, `thorough`).
  - Out-of-Scope Target Refusal Banner: If an analyst enters out-of-scope targets (e.g. `8.8.8.8`), the assistant highlights the refusal and records an audit event.
  - Multi-Turn Conversational Assistant: Conversational chat interface allowing the analyst to clarify parameters, discuss ports, or refine testing objectives. Updates the active assessment target dynamically.
  - Adaptive Plan Proposal Generator: Invokes the Gemini Developer API to construct structured `PlanProposal` steps, verified authoritatively by `PolicyGate`.

#### Page 3: Plan Approvals & Subprocess Execution Console
- **Purpose:** Bridges automated planning and live execution with human governance.
- **Features:**
  - Hierarchical Step Tree: Displays each proposed step with tool, target, action class badge, NIST phase, rationale, and cited evidence triggers.
  - Human Approval Gate: Scans categorized as `INTRUSIVE` or `VALIDATION` require explicit analyst approval before execution can proceed.
  - Subprocess Runner Console: Executes approved tools sequentially in asynchronous background processes without shell invocation.
  - Real-time Status Tracking: Automatically updates step lifecycle from `pending` $\to$ `running` $\to$ `completed` or `failed`.
  - Replay Synthetic Fixtures: Allows one-click offline replaying of synthetic scanner outputs for dry-run testing.

#### Page 4: Findings, Evidence-Inference Segregation & Risk Prioritization
- **Purpose:** Centralized vulnerability triage workbench.
- **Features:**
  - Comprehensive Filtering: Filter findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), status (`CONFIRMED`, `SUSPECTED`, `FALSE_POSITIVE`, `RISK_ACCEPTED`), and source tool.
  - Segregated Detail Cards:
    - **Observed Evidence:** Exact tool name, asset location, port, and verbatim raw output snippet with SHA-256 artifact hash.
    - **Standards Context:** Associated CWE, OWASP Top 10 category, and NIST CSF alignment.
    - **Remediation Roadmap:** Concrete mitigation steps.
  - Analyst Triage Workflow: Update finding status with required rationale, immediately recorded to the audit log.

#### Page 5: Immutable Hash-Chained Audit Log & LLM Traces
- **Purpose:** Complete governance, verification, and observability.
- **Features:**
  - One-Click Chain Verifier: Traverses the SHA-256 chain from genesis to head, rendering a tamper-evident status badge.
  - Event Explorer: Inspect timestamp, actor, event type, and canonical JSON payload for every action.
  - LLM Trace Explorer: Review every prompt sent to Gemini, raw JSON completion, latency, and token consumption.
  - Chaos Injection Switchboard: Test platform resilience by toggling simulated scanner timeouts, ZAP process terminations, or LLM outages.

#### Page 6: Executive & Technical PDF Report Generator
- **Purpose:** Generates official, publication-ready security audit deliverables.
- **Features:**
  - Grounded Executive Summary: Generates high-level risk overview using Gemini, strictly validated against real findings. Replaces placeholder text with an authentic `[AI-GENERATED · EVIDENCE-GROUNDED]` badge.
  - Scope & Methodology Documentation: Records engagement parameters, time windows, and authorized tools.
  - Finding Details & Remediation Tables: Fully formatted vulnerability catalog with CVSS v3.1 scores.
  - Cryptographic Evidence Index: Complete table linking every finding ID to its source tool, artifact locator, and SHA-256 hash.
  - One-Click PDF Download: Generates a ReportLab PDF deliverable ready for executive presentation.

---

## 5. Security & Safety Invariants Summary

Cipher-Lens enforces 15 unbreakable safety invariants across its entire codebase:

1. **Zero `shell=True`:** No command is ever executed via a shell interpreter or built using string formatting.
2. **Deterministic Policy Gate:** No scanner command can run without explicit `PolicyGate.authorize()` clearance.
3. **Evidence-Inference Segregation:** Scanner outputs and AI inferences are separate fields and never commingled.
4. **No Hallucinated CVEs:** A CVE may appear only if reported by a tool or returned from an authoritative NVD query.
5. **XML Hardening:** All XML parsing is strictly performed using `defusedxml`.
6. **Immutable Audit Chain:** All state changes generate SHA-256 hash-chained audit events protected by SQLite triggers.
7. **Artifact Hash Integrity:** Raw tool outputs are preserved unmodified with SHA-256 hashes.
8. **Credential Redaction:** Passwords, API tokens, and cookies are redacted before logging or storage.
9. **Private Range Defense:** Public IP scanning is denied unless explicitly authorized.
10. **Cloud Metadata Blocked:** Access to `169.254.169.254` is permanently hard-denied.
11. **DNS Rebinding Protection:** Target domains are resolved and pinned prior to execution.
12. **Idempotent Step Execution:** Scans are tracked by idempotency keys to prevent duplicate execution.
13. **Human Approval Checkpoints:** Intrusive actions require manual authorization.
14. **Downward Dependency Flow:** Dependencies flow strictly downward: UI $\to$ Orchestrator $\to$ Policy/Adapters $\to$ Store/Models.
15. **Transparent Fallbacks:** When offline or in fallback mode, outputs are clearly labeled.

---

## 6. Live Target Demonstration: OWASP Juice Shop Runbook

To demonstrate Cipher-Lens live against the authorized practice target (OWASP Juice Shop), follow these exact steps:

### Step 1: Start OWASP Juice Shop Docker Container
```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```
Verify Juice Shop is accessible locally by navigating to `http://127.0.0.1:3000` in your web browser.

### Step 2: Launch Streamlit Application
```bash
# In the Cipher-Lens project root
.venv\Scripts\streamlit run src/cipher_lens/ui/app.py
```
Open `http://localhost:8501` in your browser. Log in as an **Operator** using token `test-admin-secret-token-123456`.

### Step 3: Register Authorized Lab Scope (Page 1)
1. Navigate to **1. Scope Boundary**.
2. Enter Scope ID: `scope-juice-shop`
3. Enter Name: `OWASP Juice Shop Practice Lab`
4. Enter Targets: `127.0.0.1, http://127.0.0.1:3000`
5. Enter Allowed Ports: `3000, 80, 443`
6. Click **Register Authorized Scope**.

### Step 4: Initiate Assessment & Converse (Page 2)
1. Navigate to **2. Natural Intake & Plan**.
2. Under "Start New Assessment", enter Title: `Juice Shop Security Audit`
3. Enter Request: `Please perform a security assessment on target 127.0.0.1 on port 3000 for open services and web flaws.`
4. Select Scope: `scope-juice-shop` and click **Submit Request & Parse Scope**.
5. Use the conversational assistant to verify parameters, then click **Generate Adaptive Plan 🧠**.
6. The Gemini Developer API will propose Step 1: `nmap` discovery on port 3000.

### Step 5: Execute Approved Steps (Page 3)
1. Navigate to **3. Plan Approvals & Execution**.
2. Review the proposed Nmap discovery step.
3. Click **Execute Approved Steps 🚀**.
4. Nmap executes live against `127.0.0.1:3000`. The service is discovered, and raw evidence is cryptographically stored.

### Step 6: Generate Adaptive Follow-Up Plan (Page 2 $\to$ Page 3)
1. Return to **2. Natural Intake & Plan** and click **Generate Adaptive Plan 🧠**.
2. Gemini evaluates the newly recorded observation on port 3000 and generates Step 2: `nikto` web assessment on `127.0.0.1:3000`.
3. Return to **3. Plan Approvals & Execution** and execute Step 2 live against Juice Shop.

### Step 7: Review Findings & Generate Report (Pages 4 & 6)
1. Navigate to **4. Findings & Risk Prioritization** to inspect real discovered web vulnerabilities, headers, and endpoints.
2. Navigate to **5. Audit Log & LLM Traces** and click **Verify Audit Trail Integrity** to confirm the SHA-256 chain is 100% intact.
3. Navigate to **6. Executive PDF Report** and click **Generate Unified VAPT Report 📄**.
4. Download the generated PDF report complete with executive summary, CVSS v3.1 scoring, and cryptographic evidence index.
