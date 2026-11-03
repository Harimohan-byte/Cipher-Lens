# Cipher-Lens Architecture Specification

**Version:** 1.0.0 (Release)  
**Classification:** Authorized Lab VAPT Assistant Architecture  
**Standards Conformance:** NIST SP 800-115, OWASP Top 10 (2021), NIST CSF 2.0  

---

## 1. System Overview

Cipher-Lens is an AI-assisted Vulnerability Assessment and Penetration Testing (VAPT) platform designed exclusively for authorized practice environments and educational cyber ranges. It combines automated reconnaissance, deterministic policy enforcement, multi-tool correlation, and human-in-the-loop governance.

The platform ensures that:
- **No intrusive actions occur without human approval.**
- **No automated exploit payloads (e.g. Metasploit) are ever launched by the platform.**
- **All scanner evidence is cryptographically preserved and strictly segregated from AI inferences.**
- **Every state change, command execution, and human decision is immutably recorded in a hash-chained audit log.**

```
                                  +---------------------------------------+
                                  |         Streamlit Web UI / CLI        |
                                  | (6-Page Dashboard & Operator Console) |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |       UI Controller & State           |
                                  +---------------------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |    Intake & Agent Planner     |                         |     Execution Orchestrator    |
         | (Dual Gemini / Rule Fallback) |                         |   (State Machine & Retries)   |
         +-------------------------------+                         +-------------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |     Policy Gate & Scope       |                         |    Tool Runner & Rate Limit   |
         |  (CIDR, DNS, Port, Userinfo)  |                         |  (Subprocess Exec, No Shell)  |
         +-------------------------------+                         +-------------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |    Human Approval Manager     |                         |     Scanner Adapters / Imps   |
         | (Finality & Idempotent Gates) |                         | (Nmap, Nikto, ZAP, Nessus...) |
         +-------------------------------+                         +-------------------------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |    Correlator, Risk & Standards       |
                                  | (0-100 Scoring, KEV, EPSS, OWASP)     |
                                  +---------------------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |   Cryptographic Audit Store   |                         |  Grounded Report Assembler    |
         |  (SQLite Hash Chain & Triggers|                         |  (NIST SP 800-115 ReportLab)  |
         +-------------------------------+                         +-------------------------------+
```

---

## 2. Layered Architecture & Downward Dependencies

Per **AGENTS.md Rule 14**, dependencies flow strictly downward:
`ui -> orchestrator -> policy/adapters/correlate -> store/models`

```
Layer 1: UI & Presentation
  src/cipher_lens/ui/
    ├── app.py                # Streamlit multi-page interface
    ├── findings.py           # Correlated findings view, filters, triage, and validation
    └── state.py              # UIController coordinating backend subsystems

Layer 2: Orchestration & Planning
  src/cipher_lens/orchestrator/
    ├── engine.py             # Asynchronous execution state machine
    ├── runner.py             # Subprocess execution, rate limiting, and process-group isolation
    ├── grounding.py          # GroundingValidator checking hallucinated tokens against SQLite
    ├── chaos.py              # Chaos fault injection switches
    └── replay.py             # Offline artifact replay pipeline
  src/cipher_lens/planner/
    ├── intake.py             # Natural language objective intake and sanitization
    ├── planner.py            # LLM-powered plan generator (Dual-Key Gemini)
    ├── rules_planner.py      # Deterministic fallback progression
    ├── llm.py                # Dual-key client failover (3.8-Flash + 3.5-Flash-Lite)
    └── trace.py              # SQLite LLM prompt and response audit tracing

Layer 3: Policy, Governance & Correlation
  src/cipher_lens/policy/
    ├── scope.py              # Scope boundary registry, CIDR parsing, exclusions, and DNS verification
    ├── gate.py               # Deterministic PolicyGate failing closed on out-of-scope actions
    ├── approvals.py          # ApprovalManager enforcing finality and idempotent approval gates
    └── validation.py         # Manual lab validation outcome recording and evidence attestation
  src/cipher_lens/correlate/
    ├── engine.py             # Vulnerability correlation and canonical key deduplication
    ├── risk.py               # 0-100 reproducible risk scoring engine
    └── standards.py          # Deterministic mappings to OWASP Top 10, NIST CSF, and ATT&CK

Layer 4: Adapters & Enrichment
  src/cipher_lens/adapters/
    ├── base.py               # BaseAdapter, ExecutionContext, and lifecycle contracts
    ├── nmap.py               # Nmap scanner adapter (defusedxml XML parser)
    ├── nikto.py              # Nikto web scanner adapter
    ├── zap.py                # OWASP ZAP API adapter (spider, passive, active scan)
    └── importers.py          # Import-only adapters (Nessus, OpenVAS, Burp Suite XML/JSON)
  src/cipher_lens/enrichment/
    ├── service.py            # Enrichment coordinator with TTL cache
    ├── nvd.py                # NVD API 2.0 CVSS/CWE lookup
    ├── kev.py                # CISA Known Exploited Vulnerabilities catalog
    └── epss.py               # FIRST EPSS exploit probability scores

Layer 5: Storage & Domain Models
  src/cipher_lens/store/
    ├── db.py                 # SQLite connection factory with WAL mode and foreign keys
    ├── tables.py             # Relational schema DDL and append-only triggers
    ├── audit.py              # Cryptographic SHA-256 hash-chained audit log
    ├── repository.py         # Entity repository for assessments, runs, findings, and approvals
    └── artifacts.py          # Immutable artifact store with SHA-256 verification
  src/cipher_lens/models/
    ├── assessment.py         # Assessment, Target, and StepRun schemas
    ├── plan.py               # Plan, PlanStep, and ActionClass definitions
    ├── findings.py           # Finding, Asset, Evidence, Inference, RiskScore, and Validation
    └── approvals.py          # ApprovalRequest and ApprovalDecision contracts
```

---

## 3. Security & Trust Boundaries

Cipher-Lens treats all external inputs as untrusted:

### 3.1 LLM Output Boundary (AGENTS.md Rule 5)
- LLM outputs are treated as untrusted text.
- Generated plans are strictly validated against Pydantic schemas (`AssessmentPlan`).
- Action classes (`ActionClass.RECON`, `ActionClass.DISCOVERY`, `ActionClass.INTRUSIVE`, `ActionClass.VALIDATION`) are assigned or overridden **authoritatively by server-side policy**, never trusted from LLM suggestions.
- All executive summaries generated by LLM pass through `GroundingValidator`. If any CVE ID or finding ID appears that does not exist in the SQLite database, the text is rejected and falls back to a deterministic template.

### 3.2 Tool Output Boundary (AGENTS.md Rule 5 & 6)
- Raw tool outputs (stdout, stderr, XML, JSON) are wrapped in `<tool_output>` delimiters and parsed using safe parsers.
- All XML output (Nmap, Nessus, Burp) is parsed using `defusedxml` to prevent XML External Entity (XXE) and XML bomb attacks.
- Scanner outputs are saved unmodified to the filesystem, and their SHA-256 digest is recorded in `Evidence.raw_sha256`.

### 3.3 Subprocess Execution Boundary (AGENTS.md Rule 1)
- **Zero `shell=True`:** Every scanner adapter constructs command arguments as an explicit `list[str]` of validated tokens.
- No string concatenation is used to build shell commands.
- Commands are executed via `asyncio.create_subprocess_exec`.
- Subprocesses are spawned in dedicated process groups. When timeouts or cancellations occur, the entire process tree is terminated cleanly (`killpg` on POSIX, `taskkill /F /T /PID` on Windows).

### 3.4 Authorization & Policy Boundary (AGENTS.md Rule 2)
- No adapter can execute without explicit validation against `PolicyGate.authorize()`.
- Scope boundaries enforce:
  - Exact IP or CIDR match. Exclusions take precedence over inclusions.
  - DNS resolution validation (all resolved IPs must be within allowed ranges).
  - Port restrictions (unauthorized ports trigger immediate refusal).
  - Time window validity (`valid_from` to `valid_to`).
  - Rate limiting enforcement per target.

### 3.5 Human Approval Boundary (AGENTS.md Rule 2 & Master Plan A4, A13)
- Intrusive actions (e.g. ZAP Active Scan) and Manual Validation actions strictly require human approval via `ApprovalManager`.
- Approval decisions are final and immutable. A denied request cannot be re-decided or overwritten.
- Validation outcomes (confirmed, false positive, accepted risk) require lead approval, analyst attestation, and mandatory evidence artifact uploads.

---

## 4. Cryptographic Non-Repudiation (Hash-Chained Audit Log)

Every mutation within the platform produces an audit event chained via SHA-256:

$$\text{row\_hash}_i = \text{SHA-256}(\text{row\_hash}_{i-1} \,\|\, \text{canonical\_json}(\text{event}_i))$$

- **Trigger Protection:** SQLite database triggers (`audit_log_no_update`, `audit_log_no_delete`) block any modification or deletion of existing audit rows.
- **Atomic Commits:** Database state changes and their corresponding audit events are inserted inside atomic SQLite transactions (`BEGIN IMMEDIATE ... COMMIT`), guaranteeing no un-audited state exists.
- **Verification:** The `verify_audit_chain()` utility verifies every link from genesis (`0`*64) to the current head hash, alerting immediately on missing, altered, or reordered rows.

---

## 5. Prior-Art & Distinctiveness Note (Comparison with PentAGI)

PentAGI and similar autonomous agent frameworks demonstrate the power of LLMs in offensive security workflows. However, Cipher-Lens deliberately diverges from autonomous exploitation paradigms in key architectural ways:

| Feature / Architecture | PentAGI / Autonomous Exploitation Agents | Cipher-Lens Authorized VAPT Platform |
|---|---|---|
| **Autonomous Exploitation** | Uses LLM to select, compile, and fire live exploits (Metasploit, custom payloads). | **Prohibited.** Platform never executes Metasploit or autonomous exploit payloads. Validation is manual by human analyst. |
| **Execution Safety** | Often executes shell strings or dynamic docker code blocks. | **Zero `shell=True`.** Strict argv tokenization and process-group sandboxing. |
| **Target Boundary** | Autonomous URL crawling with potential for off-target drift. | **Fail-Closed PolicyGate.** Strict CIDR, port, exclusion, and DNS rebinding guards. |
| **Human Governance** | Minimal intervention or post-execution reporting. | **Mandatory Approval Gates.** Intrusive actions and validation require lead human sign-off. |
| **Evidence vs Inference** | Inferences often blended into vulnerability descriptions. | **Strict Segregation (Rule 4).** Raw scanner output (with SHA-256) is distinct from untrusted AI inference. |
| **Auditability** | Standard log files or ephemeral agent memory. | **Cryptographic Hash Chain.** Immutable SQLite audit trail with tamper-detection triggers. |
| **Offline Resilience** | Dependent on continuous LLM connectivity. | **Full Replay Mode & Rule Fallback.** Operates completely offline with recorded artifacts and deterministic planning. |

---

## 6. Data Flow: From Intake to Report Generation

1. **Intake:** The operator defines the target and scope parameters. `NaturalIntake` cleans the input and passes it to the `AgentPlanner`.
2. **Planning:** The planner evaluates target state and generates an `AssessmentPlan`. Action classes are authoritatively verified.
3. **Approval:** If any step has `ActionClass.INTRUSIVE` or `ActionClass.VALIDATION`, execution halts until approved by an operator.
4. **Execution:** `ToolRunner` validates the step against `PolicyGate`, enforces rate limits, executes the adapter, stores raw output artifacts, and registers evidence.
5. **Correlation & Scoring:** Discovered vulnerabilities are normalized, deduplicated by `correlation_key`, enriched with KEV/EPSS metrics, and scored (0–100).
6. **Triage & Validation:** Analysts can manually review findings, apply triage overrides, or request manual validation gates.
7. **Report Assembly:** `ReportAssembler` queries all assessment runs, evidence records, and audit events, generates a grounded executive summary, and produces an official NIST SP 800-115 PDF report.
