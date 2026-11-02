# Cipher-Lens decisions log

Every decision that changes how we build goes here with a date and a reason. Newest at the bottom.

| Date | Decision | Reason |
|---|---|---|
| 2026-11-02 | Python 3.12 on every machine, in a project-local `.venv` (`py -3.12 -m venv .venv`); ruff target `py312` | Matches AGENTS.md, CI and the master plan |
| 2026-11-02 | `src/` layout installed with `pip install -e .`; pytest uses `pythonpath = ["src"]` | Imports behave the same in tests, CLI and CI |
| 2026-11-02 | `requirements.txt` keeps version ranges; exact versions of the working environment are in `requirements-lock.txt` (`pip freeze --exclude-editable`) | Reproducible installs without hiding intent |
| 2026-11-02 | `main` is the default, protected branch: no direct pushes, PR with 1 approval from the other person, squash merge, delete branch | Two-person review (plan section 16.3) |
| 2026-11-02 | CI (`.github/workflows/ci.yml`, job `test`) runs ruff and offline pytest only; it never scans and uses no secrets | Plan section 4.1 |
| 2026-11-02 | Authorization reference for the local practice target: "self-hosted practice target" | Plan section 5.1 |
| 2026-11-02 | Integrations as in plan section 1: live = Nmap, Nikto, ZAP; import-only = Nessus, OpenVAS/Greenbone, Burp; manual = Metasploit | Honest and achievable |
| 2026-11-02 | Audit log hash chaining detects row edits, middle deletions, and reordering; `expected_head_hash` anchor protects against tail tampering | Security & tamper-evidence transparency |
| 2026-11-02 | EventPublisher allows broad `except Exception` only inside subscriber execution so subscriber failures never break committed audit transactions | Isolation of audit storage from presentation/pub-sub |
| 2026-11-02 | PolicyGate fails closed on DNS resolution: all resolved IPs must be in-scope, and exclusions beat allows | Prevents DNS rebinding and out-of-scope scanning |
| 2026-11-02 | Scope with `allowed_ports` requires an authorized port; port=None is rejected to prevent unrestricted port scanning | Boundary enforcement |
| 2026-11-02 | Credentials in target URLs are redacted prior to audit logging | Zero plain-text credentials in logs (AGENTS.md rule 9) |
| 2026-11-02 | Approval decisions are final and immutable; a rejected step cannot be updated in-place (a new step must be proposed) | Human-in-the-loop integrity and auditability |

| 2026-11-03 | Day 1 contracts freeze: `models/findings.py`, `models/plan.py`, `models/observations.py`, `models/approvals.py` are frozen; no field renames or removals until Day 2 retrospective review | All Person A (policy/gate/approvals/audit) and Person B (adapters/store/vertical-slice) Day 1 components import from these models; breaking changes require joint PR review from both persons |
| 2026-11-03 | Vertical slice integration test (`tests/test_vertical_slice.py`) is the Day 1 gate; it must pass on `main` before Day 2 work begins | Ensures A+B components compose correctly end-to-end with no fabricated data |
| 2026-11-03 | Audit log UPDATE/DELETE is blocked at the SQLite trigger level (`audit_log_no_update`, `audit_log_no_delete` triggers) as the primary tamper barrier; hash-chain `verify_chain()` is a secondary integrity check | Trigger-level blocking catches both accidental and adversarial modifications before they are committed to disk |
| 2026-11-03 | `NmapAdapter.parse()` uses defusedxml exclusively; standard library `xml.etree.ElementTree` is never used for any tool output | AGENTS.md rule 6: parse all XML with defusedxml |
| 2026-11-03 | CVE IDs are only emitted from `RawFinding.cve` if the tool's output string contains a matching `CVE-YYYY-NNNNN` pattern; no inference or lookup at parse time | AGENTS.md rule 3: never fabricate CVE IDs |
| 2026-11-03 | Subprocess execution uses argv lists exclusively via asyncio.create_subprocess_exec (no shell=True); timeouts kill the entire process group (POSIX: killpg, Windows: taskkill /F /T /PID) | AGENTS.md Rule 1 & Master Plan A5: prevents command injection and orphan scanner processes |
| 2026-11-03 | Every tool run goes through PolicyGate authorization and ApprovalManager requirements before any subprocess is spawned; raw output is stored unmodified with SHA-256 | AGENTS.md Rule 2 & Rule 8: execution choke point enforcement |
| 2026-11-03 | ZAP adapter uses httpx with X-ZAP-API-Key header, restricts context regex strictly to target URL with exclusions, and enforces per-step human approval prior to active scan | AGENTS.md Rule 2 & Master Plan A6: prevents off-target scanning and unauthorized intrusive web attacks |
| 2026-11-03 | Sensitive CLI flags and URLs in argv are redacted before audit storage; task cancellations terminate the process group | AGENTS.md Rule 7, 9 & CodeRabbit review fixes |

## Open items to fill in
- Gemini free-tier model IDs and limits (requests per minute, tokens per minute, requests per day) from AI Studio, plan section 4.2.
- Lab target and exact scope from the organizers, once confirmed.
- GitHub Actions versions: currently `actions/checkout@v6` and `actions/setup-python@v6`; check for newer majors.
