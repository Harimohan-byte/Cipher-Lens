# Cipher-Lens

**AI-Assisted Unified VAPT Platform** (Conversational, Human-Supervised Penetration-Testing Assistant)

[![CI](https://github.com/Harimohan-byte/Cipher-Lens/actions/workflows/ci.yml/badge.svg)](https://github.com/Harimohan-byte/Cipher-Lens/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Standards: NIST SP 800-115](https://img.shields.io/badge/Standards-NIST%20SP%20800--115-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-115/final)

---

## Executive Overview

**Cipher-Lens** is an AI-assisted Vulnerability Assessment and Penetration Testing (VAPT) platform designed for authorized lab environments and cyber-ranges. It provides human-in-the-loop governance, automated scope enforcement, multi-tool orchestration, evidence correlation, 0–100 risk scoring with CISA KEV exploitability boosts, and NIST SP 800-115 compliant PDF reporting.

### Core Architecture & Invariants

```
 +---------------------------------------------------------------------------------------+
 |                               Streamlit Multi-Page UI                                 |
 | 1. Scope Boundary | 2. Intake & Plan | 3. Approvals & Exec | 4. Findings | 5. Audit   |
 +---------------------------------------------------------------------------------------+
        |                     |                     |                     |
        v                     v                     v                     v
 +---------------+     +---------------+     +---------------+     +--------------------+
 |  Policy Gate  |     | Agent Planner |     |  Tool Runner  |     | Cryptographic      |
 | (Scope, Ports,|     | (Dual Gemini/ |     | (Subprocess,  |     | Audit Log (SHA-256 |
 |  DNS, Excl.)  |     | Rule Fallback)|     | Process Group)|     | Hash Chain)        |
 +---------------+     +---------------+     +---------------+     +--------------------+
        |                     |                     |                     |
        +---------------------+---------------------+---------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |    Vulnerability Correlator &     |
                     |       0-100 Risk Scoring Engine   |
                     | (CVSS + EPSS + CISA KEV Boosts)   |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |      Grounded Report Assembler    |
                     |  (NIST SP 800-115 PDF Generation) |
                     +-----------------------------------+
```

1. **Zero `shell=True`:** Tool adapters construct `argv` lists from validated parameters. Commands are never built via string formatting or shell interpreters.
2. **Deterministic Choke Point:** Every scan execution must pass `PolicyGate.authorize()` and `ApprovalManager.require()`.
3. **Evidence Integrity & Non-Fabrication:** Observed evidence and AI inferences are strictly segregated. Every finding links back to an immutable raw scanner artifact with a SHA-256 hash.
4. **Human-in-the-Loop Governance:** Intrusive actions (e.g. ZAP Active Scan) and manual validations strictly require operator approval. Approval decisions are final and immutable.
5. **No Automated Exploitation:** The platform **never** executes automated exploit payloads or Metasploit. Validation is conducted manually by the analyst in the authorized lab with attested evidence.
6. **Immutable Audit Trail:** Every state change and decision is cryptographically chained in SQLite using SHA-256 hashes with database-level update/delete prevention triggers.

---

## Scanner Integration Matrix

| Tool | Capability | Mode | Security & Parser Guard |
|---|---|---|---|
| **Nmap** | Host discovery & service enumeration | Live Subprocess | Parsed via `defusedxml` (XXE-safe); argument sanitization |
| **Nikto** | Web server vulnerability scanning | Live Subprocess | Port-restricted execution; non-destructive flags |
| **OWASP ZAP** | Web app spidering, passive & active scan | REST API (`httpx`) | Context-bounded regex; active scan gated by Human Approval |
| **Tenable Nessus** | Enterprise vulnerability assessment | Import-Only | Safe `.nessus` XML import; live execution rejected |
| **Greenbone OpenVAS**| Open-source vulnerability scanning | Import-Only | Safe XML import; live execution rejected |
| **Burp Suite** | Web application security assessment | Import-Only | Safe XML issue import; live execution rejected |
| **Metasploit** | Exploit verification | Manual Only | **Blocked from platform execution.** Lab testing attested by analyst. |

---

## Quick Start Guide

### 1. Installation
```powershell
# Clone the repository
git clone https://github.com/Harimohan-byte/Cipher-Lens.git
cd Cipher-Lens

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1  # On Windows PowerShell
# source .venv/bin/activate  # On Linux / macOS

# Install dependencies and editable package
pip install -r requirements.txt
pip install -e .
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```
Configure your Gemini API keys (supports Dual-Key failover):
```ini
LLM_PROVIDER=gemini
GEMINI_API_KEY_PRIMARY=your_primary_key
GEMINI_API_KEY_SECONDARY=your_secondary_failover_key
```

### 3. Launch the Application
```powershell
streamlit run src/cipher_lens/ui/app.py --server.address 127.0.0.1
```
Open your browser to `http://localhost:8501`.

---

## 6-Page Operator Workflow

1. **Page 1: Scope Boundary:** Register authorized targets (`127.0.0.1`), allowed ports, exclusions, and validity windows.
2. **Page 2: Natural Intake & Plan:** Input high-level test objectives. The AI planner evaluates scope and generates a multi-step plan.
3. **Page 3: Approvals & Execution:** Review and approve intrusive scan steps; monitor live execution or run in **Offline Replay Mode**.
4. **Page 4: Correlated Findings:** Filter, sort, and triage findings; view CISA KEV boosts and OWASP Top 10 mappings; request and record manual lab validations.
5. **Page 5: Immutable Audit Log:** Cryptographically verify the SHA-256 audit chain from genesis to head; inspect raw LLM query traces.
6. **Page 6: Executive Assessment Report:** Generate a publication-ready NIST SP 800-115 PDF report with executive summaries and evidence index.

---

## Testing & Quality Assurance

Run the comprehensive test suite:
```powershell
python -m pytest -q
```
Run static analysis and linting:
```powershell
ruff check src tests
```

---

## Documentation Links

- [Architecture Specification](ARCHITECTURE.md): Full component breakdown, security boundaries, and prior-art comparison.
- [Operations Runbook](RUNBOOK.md): Step-by-step lab deployment, practice targets (Juice Shop / DVWA), and chaos engineering drills.
- [Decisions Log](docs/DECISIONS.md): Chronological record of all architectural decisions.
- [License Attribution](LICENSES.md): Third-party licenses, tool compliance, and data source attributions.
