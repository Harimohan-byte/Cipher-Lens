# Cipher-Lens Operations Runbook

**Version:** 1.0.0 (Release)  
**Classification:** Authorized Lab Operations & Deployment  

---

## 1. Quick Start Guide

### 1.1 Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux.
- **Python:** Python 3.12 (strictly required across all development, test, and CI environments per AGENTS.md).
- **Package Manager:** `pip` or `uv`.
- **Target Environment:** Authorized practice targets running locally (e.g. Docker Juice Shop or DVWA).

### 1.2 Environment Setup
```powershell
# 1. Clone the repository
git clone https://github.com/Harimohan-byte/Cipher-Lens.git
cd Cipher-Lens

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
pip install -e .
```

### 1.3 Environment Variables Configuration
Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```
Key configuration parameters:
```ini
# LLM Providers: gemini | none (or offline for deterministic rule-based planning)
LLM_PROVIDER=gemini
GEMINI_API_KEY_PRIMARY=your_primary_gemini_key
GEMINI_API_KEY_SECONDARY=your_secondary_failover_key

# Optional NVD API Key (elevates NIST rate limits from 5 to 50 req/30s)
NVD_API_KEY=your_nvd_api_key

# Storage paths
CIPHER_LENS_DB_PATH=local_data/cipher_lens.db
CIPHER_LENS_ARTIFACTS_DIR=local_data/artifacts
CIPHER_LENS_REPORTS_DIR=local_data/reports
```

### 1.4 Launching the Application
```powershell
streamlit run src/cipher_lens/ui/app.py
```
The operator dashboard will open at `http://localhost:8501`.

---

## 2. Practice Target Deployment

All testing must be conducted strictly on self-hosted, authorized practice targets.

### 2.1 OWASP Juice Shop (Target Port 3000)
```powershell
# Start container bound to loopback only
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# Verify target availability
curl http://127.0.0.1:3000
```

### 2.2 Damn Vulnerable Web Application (DVWA) (Target Port 8080)
```powershell
docker run -d --name dvwa -p 127.0.0.1:8080:80 ghcr.io/digininja/dvwa:latest
```

---

## 3. End-to-End Operational Workflow

### Page 1: Scope Boundary Registration
1. Navigate to **Page 1: Scope Boundary**.
2. Define:
   - Target Host: `127.0.0.1`
   - Allowed Ports: `3000` (or `8080`)
   - Allowed Tools: `nmap`, `nikto`, `zap`
   - Authorization Reference: `self-hosted practice target`
   - Testing Window: Valid start and expiration times.
3. Click **Register Scope Boundary**. The deterministic `PolicyGate` enforces these bounds across all downstream execution.

### Page 2: Natural Intake & Assessment Plan
1. Navigate to **Page 2: Natural Intake & Plan**.
2. Enter an objective, e.g.:
   `"Conduct a non-destructive vulnerability assessment against 127.0.0.1 port 3000 to identify open services and web vulnerabilities."`
3. Click **Generate Assessment Plan**.
4. The system validates the objective against prompt-injection filters, evaluates scope constraints, queries the Gemini LLM (or deterministic fallback), and generates an authoritative multi-step plan.

### Page 3: Approvals, Tool Execution & Replay
1. Navigate to **Page 3: Approvals & Tool Execution**.
2. **Human Approval Gate:** Any intrusive steps (e.g. ZAP Active Scan) require lead approval. Review the rationale and click **Approve Step Gate**.
3. **Execution:** Click **Execute Approved Plan**. Tool adapters execute asynchronously via dedicated subprocesses.
4. **Offline Replay Mode:** In environments with no network or live scanners, enable **Replay Mode (Offline Artifact Pipeline)** to parse, correlate, and score recorded scanner artifacts. All results are visibly marked as `replayed`.

### Page 4: Findings, Standards Mapping & Triage
1. Navigate to **Page 4: Correlated Findings**.
2. Filter findings by Severity, Status, or Tool; sort by 0–100 Risk Score.
3. Review the strict separation of **Observed Scanner Evidence** (with SHA-256 hashes) from **AI Inferences**.
4. View mapped **OWASP Top 10 (2021)** and **CISA KEV Boost** badges.
5. **Human Triage Overrides:** Mark false positives or accept risks with mandatory rationale. Every action commits atomically to the hash-chained audit log.
6. **Manual Lab Validation Gate (Task A13):** Request lead approval for manual test reproduction, conduct the test safely in your local lab, and attest the outcome with an attached evidence artifact. (Platform strictly blocks Metasploit payloads).

### Page 5: Immutable Audit Log & LLM Traces
1. Navigate to **Page 5: Immutable Audit Log & LLM Traces**.
2. Click **Verify Audit Integrity**. The system iterates through all cryptographic SHA-256 links from genesis to head hash.
3. Inspect raw SQLite audit events and complete LLM query traces (prompt hash, model, latency, response).

### Page 6: Executive Assessment Report (PDF)
1. Navigate to **Page 6: Executive Assessment Report**.
2. Select the assessment and click **Generate Official PDF Report**.
3. The report assembler compiles real assessment records, tool runs, evidence index, and grounded executive summaries into a publication-ready NIST SP 800-115 PDF document.

---

## 4. Failure Modes & Chaos Engineering Drills

Cipher-Lens incorporates fault injection toggles on Page 3 to test platform resilience:

| Chaos Switch | Simulated Fault | Expected Platform Response |
|---|---|---|
| `kill_zap_mid_scan` | Simulates crash or SIGKILL of ZAP process. | Runner captures timeout/exit code, records failure event, marks step failed, and continues assessment without hang. |
| `slow_nmap` | Induces artificial latency exceeding step timeout. | Process group is cleanly killed (`taskkill /F /T` or `killpg`); partial output is recorded. |
| `malformed_xml` | Injects corrupt or truncated XML into parser. | `defusedxml` rejects input cleanly without crashing; error is logged in step run. |
| `llm_down` | Simulates Google Gemini API outage / 429 quota exhaustion. | Dual-key failover attempts secondary key; upon complete outage, seamlessly falls back to rule-based planner with a visible UI banner. |
| `nvd_down` | Simulates NIST NVD / EPSS endpoint failure. | Service falls back to offline SQLite cache for KEV/EPSS and marks NVD lookups as `enrichment_unavailable` without guessing or fabricating CVSS scores (AGENTS.md Rule 3). |

---

## 5. Security & Safety Invariants Checklist

Prior to conducting any assessment:
- [x] Verify target is strictly within authorized loopback/private range.
- [x] Ensure `PolicyGate` has registered the exact authorized port.
- [x] Confirm no `shell=True` or dynamic string execution exists.
- [x] Ensure all XML outputs are parsed with `defusedxml`.
- [x] Verify that audit log hash chain reports `Chain verified successfully`.
