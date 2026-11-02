# Cipher-Lens – Run Book

> **Scope:** This runbook describes how to set up and operate the Day 1 scanning environment for the Cipher-Lens lab.
> All scan targets must be **authorized practice targets on your local machine only**.
> Never execute any scanner against external or production infrastructure.

---

## 1. Prerequisites

### 1.1 Python Environment

| Requirement | Version | Check |
|---|---|---|
| Python | 3.12+ (3.14 on dev box) | `python --version` |
| uv | 0.11+ | `uv --version` |
| Project venv | `.venv/` in repo root | `.venv\Scripts\python.exe --version` |

```powershell
# Bootstrap on Windows
uv venv .venv
uv pip install -r requirements.txt
.venv\Scripts\pip install -e .
```

### 1.2 Scan Tools (WSL2 / Kali VM)

> **DECISION:** The designated scan machine runs all live tools (Nmap, Nikto, ZAP) inside WSL2 Ubuntu/Kali.
> The Windows host runs the Streamlit UI and SQLite store only.

| Tool | Minimum Version | Install Command | Verify |
|---|---|---|---|
| Nmap | 7.94 | `sudo apt-get install -y nmap` | `nmap --version` |
| Nikto | 2.1.6 | `sudo apt-get install -y nikto` | `nikto -Version` |
| OWASP ZAP | 2.15.0 | Download from zaproxy.org | `zap.sh -version` |

Capture and document your installed versions here once verified:

```
Nmap:   ____________
Nikto:  ____________
ZAP:    ____________
```

---

## 2. Practice Target Setup

> **Authorization Reference:** `"self-hosted practice target"` (recorded in DECISIONS.md, `2026-11-02`)
> All targets run on `localhost` inside Docker. No external traffic is generated.

### 2.1 OWASP Juice Shop (Recommended)

```powershell
# Pull and start Juice Shop bound to localhost only
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# Verify
curl http://localhost:3000
```

- **Target host/IP:** `127.0.0.1`
- **Target port:** `3000`
- **Authorization reference:** `self-hosted practice target`

### 2.2 DVWA (Alternative)

```powershell
docker run -d --name dvwa -p 127.0.0.1:8080:80 ghcr.io/digininja/dvwa:latest
```

---

## 3. Scope Registration

Before running any scan through Cipher-Lens, register the practice target scope in the Python shell or via the CLI:

```python
from datetime import UTC, datetime, timedelta
from cipher_lens.policy.scope import Scope, ScopeRegistry

registry = ScopeRegistry()
registry.register(Scope(
    id="scope-lab-01",
    owner="your-name",
    authorization_reference="self-hosted practice target",
    allowed_targets=["127.0.0.1"],
    exclusions=[],
    allowed_ports=[3000],           # Juice Shop port
    tool_allowlist=["nmap", "nikto", "zap"],
    valid_from=datetime.now(UTC),
    valid_to=datetime.now(UTC) + timedelta(hours=8),
))
```

---

## 4. Running Nmap Discovery (Fixture / Offline Mode)

For development and CI, always use the synthetic fixture. Do not run live scans in CI.

```powershell
# Verify the parser works against the synthetic fixture
.venv\Scripts\pytest tests\adapters\test_nmap_parser.py -v

# Run all offline tests (no live tools, no network)
.venv\Scripts\pytest -q
```

**Live Nmap (WSL2 only, authorized targets only):**

```bash
# Inside WSL2 — replace 127.0.0.1 with the Docker practice target IP
nmap -sV -p 3000 --script=http-title -oX /tmp/nmap_lab.xml 127.0.0.1
```

Then import into Cipher-Lens:
```python
from cipher_lens.store.artifacts import ArtifactStore
store = ArtifactStore()
with open("/tmp/nmap_lab.xml", "rb") as f:
    meta = store.save_raw(f.read(), source_tool="nmap", run_id="run-001", extension="xml")
print(meta.sha256_hash)
```

---

## 5. Offline / Fixture Mode

Set `OFFLINE_MODE=true` in your `.env` to prevent any live tool execution. Adapters in `import_only` or fixture mode will skip `run()` and rely on `parse()` only.

```
OFFLINE_MODE=true
DB_PATH=local_data/cipher_lens.db
RAW_DIR=local_data/artifacts
```

---

## 6. Running Tests and Lint

```powershell
# All tests (offline only, safe to run in CI)
.venv\Scripts\pytest -q

# Lint
.venv\Scripts\ruff check src tests

# Specific test suites
.venv\Scripts\pytest tests\models -v          # Data contracts
.venv\Scripts\pytest tests\store -v           # Artifact store + audit log
.venv\Scripts\pytest tests\policy -v          # Scope gate + approvals
.venv\Scripts\pytest tests\adapters -v        # Nmap parser + base adapter
.venv\Scripts\pytest tests\test_vertical_slice.py -v  # Day 1 integration gate
```

---

## 7. Healthchecks

```python
import asyncio
from cipher_lens.adapters.nmap import NmapAdapter

adapter = NmapAdapter()
result = asyncio.run(adapter.healthcheck())
print(result.status, result.message)
# healthy: Nmap executable found at /usr/bin/nmap
# unavailable: Nmap binary not found on PATH
```

---

## 8. Database

SQLite database lives at `local_data/cipher_lens.db` (gitignored). Initialize with:

```python
from cipher_lens.store.db import connect, init_db
conn = connect()
init_db(conn)
```

---

## 9. Day 2+ Readiness Checklist

- [ ] Nmap version documented (Section 1.2)
- [ ] Nikto version documented
- [ ] ZAP version documented and daemon started (`zap.sh -daemon -port 8080`)
- [ ] Docker practice target running and accessible from WSL2
- [ ] `GEMINI_API_KEY` set in `.env` (obtain from Google AI Studio)
- [ ] `NVD_API_KEY` set in `.env` (obtain from nvd.nist.gov)
- [ ] Practice target scope registered with `allowed_targets=["127.0.0.1"]`
