# DECISION: CISA KEV catalog is checked against a local snapshot with optional remote refresh; offline mode uses local snapshot exclusively.
"""CISA Known Exploited Vulnerabilities (KEV) catalog checker."""

import json
from pathlib import Path

import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevCatalog:
    """Manages CISA KEV catalog membership checks."""

    def __init__(
        self,
        snapshot_path: Path | str | None = None,
    ) -> None:
        self.snapshot_path = Path(snapshot_path) if snapshot_path else None
        self._kev_set: set[str] = set()
        self._due_dates: dict[str, str] = {}
        self._load_snapshot()

    def _load_snapshot(self) -> None:
        if self.snapshot_path and self.snapshot_path.exists():
            try:
                data = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cveID", "").upper()
                    if cve:
                        self._kev_set.add(cve)
                        if "dueDate" in vuln:
                            self._due_dates[cve] = vuln["dueDate"]
            except Exception:
                pass

    async def refresh_remote(self, client: httpx.AsyncClient | None = None) -> bool:
        """Refreshes the catalog from the official CISA feed."""
        should_close = client is None
        http_client = client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http_client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            new_set: set[str] = set()
            new_dates: dict[str, str] = {}
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cveID", "").upper()
                if cve:
                    new_set.add(cve)
                    if "dueDate" in vuln:
                        new_dates[cve] = vuln["dueDate"]
            self._kev_set = new_set
            self._due_dates = new_dates

            # Save snapshot if path provided
            if self.snapshot_path:
                self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                self.snapshot_path.write_text(json.dumps(data), encoding="utf-8")
            return True
        except Exception:
            return False
        finally:
            if should_close:
                await http_client.aclose()

    def is_known_exploited(self, cve_id: str) -> bool:
        """Returns True if the CVE is in CISA KEV."""
        return cve_id.upper() in self._kev_set

    def get_due_date(self, cve_id: str) -> str | None:
        """Returns the CISA remediation due date if present."""
        return self._due_dates.get(cve_id.upper())
