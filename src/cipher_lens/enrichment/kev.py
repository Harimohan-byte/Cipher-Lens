# DECISION: CISA KEV catalog is checked against a local snapshot with optional remote refresh; offline mode uses local snapshot exclusively.
"""CISA Known Exploited Vulnerabilities (KEV) catalog checker."""

import json
import logging
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_SNAPSHOT_PATH = Path("samples/cisa_kev_sample.json")


def _is_sample_path(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        if path.exists() and DEFAULT_SNAPSHOT_PATH.exists():
            return path.samefile(DEFAULT_SNAPSHOT_PATH)
    except OSError:
        pass
    normalized = str(path).replace("\\", "/")
    return normalized.endswith("samples/cisa_kev_sample.json")


class KevCatalog:
    """Manages CISA KEV catalog membership checks."""

    def __init__(
        self,
        snapshot_path: Path | str | None = None,
        retry_delay_seconds: float = 300.0,
    ) -> None:
        self._is_default_sample = False
        if snapshot_path is not None:
            self.snapshot_path = Path(snapshot_path)
            self._is_default_sample = _is_sample_path(self.snapshot_path)
        elif DEFAULT_SNAPSHOT_PATH.exists():
            self.snapshot_path = DEFAULT_SNAPSHOT_PATH
            self._is_default_sample = True
        else:
            self.snapshot_path = None

        self._retry_delay_seconds = retry_delay_seconds
        self._kev_set: set[str] = set()
        self._due_dates: dict[str, str] = {}
        self._loaded_at: float | None = None
        self._refreshed_at: float | None = None
        self._last_refresh_attempt: float = 0.0
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

                # Preserve the snapshot's actual freshness using file modification time.
                # Default synthetic sample is never treated as a fresh live catalog.
                if self._is_default_sample:
                    self._loaded_at = None
                    self._refreshed_at = None
                else:
                    mtime = self.snapshot_path.stat().st_mtime
                    self._loaded_at = mtime
                    self._refreshed_at = mtime
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Failed to load CISA KEV snapshot from %s: %s", self.snapshot_path, exc
                )

    async def refresh_remote(self, client: httpx.AsyncClient | None = None) -> bool:
        """Refreshes the catalog from the official CISA feed."""
        self._last_refresh_attempt = time.time()
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
            now = time.time()
            self._loaded_at = now
            self._refreshed_at = now
            self._is_default_sample = False

            # Save snapshot if path provided and not pointing to the static sample
            if self.snapshot_path and not _is_sample_path(self.snapshot_path):
                self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                self.snapshot_path.write_text(json.dumps(data), encoding="utf-8")
            return True
        except Exception as exc:
            logger.warning("Remote CISA KEV refresh failed: %s", exc)
            return False
        finally:
            if should_close:
                await http_client.aclose()

    async def ensure_fresh(
        self,
        client: httpx.AsyncClient | None = None,
        max_age_seconds: float = 86400.0,
    ) -> None:
        """Refreshes the catalog if not yet loaded or stale, respecting retry cooldown."""
        now = time.time()
        # Cooldown guard: limit retries after a failed KEV refresh
        if (now - self._last_refresh_attempt) < self._retry_delay_seconds:
            return

        if self._refreshed_at is None or (now - self._refreshed_at) > max_age_seconds:
            await self.refresh_remote(client)

    @property
    def is_empty(self) -> bool:
        """Returns True if the catalog has no indexed vulnerabilities."""
        return len(self._kev_set) == 0

    @property
    def refreshed_at(self) -> float | None:
        """Timestamp of last successful remote refresh."""
        return self._refreshed_at

    def is_known_exploited(self, cve_id: str) -> bool:
        """Returns True if the CVE is in CISA KEV."""
        return cve_id.upper() in self._kev_set

    def get_due_date(self, cve_id: str) -> str | None:
        """Returns the CISA remediation due date if present."""
        return self._due_dates.get(cve_id.upper())
