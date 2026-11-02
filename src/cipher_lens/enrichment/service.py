# DECISION: Enrichment lookups strictly validate CVE ID format (^CVE-\\d{4}-\\d{4,7}$); arbitrary query parameters are blocked.
# DECISION: When offline or remote APIs fail, results are marked 'not_found' or 'enrichment_unavailable' and never populated with fabricated data.
"""Unified vulnerability enrichment service coordinating NVD, KEV, EPSS, and caching."""

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from cipher_lens.enrichment.cache import SqliteTtlCache
from cipher_lens.enrichment.epss import fetch_epss
from cipher_lens.enrichment.kev import KevCatalog
from cipher_lens.enrichment.nvd import fetch_nvd_cve
from cipher_lens.models.findings import CvssInfo

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class CveEnrichment(BaseModel):
    """Enriched vulnerability context combining NVD, KEV, and EPSS."""

    cve_id: str
    cvss: CvssInfo | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str | None = None
    cisa_kev: bool = False
    cisa_kev_due_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    status: Literal["enriched", "not_found", "enrichment_unavailable"] = "enriched"
    source: str = "nvd_kev_epss"
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EnrichmentService:
    """Coordinates CVE enrichment across NVD, CISA KEV, FIRST EPSS with TTL caching."""

    def __init__(
        self,
        cache: SqliteTtlCache | None = None,
        client: httpx.AsyncClient | None = None,
        kev_catalog: KevCatalog | None = None,
        offline_mode: bool = False,
        snapshots_dir: Path | str | None = None,
        cache_ttl_seconds: float = 604800.0,  # 7 days
    ) -> None:
        self.cache = cache or SqliteTtlCache()
        self.client = client
        self.kev_catalog = kev_catalog or KevCatalog()
        self.offline_mode = offline_mode
        self.snapshots_dir = Path(snapshots_dir) if snapshots_dir else None
        self.cache_ttl_seconds = cache_ttl_seconds

    async def enrich_cve(self, cve_id: str) -> CveEnrichment:
        """Enriches a tool-reported CVE ID.

        Invariants:
        1. Validates CVE regex; rejects malformed inputs.
        2. Serves cache hits before attempting network queries.
        3. Never fabricates CVSS or exploitability metrics.
        """
        clean_cve = cve_id.strip().upper()
        if not CVE_REGEX.match(clean_cve):
            raise ValueError(f"Invalid CVE ID format: '{cve_id}'")

        # 1. Check TTL Cache (Live mode only; offline lookups never read from or write to the live cache)
        if not self.offline_mode:
            cached_dict = self.cache.get(clean_cve)
            if cached_dict is not None:
                try:
                    return CveEnrichment.model_validate(cached_dict)
                except Exception:
                    self.cache.delete(clean_cve)

        now = datetime.now(UTC)

        # 2. Offline Mode (Strictly reads from local snapshots, never poisons the live cache)
        if self.offline_mode:
            is_kev = self.kev_catalog.is_known_exploited(clean_cve)
            due_date = self.kev_catalog.get_due_date(clean_cve)

            # Check local snapshot
            if self.snapshots_dir:
                snapshot_file = self.snapshots_dir / f"{clean_cve}.json"
                if snapshot_file.exists():
                    try:
                        snap_data = json.loads(snapshot_file.read_text(encoding="utf-8"))
                        cvss_obj = (
                            CvssInfo.model_validate(snap_data["cvss"])
                            if snap_data.get("cvss")
                            else None
                        )
                        return CveEnrichment(
                            cve_id=clean_cve,
                            cvss=cvss_obj,
                            cwe_ids=snap_data.get("cwe_ids", []),
                            description=snap_data.get("description"),
                            cisa_kev=is_kev,
                            cisa_kev_due_date=due_date,
                            epss_score=snap_data.get("epss_score"),
                            epss_percentile=snap_data.get("epss_percentile"),
                            status="enriched",
                            source="offline_snapshot",
                            fetched_at=now,
                        )
                    except Exception:
                        pass

            # If not in snapshot, return not_found without caching
            return CveEnrichment(
                cve_id=clean_cve,
                cisa_kev=is_kev,
                cisa_kev_due_date=due_date,
                status="enriched" if is_kev else "not_found",
                source="offline_catalog",
                fetched_at=now,
            )

        # 3. Live Mode (Ensure KEV is fresh, then query NVD and EPSS)
        await self.kev_catalog.ensure_fresh(self.client)
        is_kev = self.kev_catalog.is_known_exploited(clean_cve)
        due_date = self.kev_catalog.get_due_date(clean_cve)

        try:
            nvd_record, (epss_score, epss_percentile) = await asyncio.gather(
                fetch_nvd_cve(clean_cve, client=self.client),
                fetch_epss(clean_cve, client=self.client),
            )
        except Exception:
            # Network failure or service downtime -> return enrichment_unavailable without guessing
            result = CveEnrichment(
                cve_id=clean_cve,
                status="enrichment_unavailable",
                source="error",
                fetched_at=now,
            )
            return result

        if nvd_record is None and epss_score is None and not is_kev:
            result = CveEnrichment(
                cve_id=clean_cve,
                status="not_found",
                source="nvd",
                fetched_at=now,
            )
            self.cache.set(clean_cve, result.model_dump(mode="json"), ttl_seconds=3600.0)
            return result

        result = CveEnrichment(
            cve_id=clean_cve,
            cvss=nvd_record.cvss if nvd_record else None,
            cwe_ids=nvd_record.cwe_ids if nvd_record else [],
            description=nvd_record.description if nvd_record else None,
            cisa_kev=is_kev,
            cisa_kev_due_date=due_date,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            status="enriched",
            source="nvd_kev_epss",
            fetched_at=now,
        )
        self.cache.set(clean_cve, result.model_dump(mode="json"), ttl_seconds=self.cache_ttl_seconds)
        return result
