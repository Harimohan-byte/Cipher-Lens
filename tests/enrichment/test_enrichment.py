"""Tests for Vulnerability Enrichment Layer (Task A7).

Invariants tested:
1. NVD lookups only for valid tool-reported CVE IDs (AGENTS.md Rule 3).
2. Never fabricate CVSS scores, vectors, or descriptions (AGENTS.md Rule 3).
3. Cache in SQLite with TTL; cache hits avoid network requests.
4. Offline mode uses local snapshots exclusively without outbound network calls.
5. Unknown CVE returns status='not_found', never guesses scores.
6. API failures/timeouts return status='enrichment_unavailable' (Rule 13).
7. CISA KEV detection sets cisa_kev=True for known exploited vulnerabilities.
8. EPSS returns score and percentile.
"""

import json
import time
from pathlib import Path

import httpx
import pytest

from cipher_lens.enrichment.cache import SqliteTtlCache
from cipher_lens.enrichment.epss import fetch_epss
from cipher_lens.enrichment.kev import KevCatalog
from cipher_lens.enrichment.nvd import fetch_nvd_cve
from cipher_lens.enrichment.service import EnrichmentService

# ---------------------------------------------------------------------------
# Synthetic Test Fixtures
# ---------------------------------------------------------------------------

SAMPLE_NVD_CVE_2021_41773 = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {"lang": "en", "value": "CWE-22"}
                        ]
                    }
                ],
            }
        }
    ]
}

SAMPLE_EPSS_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "total": 1,
    "offset": 0,
    "limit": 1,
    "data": [
        {
            "cve": "CVE-2021-41773",
            "epss": "0.97453",
            "percentile": "0.99982",
            "date": "2026-11-01",
        }
    ],
}

SAMPLE_KEV_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.11.01",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
            "dateAdded": "2021-11-03",
            "shortDescription": "Apache HTTP Server contains a path traversal vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-11-17",
        }
    ],
}


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_sqlite_ttl_cache(tmp_path: Path):
    """TTL Cache stores values, returns cache hits, and expires stale entries."""
    db_path = tmp_path / "cache.db"
    cache = SqliteTtlCache(db_path=db_path)

    cache.set("test_key", {"foo": "bar"}, ttl_seconds=1.0)
    hit = cache.get("test_key")
    assert hit == {"foo": "bar"}

    # Non-existent key returns None
    assert cache.get("missing_key") is None

    # Wait for expiration
    time.sleep(1.1)
    expired = cache.get("test_key")
    assert expired is None


@pytest.mark.asyncio
async def test_nvd_fetch_successful():
    """NVD client parses CVSS v3.1, score, vector, CWE, and description."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert "cveId=CVE-2021-41773" in str(request.url)
        return httpx.Response(200, json=SAMPLE_NVD_CVE_2021_41773)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    record = await fetch_nvd_cve("CVE-2021-41773", client=client)

    assert record is not None
    assert record.cvss is not None
    assert record.cvss.score == 7.5
    assert record.cvss.version == "3.1"
    assert record.cvss.source == "nvd"
    assert "CWE-22" in record.cwe_ids
    assert "Apache HTTP Server" in (record.description or "")


@pytest.mark.asyncio
async def test_nvd_unknown_cve_never_invents_scores():
    """Safety: NVD 404 or empty response returns None, never guesses scores."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    record = await fetch_nvd_cve("CVE-9999-0001", client=client)
    assert record is None


@pytest.mark.asyncio
async def test_epss_fetch_successful():
    """EPSS client extracts float score and percentile."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE_EPSS_RESPONSE)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    score, percentile = await fetch_epss("CVE-2021-41773", client=client)

    assert score is not None and abs(score - 0.97453) < 0.0001
    assert percentile is not None and abs(percentile - 0.99982) < 0.0001


def test_cisa_kev_membership(tmp_path: Path):
    """CISA KEV catalog identifies known exploited vulnerabilities."""
    snapshot_path = tmp_path / "cisa_kev_test.json"
    snapshot_path.write_text(json.dumps(SAMPLE_KEV_CATALOG), encoding="utf-8")

    catalog = KevCatalog(snapshot_path=snapshot_path)
    assert catalog.is_known_exploited("CVE-2021-41773") is True
    assert catalog.is_known_exploited("CVE-2099-9999") is False


@pytest.mark.asyncio
async def test_enrichment_service_cache_hit_avoids_network(tmp_path: Path):
    """EnrichmentService caches completed lookups and avoids redundant network calls."""
    cache = SqliteTtlCache(db_path=tmp_path / "cache.db")
    network_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        url_str = str(request.url)
        if "cveId=" in url_str:
            return httpx.Response(200, json=SAMPLE_NVD_CVE_2021_41773)
        if "epss" in url_str:
            return httpx.Response(200, json=SAMPLE_EPSS_RESPONSE)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    snapshot_path = tmp_path / "cisa_kev.json"
    snapshot_path.write_text(json.dumps(SAMPLE_KEV_CATALOG), encoding="utf-8")
    kev = KevCatalog(snapshot_path=snapshot_path)

    service = EnrichmentService(cache=cache, client=client, kev_catalog=kev)

    # First lookup -> makes network calls
    res1 = await service.enrich_cve("CVE-2021-41773")
    assert res1.status == "enriched"
    assert res1.cisa_kev is True
    assert res1.cvss is not None
    assert res1.cvss.score == 7.5
    calls_after_first = network_calls
    assert calls_after_first > 0

    # Second lookup -> served from cache, zero additional network calls
    res2 = await service.enrich_cve("CVE-2021-41773")
    assert res2.status == "enriched"
    assert res2.cisa_kev is True
    assert network_calls == calls_after_first


@pytest.mark.asyncio
async def test_enrichment_service_offline_mode_uses_snapshots(tmp_path: Path):
    """In offline mode, external network calls are blocked and snapshots are used."""
    cache = SqliteTtlCache(db_path=tmp_path / "cache.db")

    # Client that raises if any network call is attempted
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Network calls forbidden in offline mode")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    snapshot_path = tmp_path / "cisa_kev.json"
    snapshot_path.write_text(json.dumps(SAMPLE_KEV_CATALOG), encoding="utf-8")
    kev = KevCatalog(snapshot_path=snapshot_path)

    # Provide local snapshot file for CVE
    snapshots_dir = tmp_path / "cve_snapshots"
    snapshots_dir.mkdir()
    (snapshots_dir / "CVE-2021-41773.json").write_text(
        json.dumps({
            "cve_id": "CVE-2021-41773",
            "cvss": {"score": 7.5, "version": "3.1", "source": "nvd_snapshot"},
            "cwe_ids": ["CWE-22"],
            "description": "Offline snapshot Apache flaw",
            "epss_score": 0.95,
            "epss_percentile": 0.99,
        }),
        encoding="utf-8",
    )

    service = EnrichmentService(
        cache=cache,
        client=client,
        kev_catalog=kev,
        offline_mode=True,
        snapshots_dir=snapshots_dir,
    )

    res = await service.enrich_cve("CVE-2021-41773")
    assert res.status == "enriched"
    assert res.cisa_kev is True
    assert res.cvss is not None
    assert res.cvss.score == 7.5


@pytest.mark.asyncio
async def test_enrichment_service_api_down_records_enrichment_unavailable(tmp_path: Path):
    """When remote APIs fail, result is recorded as enrichment_unavailable; never guessed."""
    cache = SqliteTtlCache(db_path=tmp_path / "cache.db")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("NVD service down")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = EnrichmentService(cache=cache, client=client)

    res = await service.enrich_cve("CVE-2021-41773")
    assert res.status == "enrichment_unavailable"
    assert res.cvss is None  # Never fabricated


@pytest.mark.asyncio
async def test_invalid_cve_format_rejected(tmp_path: Path):
    """Security: Lookups with invalid CVE format are rejected to prevent injection."""
    cache = SqliteTtlCache(db_path=tmp_path / "cache.db")
    service = EnrichmentService(cache=cache)

    with pytest.raises(ValueError, match="Invalid CVE ID format"):
        await service.enrich_cve("NOT-A-CVE-1234")

    with pytest.raises(ValueError, match="Invalid CVE ID format"):
        await service.enrich_cve("CVE-2021-1234; DROP TABLE")
