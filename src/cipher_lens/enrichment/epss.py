# DECISION: FIRST EPSS queries are bounded by explicit timeouts; missing or offline EPSS scores return None rather than synthetic defaults.
"""FIRST EPSS (Exploit Prediction Scoring System) client."""

import urllib.parse

import httpx


async def fetch_epss(
    cve_id: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
) -> tuple[float | None, float | None]:
    """Fetches EPSS probability score and percentile for a CVE ID.

    Returns (epss_score, percentile) or (None, None) if not available.
    """
    safe_cve = urllib.parse.quote(cve_id.strip())
    url = f"https://api.first.org/data/v1/epss?cve={safe_cve}"
    should_close = client is None
    http_client = client or httpx.AsyncClient(timeout=timeout)

    try:
        resp = await http_client.get(url)
        resp.raise_for_status()
        data = resp.json()
        records = data.get("data", [])
        if not records:
            return None, None
        record = records[0]
        score = float(record.get("epss")) if record.get("epss") is not None else None
        percentile = float(record.get("percentile")) if record.get("percentile") is not None else None
        return score, percentile
    finally:
        if should_close:
            await http_client.aclose()
