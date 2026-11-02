# DECISION: NVD CVE 2.0 responses are parsed strictly for CVSS v3.1, v3.0, and v2.0 metrics; if no CVSS metric is provided, score is set to None rather than guessed.
"""NVD CVE API 2.0 client and CVSS parser."""

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from cipher_lens.models.findings import CvssInfo


@dataclass
class NvdRecord:
    """Enrichment record parsed from NVD CVE API 2.0."""

    cve_id: str
    cvss: CvssInfo | None
    cwe_ids: list[str] = field(default_factory=list)
    description: str | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))


async def fetch_nvd_cve(
    cve_id: str,
    *,
    client: httpx.AsyncClient | None = None,
    api_key: str | None = None,
    timeout: float = 10.0,
) -> NvdRecord | None:
    """Queries NVD CVE API 2.0 for a tool-reported CVE ID.

    Never invents scores or descriptions; returns None if CVE is not indexed by NVD.
    """
    key = api_key or os.environ.get("CIPHER_LENS_NVD_API_KEY")
    headers = {}
    if key:
        headers["apiKey"] = key

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    should_close = client is None
    http_client = client or httpx.AsyncClient(timeout=timeout, headers=headers)

    try:
        resp = await http_client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
    finally:
        if should_close:
            await http_client.aclose()

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve_data = vulnerabilities[0].get("cve", {})

    # Extract Description
    description: str | None = None
    descriptions = cve_data.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value")
            break
    if not description and descriptions:
        description = descriptions[0].get("value")

    # Extract CWEs
    cwe_ids: list[str] = []
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwe_ids:
                cwe_ids.append(val)

    # Extract CVSS (prefer v3.1, then v3.0, then v2.0)
    cvss_info: CvssInfo | None = None
    metrics = cve_data.get("metrics", {})

    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        v31 = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_info = CvssInfo(
            score=float(v31.get("baseScore", 0.0)),
            version=str(v31.get("version", "3.1")),
            vector=v31.get("vectorString"),
            source="nvd",
        )
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        v30 = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_info = CvssInfo(
            score=float(v30.get("baseScore", 0.0)),
            version=str(v30.get("version", "3.0")),
            vector=v30.get("vectorString"),
            source="nvd",
        )
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_info = CvssInfo(
            score=float(v2.get("baseScore", 0.0)),
            version=str(v2.get("version", "2.0")),
            vector=v2.get("vectorString"),
            source="nvd",
        )

    return NvdRecord(
        cve_id=cve_id,
        cvss=cvss_info,
        cwe_ids=cwe_ids,
        description=description,
        fetched_at=datetime.now(UTC),
    )
