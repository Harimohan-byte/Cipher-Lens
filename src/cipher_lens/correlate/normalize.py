"""Normalization functions for raw vulnerability findings and assets (B11).

Invariants:
1. Normalize host/IP, ports, URL paths, and vendor severity terms.
2. Extract CVE and CWE strictly via regex validation (AGENTS.md Rule 3).
3. Do not fabricate or invent missing attributes.
"""

from typing import Literal

from cipher_lens.adapters.imports.common import CVE_PATTERN, CWE_PATTERN
from cipher_lens.models.findings import Asset, RawFinding

SEVERITY_MAP: dict[str, Literal["info", "low", "medium", "high", "critical"]] = {
    "0": "info",
    "info": "info",
    "informational": "info",
    "log": "info",
    "none": "info",
    "1": "low",
    "low": "low",
    "2": "medium",
    "medium": "medium",
    "moderate": "medium",
    "3": "high",
    "high": "high",
    "4": "critical",
    "critical": "critical",
}


def normalize_severity(sev: str | None) -> Literal["info", "low", "medium", "high", "critical"]:
    """Maps vendor severity strings to standardized info|low|medium|high|critical."""
    if not sev:
        return "medium"
    clean = str(sev).strip().lower()
    return SEVERITY_MAP.get(clean, "medium")


def normalize_url_path(url_path: str | None) -> str | None:
    """Canonicalizes URL paths by stripping fragments, query parameters, and normalizing slashes."""
    if url_path is None:
        return None
    clean = url_path.strip()
    if not clean:
        return "/"
    # Strip query and fragment
    clean = clean.split("?", 1)[0].split("#", 1)[0]
    # Ensure leading slash
    if not clean.startswith("/"):
        clean = f"/{clean}"
    # Remove trailing slash unless root
    if len(clean) > 1 and clean.endswith("/"):
        clean = clean.rstrip("/")
    return clean


def normalize_asset(asset: Asset) -> Asset:
    """Produces a canonicalized Asset model."""
    host = asset.host.strip().lower()
    ip = asset.ip.strip() if asset.ip else None
    port = asset.port if (asset.port and 1 <= asset.port <= 65535) else None
    protocol = asset.protocol.strip().lower() if asset.protocol else "tcp"
    service = asset.service.strip().lower() if asset.service else None
    url_path = normalize_url_path(asset.url_path)

    return Asset(
        host=host,
        ip=ip,
        port=port,
        protocol=protocol,
        service=service,
        url_path=url_path,
    )


def normalize_finding(raw: RawFinding) -> RawFinding:
    """Normalizes raw finding fields (canonical asset, regex-validated CVE/CWE, standardized severity)."""
    norm_asset = normalize_asset(raw.asset)
    norm_sev = normalize_severity(raw.tool_severity)

    # Validated regex extraction only (AGENTS.md Rule 3: never fabricate CVE/CWE)
    valid_cves: list[str] = []
    for c in raw.cve:
        valid_cves.extend([m.upper() for m in CVE_PATTERN.findall(c)])
    # Also check title and description for CVE patterns
    valid_cves.extend([m.upper() for m in CVE_PATTERN.findall(raw.title)])
    if raw.description:
        valid_cves.extend([m.upper() for m in CVE_PATTERN.findall(raw.description)])

    valid_cwes: list[str] = []
    for w in raw.cwe:
        valid_cwes.extend([m.upper() for m in CWE_PATTERN.findall(w)])

    return RawFinding(
        title=raw.title.strip(),
        asset=norm_asset,
        tool_name=raw.tool_name,
        tool_severity=norm_sev,
        raw_evidence=raw.raw_evidence,
        cve=sorted(dict.fromkeys(valid_cves)),
        cwe=sorted(dict.fromkeys(valid_cwes)),
        description=raw.description,
        solution=raw.solution,
        confidence=raw.confidence,
    )
