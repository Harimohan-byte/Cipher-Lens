"""Finding correlation and deduplication engine (B12, Master Plan §8.1).

Rules:
1. Normalize asset/service/URL first.
2. correlation_key = hash(normalized asset + port/protocol or canonical URL path/param + canonical vuln id)
3. Merge only when asset and location match; keep every original finding's evidence and sources.
4. When assets, ports, paths disagree materially, keep findings separate and record related_ids.
5. Invariance §8.1 Rule 5: Never merge distinct affected assets, even with identical titles.
"""

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

from cipher_lens.correlate.normalize import normalize_finding
from cipher_lens.correlate.status import evaluate_status_and_confidence
from cipher_lens.models.findings import Evidence, Finding, RawFinding


def compute_correlation_key(rf: RawFinding) -> str:
    """Computes a deterministic, collision-resistant correlation key for an asset and vulnerability."""
    asset = rf.asset
    # Host or IP anchor
    asset_str = f"{asset.host}|{asset.ip or ''}"
    # Location anchor: port/protocol and url path
    loc_str = f"{asset.port or ''}/{asset.protocol or ''}:{asset.url_path or ''}"

    # Vuln identifier: first CVE if available, else first CWE, else normalized title
    if rf.cve:
        vuln_id = rf.cve[0].upper()
    elif rf.cwe:
        vuln_id = rf.cwe[0].upper()
    else:
        clean_title = "".join(c for c in rf.title.lower() if c.isalnum() or c.isspace()).strip()
        vuln_id = clean_title

    payload = f"{asset_str}#{loc_str}#{vuln_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def correlate_findings(raw_findings: list[RawFinding]) -> list[Finding]:
    """Correlates and deduplicates a list of raw findings across scanners into normalized Findings."""
    if not raw_findings:
        return []

    # Step 1: Normalize all raw findings
    normalized = [normalize_finding(rf) for rf in raw_findings]

    # Step 2: Group by correlation_key
    grouped: dict[str, list[RawFinding]] = defaultdict(list)
    for rf in normalized:
        ckey = compute_correlation_key(rf)
        grouped[ckey].append(rf)

    correlated_findings: list[Finding] = []
    id_counter = 1

    for ckey, group in grouped.items():
        # Sort group by tool_name and observed_at to guarantee order independence
        sorted_group = sorted(
            group,
            key=lambda x: (x.tool_name, x.raw_evidence.observed_at.isoformat()),
        )

        first = sorted_group[0]
        finding_id = f"VAPT-{id_counter:04d}"
        id_counter += 1

        # Combine all evidence records and sources
        all_sources = sorted({rf.tool_name for rf in sorted_group})
        all_evidence: list[Evidence] = []
        for rf in sorted_group:
            all_evidence.append(rf.raw_evidence)

        # Aggregate unique CVEs and CWEs
        all_cves = sorted(dict.fromkeys(c for rf in sorted_group for c in rf.cve))
        all_cwes = sorted(dict.fromkeys(w for rf in sorted_group for w in rf.cwe))

        # Status & confidence evaluation
        status, confidence, reason = evaluate_status_and_confidence(sorted_group)

        # Earliest and latest observation timestamps
        timestamps = [rf.raw_evidence.observed_at for rf in sorted_group]
        first_seen = min(timestamps) if timestamps else datetime.now(UTC)
        last_seen = max(timestamps) if timestamps else datetime.now(UTC)

        correlated_findings.append(
            Finding(
                id=finding_id,
                title=first.title,
                asset=first.asset,
                sources=all_sources,
                evidence=all_evidence,
                inferences=[],
                cve=all_cves,
                cwe=all_cwes,
                cvss=None,  # Enriched in Day 3 A7 / B14
                tool_severity=first.tool_severity,
                confidence=confidence,
                status=status,
                status_reason=reason,
                limitations=[],
                risk=None,
                validation=None,
                correlation_key=ckey,
                related_ids=[],
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    # Step 3: Populate related_ids for findings on same host but different locations/ports
    for i, f1 in enumerate(correlated_findings):
        for j, f2 in enumerate(correlated_findings):
            if i != j and f1.asset.host == f2.asset.host:
                if f2.id not in f1.related_ids:
                    f1.related_ids.append(f2.id)

    return correlated_findings
