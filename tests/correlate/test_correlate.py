"""Tests for B11: Normalizer, B12: Correlation & Status rules, and B13: Standards mapping.

Invariants to test:
- Normalize host/IP, ports, URL paths, severity vocabulary.
- Extract CVE/CWE only from valid regex matches, never fabricated (AGENTS.md Rule 3).
- Stable correlation keys: hash(normalized asset + location + vuln id).
- Cross-tool merge keeps ALL evidence records and sources (Master Plan §8.1).
- Distinct assets never merge even if titles/CVEs match (Master Plan §8.1 Rule 5).
- Different paths/ports on same host stay separate (recorded in related_ids).
- Order-independent merge results.
- Status rules: direct proof / validation -> confirmed; banner/heuristic -> suspected (Master Plan §8.2).
- Tool disagreement -> conservative: suspected, low confidence, conflict noted (Master Plan §8.2).
- Standards mapping: CWE -> OWASP Top 10 (2021), remediation -> NIST CSF 2.0, step -> NIST SP 800-115, finding -> ATT&CK suggestion. Unmapped -> 'unmapped' (never guessed).
"""

from datetime import UTC, datetime
from pathlib import Path

from cipher_lens.correlate.dedup import correlate_findings
from cipher_lens.correlate.normalize import (
    normalize_finding,
    normalize_severity,
    normalize_url_path,
)
from cipher_lens.correlate.standards import StandardsMapper
from cipher_lens.correlate.status import evaluate_status_and_confidence
from cipher_lens.models.findings import Asset, Evidence, RawFinding

MAPPINGS_FILE = Path(__file__).parent.parent.parent / "config" / "mappings.yaml"


def make_raw_finding(
    tool: str,
    title: str,
    host: str = "lab-target.local",
    ip: str = "10.0.0.5",
    port: int | None = 80,
    url_path: str | None = "/",
    cve: list[str] | None = None,
    cwe: list[str] | None = None,
    sev: str = "high",
    conf: str = "medium",
    snippet: str = "vulnerable snippet",
) -> RawFinding:
    ev = Evidence(
        id=f"ev_{tool}_{len(title)}",
        source_tool=tool,
        run_id="run-01",
        artifact_id=f"art-{tool}-01",
        locator=f"/{tool}/item",
        raw_sha256="a" * 64,
        snippet=snippet,
        observed_at=datetime.now(UTC),
        origin="sample",
    )
    return RawFinding(
        title=title,
        asset=Asset(host=host, ip=ip, port=port, protocol="tcp", service="http", url_path=url_path),
        tool_name=tool,
        tool_severity=sev,
        raw_evidence=ev,
        cve=cve or [],
        cwe=cwe or [],
        description=f"Description from {tool}",
        confidence=conf,
    )


# ---------------------------------------------------------------------------
# B11 Normalizer Tests
# ---------------------------------------------------------------------------


def test_normalize_severity_vocabulary():
    """Maps various vendor severities to standardized info|low|medium|high|critical."""
    assert normalize_severity("informational") == "info"
    assert normalize_severity("0") == "info"
    assert normalize_severity("LOG") == "info"
    assert normalize_severity("Low") == "low"
    assert normalize_severity("moderate") == "medium"
    assert normalize_severity("High") == "high"
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("unknown_val") == "medium"  # Safe fallback


def test_normalize_url_path():
    """Canonicalizes URL paths (stripping fragments, query params if needed, normalizing slashes)."""
    assert normalize_url_path("/path/to/page") == "/path/to/page"
    assert normalize_url_path("/path/to/page?query=1#frag") == "/path/to/page"
    assert normalize_url_path("path/to/page/") == "/path/to/page"
    assert normalize_url_path("") == "/"
    assert normalize_url_path(None) is None


def test_normalize_finding_cve_cwe_extraction_and_cleaning():
    """Extracts strictly valid CVE and CWE strings via regex, discarding fabrications/noise."""
    raw = make_raw_finding(
        tool="nmap",
        title="Apache Vulnerability CVE-2021-41773 and invalid CVE-999",
        cve=["cve-2021-41773", "not-a-cve", "CVE-2021-41773"],
        cwe=["cwe-22", "invalid_cwe", "CWE-022"],
    )
    norm = normalize_finding(raw)

    assert norm.cve == ["CVE-2021-41773"]
    assert "CWE-22" in norm.cwe or "CWE-022" in norm.cwe
    assert "not-a-cve" not in norm.cve


# ---------------------------------------------------------------------------
# B12 Correlation and Status Tests (§8.1 & §8.2)
# ---------------------------------------------------------------------------


def test_correlation_cross_tool_merge_preserves_all_evidence():
    """Matching asset and location merges into one finding preserving all evidence and sources."""
    rf1 = make_raw_finding(
        tool="nmap",
        title="Apache Path Traversal",
        port=80,
        cve=["CVE-2021-41773"],
        snippet="<script id='http-vuln-cve2021-41773' output='VULNERABLE'/>",
    )
    rf2 = make_raw_finding(
        tool="nessus",
        title="Apache HTTP Server Path Traversal",
        port=80,
        cve=["CVE-2021-41773"],
        snippet="<plugin_output>Vulnerable path found</plugin_output>",
    )

    findings = correlate_findings([rf1, rf2])

    assert len(findings) == 1
    f = findings[0]
    assert set(f.sources) == {"nmap", "nessus"}
    assert len(f.evidence) == 2
    assert any(e.source_tool == "nmap" for e in f.evidence)
    assert any(e.source_tool == "nessus" for e in f.evidence)
    assert f.status == "confirmed"  # Direct proof in snippet or multi-tool corroboration


def test_correlation_distinct_assets_never_merge():
    """Invariance §8.1 Rule 5: Never merge distinct affected assets, even with identical titles."""
    rf1 = make_raw_finding(tool="nmap", title="Open SSH Port", host="target-1.local", ip="10.0.0.1", port=22)
    rf2 = make_raw_finding(tool="nmap", title="Open SSH Port", host="target-2.local", ip="10.0.0.2", port=22)

    findings = correlate_findings([rf1, rf2])
    assert len(findings) == 2
    assert findings[0].asset.host != findings[1].asset.host


def test_correlation_different_locations_stay_separate_and_link_related():
    """Different ports or paths on the same host stay separate but populate related_ids."""
    rf1 = make_raw_finding(tool="nikto", title="X-Frame-Options Header Missing", port=80, url_path="/")
    rf2 = make_raw_finding(tool="nikto", title="X-Frame-Options Header Missing", port=8080, url_path="/")

    findings = correlate_findings([rf1, rf2])
    assert len(findings) == 2
    assert findings[0].id in findings[1].related_ids or findings[1].id in findings[0].related_ids


def test_correlation_order_independence():
    """Correlating [A, B] produces identical groupings as [B, A]."""
    rf1 = make_raw_finding(tool="nmap", title="Vuln A", port=80, cve=["CVE-2021-41773"])
    rf2 = make_raw_finding(tool="openvas", title="Vuln B", port=80, cve=["CVE-2021-41773"])

    res1 = correlate_findings([rf1, rf2])
    res2 = correlate_findings([rf2, rf1])

    assert len(res1) == len(res2) == 1
    assert set(res1[0].sources) == set(res2[0].sources)
    assert len(res1[0].evidence) == len(res2[0].evidence)


def test_status_rules_banner_only_suspected():
    """Banner/version-only finding stays suspected, low/medium confidence (§8.2)."""
    rf = make_raw_finding(
        tool="nmap",
        title="Apache 2.4.49 Detected",
        port=80,
        conf="low",
        snippet="<service name='http' product='Apache' version='2.4.49'/>",
    )
    findings = correlate_findings([rf])
    assert len(findings) == 1
    assert findings[0].status == "suspected"
    assert "banner" in findings[0].status_reason.lower() or "version" in findings[0].status_reason.lower()


def test_status_rules_tool_conflict_handled_conservatively():
    """If tools disagree materially, keep finding as suspected, low, and note conflict (§8.2)."""
    rf1 = make_raw_finding(tool="nikto", title="Service Vulnerability", port=80, sev="high")
    rf2 = make_raw_finding(tool="zap", title="Service Vulnerability (Patched / Clean)", port=80, sev="info")

    status, conf, reason = evaluate_status_and_confidence([rf1, rf2], direct_proof=False, conflict=True)
    assert status == "suspected"
    assert conf == "low"
    assert "conflict" in reason.lower() or "disagree" in reason.lower()


# ---------------------------------------------------------------------------
# B13 Standards Mapping Tests
# ---------------------------------------------------------------------------


def test_standards_mapper_cwe_to_owasp_and_nist():
    """StandardsMapper maps CWE to OWASP Top 10 (2021) and NIST CSF 2.0 categories."""
    mapper = StandardsMapper.load(MAPPINGS_FILE)

    mapping = mapper.map_finding(cwe=["CWE-79", "CWE-89"])
    assert "A03:2021-Injection" in mapping.owasp_top_10
    assert "A05:2025-Injection" in mapping.owasp_top_10_2025
    assert "PR.DS" in mapping.nist_csf_functions or "PR.PS" in mapping.nist_csf_functions


def test_standards_mapper_owasp_2025_common_scanner_cwes():
    """Break-it test: Common scanner CWEs map to OWASP Top 10 2025 (ERR-15 / INC-09)."""
    mapper = StandardsMapper.load(MAPPINGS_FILE)

    mapping = mapper.map_finding(cwe=["CWE-352", "CWE-918", "CWE-1021", "CWE-611", "CWE-862"])
    assert "A01:2025-Broken Access Control" in mapping.owasp_top_10_2025
    assert "A02:2025-Security Misconfiguration" in mapping.owasp_top_10_2025
    assert "unmapped" not in mapping.owasp_top_10_2025



def test_standards_mapper_unmapped_never_guessed():
    """Unknown CWE or unmapped issue yields 'unmapped', never fabricated."""
    mapper = StandardsMapper.load(MAPPINGS_FILE)

    mapping = mapper.map_finding(cwe=["CWE-999999"])
    assert mapping.owasp_top_10 == ["unmapped"]
    assert mapping.nist_csf_functions == ["unmapped"]
    assert mapping.attck_techniques == ["unmapped"]
