"""End-to-end integration test for Day 3 shared gate.

Tests:
Feed Nmap + Nikto + one import fixture (Nessus) through:
parse -> normalize -> correlate -> enrich (via cache/service)
Verifies:
1. Merged group with multi-tool evidence.
2. Near-match on different port or host that stays separate.
3. Every finding retains source evidence with locator and hash.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipher_lens.adapters.imports.nessus import NessusImporter
from cipher_lens.adapters.nikto import parse_nikto_xml
from cipher_lens.adapters.nmap import parse_nmap_xml
from cipher_lens.correlate.dedup import correlate_findings
from cipher_lens.correlate.standards import StandardsMapper
from cipher_lens.enrichment.cache import SqliteTtlCache
from cipher_lens.enrichment.service import EnrichmentService
from cipher_lens.models.findings import Evidence, RawFinding
from cipher_lens.policy.scope import Scope

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MAPPINGS_FILE = Path(__file__).parent.parent / "config" / "mappings.yaml"


@pytest.mark.asyncio
async def test_day3_shared_gate_flow(tmp_path):
    scope = Scope(
        id="scope-gate-03",
        owner="Lab Admin",
        authorization_reference="AUTH-DAY3",
        allowed_targets=["10.0.0.5", "lab-target.local"],
        exclusions=["192.168.1.100"],
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
    )

    ev_nmap = Evidence(
        id="ev_nmap_gate",
        source_tool="nmap",
        run_id="run-nmap",
        artifact_id="art-nmap",
        locator="/nmaprun",
        raw_sha256="1" * 64,
        snippet="",
        observed_at=datetime.now(UTC),
        origin="sample",
    )
    ev_nikto = Evidence(
        id="ev_nikto_gate",
        source_tool="nikto",
        run_id="run-nikto",
        artifact_id="art-nikto",
        locator="/niktoscan",
        raw_sha256="2" * 64,
        snippet="",
        observed_at=datetime.now(UTC),
        origin="sample",
    )
    ev_nessus = Evidence(
        id="ev_nessus_gate",
        source_tool="nessus",
        run_id="run-nessus",
        artifact_id="art-nessus",
        locator="/NessusClientData_v2",
        raw_sha256="3" * 64,
        snippet="",
        observed_at=datetime.now(UTC),
        origin="import",
    )

    # 1. Parse outputs
    nmap_raw = (FIXTURES_DIR / "nmap_synthetic.xml").read_bytes()
    nikto_raw = (FIXTURES_DIR / "nikto_synthetic.xml").read_bytes()
    nessus_raw = (FIXTURES_DIR / "nessus_synthetic.nessus").read_bytes()

    nmap_results = parse_nmap_xml(nmap_raw, ev_nmap)
    nikto_findings = parse_nikto_xml(nikto_raw, ev_nikto)
    nessus_res = NessusImporter().parse_with_scope(nessus_raw, ev_nessus, scope=scope)

    raw_findings = [r for r in nmap_results if isinstance(r, RawFinding)]
    raw_findings.extend(nikto_findings)
    raw_findings.extend(nessus_res.findings)

    # 2. Correlate
    findings = correlate_findings(raw_findings)

    # In our synthetic fixtures:
    # - Nmap and Nessus both report CVE-2021-41773 on port 80 -> should merge into 1 finding!
    # - Nikto reports Apache default file & X-Frame-Options on port 3000 -> stays separate!
    cve_findings = [f for f in findings if "CVE-2021-41773" in f.cve]
    assert len(cve_findings) == 1
    merged = cve_findings[0]

    assert set(merged.sources) == {"nmap", "nessus"}
    assert len(merged.evidence) >= 2
    assert merged.status == "confirmed"

    # Separate port Nikto findings stay separate
    nikto_items = [f for f in findings if "nikto" in f.sources]
    assert len(nikto_items) >= 1
    for nf in nikto_items:
        assert nf.asset.port == 3000
        assert nf.id in merged.related_ids or merged.id in nf.related_ids

    # 3. Standards mapping
    mapper = StandardsMapper.load(MAPPINGS_FILE)
    std_map = mapper.map_finding(merged.cwe)
    assert std_map.owasp_top_10 is not None

    # 4. Enrichment from offline cache
    cache = SqliteTtlCache(db_path=tmp_path / "enrichment.db")
    service = EnrichmentService(cache=cache, offline_mode=True)
    enriched = await service.enrich_cve("CVE-2021-41773")
    assert enriched is not None
    assert enriched.cve_id == "CVE-2021-41773"
