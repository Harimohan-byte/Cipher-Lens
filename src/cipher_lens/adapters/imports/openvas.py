"""OpenVAS / Greenbone XML report importer.

Invariants:
1. Parse strictly with defusedxml (AGENTS.md Rule 6).
2. Hosts outside scope are dropped and listed as warnings, never silently ingested (Master Plan B10).
3. Do not fabricate CVEs or scores (AGENTS.md Rule 3).
4. Raw evidence records carry locator and SHA-256 (AGENTS.md Rule 8).
"""

import uuid
from datetime import UTC, datetime

from defusedxml import ElementTree as ET
from pydantic import BaseModel

from cipher_lens.adapters.base import AdapterStatus, BaseAdapter, HealthResult
from cipher_lens.adapters.imports.common import (
    CVE_PATTERN,
    ImportResult,
    is_target_in_scope,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.policy.scope import Scope


class OpenvasImportParams(BaseModel):
    """Parameters for OpenVAS import."""

    file_path: str | None = None


class OpenvasImporter(BaseAdapter):
    """Importer adapter for OpenVAS / Greenbone Community XML export files."""

    name = "openvas_import"
    status = AdapterStatus.IMPORT_ONLY
    params_model = OpenvasImportParams

    async def healthcheck(self) -> HealthResult:
        """Healthcheck for import-only adapter."""
        return HealthResult(
            status="healthy",
            message="OpenVAS importer is ready (import-only adapter).",
            details={"import_only": True},
        )

    def parse_with_scope(
        self,
        raw_bytes: bytes,
        evidence_meta: Evidence,
        scope: Scope | None = None,
    ) -> ImportResult:
        """Parses OpenVAS XML report, dropping out-of-scope hosts with warnings."""
        root = ET.fromstring(raw_bytes)
        result = ImportResult()

        for res_idx, res_elem in enumerate(root.findall(".//results/result")):
            host_elem = res_elem.find("host")
            host_text = (host_elem.text or "").strip() if host_elem is not None else ""

            if not host_text:
                continue

            # Scope boundary validation
            if scope and not is_target_in_scope(host_text, scope):
                result.warnings.append(
                    f"OpenVAS import: Host '{host_text}' is outside registered scope and was dropped."
                )
                continue

            port_elem = res_elem.find("port")
            port_text = (port_elem.text or "").strip() if port_elem is not None else ""

            port_num = None
            protocol = "tcp"
            if "/" in port_text:
                p_part, proto_part = port_text.split("/", 1)
                try:
                    port_num = int(p_part)
                except ValueError:
                    port_num = None
                protocol = proto_part.lower()

            asset = Asset(
                host=host_text,
                ip=host_text if any(c.isdigit() for c in host_text) else None,
                port=port_num,
                protocol=protocol,
            )

            name_elem = res_elem.find("name")
            title = name_elem.text.strip() if name_elem is not None and name_elem.text else "OpenVAS Finding"

            threat_elem = res_elem.find("threat")
            threat_text = threat_elem.text.strip().lower() if threat_elem is not None and threat_elem.text else "medium"

            sev_map = {
                "log": "info",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical",
            }
            tool_sev = sev_map.get(threat_text, "medium")

            desc_elem = res_elem.find("description")
            desc_text = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

            # Extract tool-reported CVEs from nvt block
            cves: list[str] = []
            nvt_elem = res_elem.find("nvt")
            if nvt_elem is not None:
                cve_elem = nvt_elem.find("cve")
                if cve_elem is not None and cve_elem.text:
                    cves.extend([c.upper() for c in CVE_PATTERN.findall(cve_elem.text)])

            locator = f"/report/results/result[{res_idx + 1}]"
            snippet = (
                f"<result id='{res_elem.get('id', '')}'>\n"
                f"  <name>{title}</name>\n"
                f"  <host>{host_text}</host>\n"
                f"  <threat>{threat_text}</threat>\n"
                f"</result>"
            )

            result.findings.append(
                RawFinding(
                    title=f"[OpenVAS] {title}",
                    asset=asset,
                    tool_name="openvas",
                    tool_severity=tool_sev,
                    raw_evidence=Evidence(
                        id=f"ev_openvas_{uuid.uuid4().hex[:8]}",
                        source_tool=self.name,
                        run_id=evidence_meta.run_id,
                        artifact_id=evidence_meta.artifact_id,
                        locator=locator,
                        raw_sha256=evidence_meta.raw_sha256,
                        snippet=snippet,
                        observed_at=datetime.now(UTC),
                        origin="import",
                    ),
                    cve=list(dict.fromkeys(cves)),
                    cwe=[],
                    description=desc_text,
                    confidence="medium",
                )
            )

        return result

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Standard BaseAdapter parse interface (parses without scope filter)."""
        res = self.parse_with_scope(raw_bytes, evidence_meta, scope=None)
        return [*res.observations, *res.findings]

