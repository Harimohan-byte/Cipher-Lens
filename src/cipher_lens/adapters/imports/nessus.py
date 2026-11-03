"""Nessus .nessus (NessusClientData_v2) XML report importer.

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


class NessusImportParams(BaseModel):
    """Parameters for Nessus import."""

    file_path: str | None = None


class NessusImporter(BaseAdapter):
    """Importer adapter for Tenable Nessus XML export files."""

    name = "nessus_import"
    status = AdapterStatus.IMPORT_ONLY
    params_model = NessusImportParams

    async def healthcheck(self) -> HealthResult:
        """Healthcheck for import-only adapter."""
        return HealthResult(
            status="healthy",
            message="Nessus importer is ready (import-only adapter).",
            details={"import_only": True},
        )

    def parse_with_scope(
        self,
        raw_bytes: bytes,
        evidence_meta: Evidence,
        scope: Scope | None = None,
    ) -> ImportResult:
        """Parses NessusClientData_v2 XML, dropping out-of-scope hosts with warnings."""
        root = ET.fromstring(raw_bytes)
        result = ImportResult()

        severity_map = {
            "0": "info",
            "1": "low",
            "2": "medium",
            "3": "high",
            "4": "critical",
        }

        for host_idx, host_elem in enumerate(root.findall(".//ReportHost")):
            host_name = host_elem.get("name", "").strip()
            host_ip = None
            host_fqdn = None

            for tag in host_elem.findall(".//tag"):
                t_name = tag.get("name")
                if t_name == "host-ip":
                    host_ip = (tag.text or "").strip()
                elif t_name == "host-fqdn":
                    host_fqdn = (tag.text or "").strip()

            target_repr = host_fqdn or host_ip or host_name

            # Scope boundary validation
            if scope and not (
                is_target_in_scope(target_repr, scope)
                or (host_ip and is_target_in_scope(host_ip, scope))
                or (host_fqdn and is_target_in_scope(host_fqdn, scope))
            ):
                result.warnings.append(
                    f"Nessus import: Host '{target_repr}' is outside registered scope and was dropped."
                )
                continue

            asset = Asset(
                host=host_fqdn or host_name or (host_ip or "unknown"),
                ip=host_ip,
            )

            for item_idx, item_elem in enumerate(host_elem.findall(".//ReportItem")):
                port_str = item_elem.get("port", "0")
                svc_name = item_elem.get("svc_name", "")
                protocol = item_elem.get("protocol", "tcp")
                severity_code = item_elem.get("severity", "0")
                plugin_name = item_elem.get("pluginName", "Nessus Finding")
                plugin_id = item_elem.get("pluginID", "")

                try:
                    port_num = int(port_str)
                except ValueError:
                    port_num = 0

                item_asset = Asset(
                    host=asset.host,
                    ip=asset.ip,
                    port=port_num if port_num > 0 else None,
                    protocol=protocol,
                    service=svc_name or None,
                )

                desc_elem = item_elem.find("description")
                desc_text = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
                sol_elem = item_elem.find("solution")
                sol_text = sol_elem.text.strip() if sol_elem is not None and sol_elem.text else ""
                out_elem = item_elem.find("plugin_output")
                out_text = out_elem.text.strip() if out_elem is not None and out_elem.text else ""

                # Extract tool-reported CVEs only (AGENTS.md Rule 3)
                cves: list[str] = []
                for cve_elem in item_elem.findall("cve"):
                    if cve_elem.text:
                        cves.extend([c.upper() for c in CVE_PATTERN.findall(cve_elem.text)])

                locator = f"/NessusClientData_v2/Report/ReportHost[{host_idx + 1}]/ReportItem[{item_idx + 1}]"
                snippet = (
                    f"<ReportItem pluginID='{plugin_id}' pluginName='{plugin_name}' severity='{severity_code}'>\n"
                    f"  <plugin_output>{out_text[:300]}</plugin_output>\n"
                    f"</ReportItem>"
                )

                tool_sev = severity_map.get(severity_code, "medium")

                # If severity is 0, it can be represented as an observation
                if severity_code == "0":
                    result.observations.append(
                        Observation(
                            id=f"obs_nessus_{uuid.uuid4().hex[:8]}",
                            source_tool=self.name,
                            asset=item_asset,
                            observation_type="service_info",
                            data={
                                "plugin_name": plugin_name,
                                "plugin_id": plugin_id,
                                "description": desc_text,
                            },
                            raw_evidence=Evidence(
                                id=f"ev_nessus_{uuid.uuid4().hex[:8]}",
                                source_tool=self.name,
                                run_id=evidence_meta.run_id,
                                artifact_id=evidence_meta.artifact_id,
                                locator=locator,
                                raw_sha256=evidence_meta.raw_sha256,
                                snippet=snippet,
                                observed_at=datetime.now(UTC),
                                origin="import",
                            ),
                            observed_at=datetime.now(UTC),
                        )
                    )
                else:
                    result.findings.append(
                        RawFinding(
                            title=f"[Nessus] {plugin_name}",
                            asset=item_asset,
                            tool_name="nessus",
                            tool_severity=tool_sev,
                            raw_evidence=Evidence(
                                id=f"ev_nessus_{uuid.uuid4().hex[:8]}",
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
                            solution=sol_text or None,
                            confidence="medium",
                        )
                    )

        return result

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Standard BaseAdapter parse interface (parses without scope filter)."""
        res = self.parse_with_scope(raw_bytes, evidence_meta, scope=None)
        return [*res.observations, *res.findings]

