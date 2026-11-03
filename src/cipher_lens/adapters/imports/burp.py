"""Burp Suite XML export report importer.

Invariants:
1. Parse strictly with defusedxml (AGENTS.md Rule 6).
2. Hosts outside scope are dropped and listed as warnings, never silently ingested (Master Plan B10).
3. Do not fabricate CVEs or scores (AGENTS.md Rule 3).
4. Truncate/redact request-response to prevent secret leakage (AGENTS.md Rule 9).
5. Raw evidence records carry locator and SHA-256 (AGENTS.md Rule 8).
"""

import uuid
from datetime import UTC, datetime

from defusedxml import ElementTree as ET
from pydantic import BaseModel

from cipher_lens.adapters.base import AdapterStatus, BaseAdapter, HealthResult
from cipher_lens.adapters.imports.common import (
    ImportResult,
    is_target_in_scope,
    redact_sensitive_text,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.policy.scope import Scope


class BurpImportParams(BaseModel):
    """Parameters for Burp import."""

    file_path: str | None = None


class BurpImporter(BaseAdapter):
    """Importer adapter for PortSwigger Burp Suite XML issue exports."""

    name = "burp_import"
    status = AdapterStatus.IMPORT_ONLY
    params_model = BurpImportParams

    async def healthcheck(self) -> HealthResult:
        """Healthcheck for import-only adapter."""
        return HealthResult(
            status="healthy",
            message="Burp importer is ready (import-only adapter).",
            details={"import_only": True},
        )

    def parse_with_scope(
        self,
        raw_bytes: bytes,
        evidence_meta: Evidence,
        scope: Scope | None = None,
    ) -> ImportResult:
        """Parses Burp XML issues, dropping out-of-scope hosts and redacting request/response data."""
        root = ET.fromstring(raw_bytes)
        result = ImportResult()

        sev_map = {
            "information": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
        }

        conf_map = {
            "certain": "high",
            "firm": "medium",
            "tentative": "low",
        }

        for issue_idx, issue_elem in enumerate(root.findall(".//issue")):
            host_elem = issue_elem.find("host")
            host_url = (host_elem.text or "").strip() if host_elem is not None else ""
            host_ip = host_elem.get("ip", "").strip() if host_elem is not None else ""

            target_repr = host_url or host_ip

            # Scope boundary validation
            if scope and not (
                is_target_in_scope(target_repr, scope)
                or (host_ip and is_target_in_scope(host_ip, scope))
            ):
                result.warnings.append(
                    f"Burp import: Host '{target_repr}' is outside registered scope and was dropped."
                )
                continue

            path_elem = issue_elem.find("path")
            url_path = (path_elem.text or "").strip() if path_elem is not None else None

            # Clean host representation
            clean_host = target_repr
            if "://" in clean_host:
                clean_host = clean_host.split("://", 1)[1]
            clean_host = clean_host.split("/", 1)[0]
            port_num = 443 if target_repr.startswith("https://") else (80 if target_repr.startswith("http://") else None)
            if ":" in clean_host:
                h_part, p_part = clean_host.split(":", 1)
                clean_host = h_part
                try:
                    port_num = int(p_part)
                except ValueError:
                    pass

            asset = Asset(
                host=clean_host,
                ip=host_ip or None,
                port=port_num,
                protocol="tcp",
                service="https" if target_repr.startswith("https://") else "http",
                url_path=url_path,
            )

            name_elem = issue_elem.find("name")
            title = name_elem.text.strip() if name_elem is not None and name_elem.text else "Burp Issue"

            sev_elem = issue_elem.find("severity")
            sev_text = (sev_elem.text or "").strip().lower() if sev_elem is not None else "medium"
            tool_sev = sev_map.get(sev_text, "medium")

            conf_elem = issue_elem.find("confidence")
            conf_text = (conf_elem.text or "").strip().lower() if conf_elem is not None else "firm"
            confidence = conf_map.get(conf_text, "medium")

            detail_elem = issue_elem.find("issueDetail")
            detail_text = (detail_elem.text or "").strip() if detail_elem is not None else ""
            remed_elem = issue_elem.find("remediationDetail")
            remed_text = (remed_elem.text or "").strip() if remed_elem is not None else ""

            # Extract request / response snippets and redact credentials
            rr_snippet = ""
            req_elem = issue_elem.find(".//requestresponse/request")
            if req_elem is not None and req_elem.text:
                req_text = req_elem.text[:300]
                rr_snippet = f"\n<request>\n{redact_sensitive_text(req_text)}\n</request>"

            locator = f"/issues/issue[{issue_idx + 1}]"
            snippet = (
                f"<issue>\n"
                f"  <name>{title}</name>\n"
                f"  <host ip='{host_ip}'>{host_url}</host>\n"
                f"  <path>{url_path or '/'}</path>"
                f"{rr_snippet}\n"
                f"</issue>"
            )

            result.findings.append(
                RawFinding(
                    title=f"[Burp] {title}",
                    asset=asset,
                    tool_name="burp",
                    tool_severity=tool_sev,
                    raw_evidence=Evidence(
                        id=f"ev_burp_{uuid.uuid4().hex[:8]}",
                        source_tool=self.name,
                        run_id=evidence_meta.run_id,
                        artifact_id=evidence_meta.artifact_id,
                        locator=locator,
                        raw_sha256=evidence_meta.raw_sha256,
                        snippet=snippet,
                        observed_at=datetime.now(UTC),
                        origin="import",
                    ),
                    cve=[],
                    cwe=[],
                    description=detail_text,
                    solution=remed_text or None,
                    confidence=confidence,
                )
            )

        return result

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Standard BaseAdapter parse interface (parses without scope filter)."""
        res = self.parse_with_scope(raw_bytes, evidence_meta, scope=None)
        return [*res.observations, *res.findings]

