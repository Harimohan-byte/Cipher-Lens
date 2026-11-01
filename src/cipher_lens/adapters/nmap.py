"""Nmap adapter and defusedxml parser spike."""

import re
import shutil
import uuid
from datetime import UTC, datetime

from defusedxml import ElementTree as ET
from pydantic import BaseModel, Field

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    HealthResult,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.observations import Observation

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapParams(BaseModel):
    """Validated parameters for Nmap execution."""
    target: str
    ports: str | None = None
    profile: str = Field(default="discovery", pattern="^(discovery|service|scripts)$")


def parse_nmap_xml(
    raw_bytes: bytes,
    evidence_meta: Evidence,
) -> list[Observation | RawFinding]:
    """Parses Nmap XML safely using defusedxml into Observations and RawFindings.

    Invariants:
    1. Parse XML exclusively with defusedxml to block XXE/entity expansion attacks.
    2. CVE IDs are extracted strictly if reported in tool output. Never fabricate.
    3. Verbatim snippets and locators are attached to every generated record.
    """
    root = ET.fromstring(raw_bytes)
    results: list[Observation | RawFinding] = []

    for host_idx, host_elem in enumerate(root.findall("host")):
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        ip_addr = addr_elem.get("addr", "")

        hostname_elem = host_elem.find("hostnames/hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else ip_addr

        base_asset = Asset(host=hostname or ip_addr, ip=ip_addr)

        # Host observation
        host_locator = f"/nmaprun/host[{host_idx + 1}]"
        results.append(
            Observation(
                id=f"obs_host_{uuid.uuid4().hex[:8]}",
                source_tool="nmap",
                asset=base_asset,
                observation_type="host",
                data={"ip": ip_addr, "hostname": hostname},
                raw_evidence=Evidence(
                    id=f"ev_obs_{uuid.uuid4().hex[:8]}",
                    source_tool="nmap",
                    run_id=evidence_meta.run_id,
                    artifact_id=evidence_meta.artifact_id,
                    locator=host_locator,
                    raw_sha256=evidence_meta.raw_sha256,
                    snippet=f"<address addr='{ip_addr}'/>",
                    observed_at=datetime.now(UTC),
                    origin=evidence_meta.origin,
                ),
                observed_at=datetime.now(UTC),
            )
        )

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_idx, port_elem in enumerate(ports_elem.findall("port")):
            port_id_str = port_elem.get("portid")
            if not port_id_str:
                continue
            port_num = int(port_id_str)
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None

            port_asset = Asset(
                host=hostname or ip_addr,
                ip=ip_addr,
                port=port_num,
                protocol=protocol,
                service=service_name,
            )

            port_locator = f"{host_locator}/ports/port[{port_idx + 1}]"
            snippet = f"<port protocol='{protocol}' portid='{port_num}'><state state='{state}'/>"
            if service_elem is not None:
                prod_str = product or ""
                ver_str = version or ""
                snippet += f"<service name='{service_name}' product='{prod_str}' version='{ver_str}'/>"
            snippet += "</port>"

            # Port / Service observation
            results.append(
                Observation(
                    id=f"obs_port_{uuid.uuid4().hex[:8]}",
                    source_tool="nmap",
                    asset=port_asset,
                    observation_type="port",
                    data={
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                    raw_evidence=Evidence(
                        id=f"ev_obs_{uuid.uuid4().hex[:8]}",
                        source_tool="nmap",
                        run_id=evidence_meta.run_id,
                        artifact_id=evidence_meta.artifact_id,
                        locator=port_locator,
                        raw_sha256=evidence_meta.raw_sha256,
                        snippet=snippet,
                        observed_at=datetime.now(UTC),
                        origin=evidence_meta.origin,
                    ),
                    observed_at=datetime.now(UTC),
                )
            )

            # Check for vulnerability scripts (e.g. NSE scripts)
            for script_idx, script_elem in enumerate(port_elem.findall("script")):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                full_script_text = f"{script_id} {script_output}"

                cves_found = [c.upper() for c in CVE_PATTERN.findall(full_script_text)]

                if "VULNERABLE" in full_script_text.upper() or cves_found:
                    script_locator = f"{port_locator}/script[{script_idx + 1}]"
                    finding_title = f"{product or service_name or 'Service'} Vulnerability ({script_id})"
                    if cves_found:
                        finding_title = f"{finding_title} - {', '.join(cves_found)}"

                    results.append(
                        RawFinding(
                            title=finding_title,
                            asset=port_asset,
                            tool_name="nmap",
                            tool_severity="high" if cves_found else "medium",
                            raw_evidence=Evidence(
                                id=f"ev_nmap_{uuid.uuid4().hex[:8]}",
                                source_tool="nmap",
                                run_id=evidence_meta.run_id,
                                artifact_id=evidence_meta.artifact_id,
                                locator=script_locator,
                                raw_sha256=evidence_meta.raw_sha256,
                                snippet=f"<script id='{script_id}' output='{script_output}'/>",
                                observed_at=datetime.now(UTC),
                                origin=evidence_meta.origin,
                            ),
                            cve=cves_found,
                            cwe=[],
                            description=script_output,
                            confidence="high" if "VULNERABLE" in full_script_text.upper() else "medium",
                        )
                    )

    return results


class NmapAdapter(BaseAdapter):
    """Live and fixture parser adapter for Nmap."""

    name = "nmap"
    status = AdapterStatus.LIVE
    params_model = NmapParams

    async def healthcheck(self) -> HealthResult:
        """Checks if nmap is installed on the local system."""
        nmap_path = shutil.which("nmap")
        if nmap_path:
            return HealthResult(
                status="healthy",
                message=f"Nmap executable found at {nmap_path}",
                details={"path": nmap_path},
            )
        return HealthResult(
            status="unavailable",
            message="Nmap binary not found on PATH. Required for live scanning.",
        )

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Parses Nmap XML output into Observations and RawFindings."""
        return parse_nmap_xml(raw_bytes, evidence_meta)
