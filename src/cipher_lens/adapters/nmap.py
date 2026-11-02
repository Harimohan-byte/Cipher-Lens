"""Nmap adapter, argv builder, live runner, and defusedxml parser."""

import re
import shutil
import subprocess
import time
import uuid
from datetime import UTC, datetime
from typing import Literal

from defusedxml import ElementTree as ET
from pydantic import BaseModel, Field, field_validator

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    ExecutionContext,
    ExecutionResult,
    HealthResult,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import PlanStep

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Strict allowlist of safe NSE scripts (§7 Task B6)
ALLOWED_NSE_SCRIPTS: set[str] = {
    "banner",
    "http-title",
    "http-headers",
    "http-methods",
    "http-server-header",
    "ssl-cert",
    "ssl-enum-ciphers",
    "http-vuln-cve2021-41773",
}

PORTS_REGEX = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")
DISALLOWED_TARGET_CHARS = re.compile(r"[;&|`$\s\r\n]")


class NmapParams(BaseModel):
    """Validated parameters for Nmap execution."""

    target: str
    ports: str | None = None
    profile: Literal["discovery", "service", "scripts"] = "discovery"
    scripts: list[str] = Field(default_factory=list)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean = v.strip()
        if not clean or DISALLOWED_TARGET_CHARS.search(clean):
            raise ValueError(f"Invalid characters in target '{v}'; shell injection disallowed")
        return clean

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            return None
        if not PORTS_REGEX.match(clean):
            raise ValueError(f"Invalid port specification '{v}'; must be comma-separated numbers or ranges")
        return clean

    @field_validator("scripts")
    @classmethod
    def validate_scripts(cls, scripts: list[str]) -> list[str]:
        for s in scripts:
            clean_s = s.strip()
            if clean_s not in ALLOWED_NSE_SCRIPTS:
                raise ValueError(
                    f"Disallowed NSE script '{clean_s}'. Allowed scripts: {sorted(ALLOWED_NSE_SCRIPTS)}"
                )
        return scripts


def build_nmap_argv(
    params: NmapParams,
    rate_limit: int | None = None,
    binary_path: str = "nmap",
) -> list[str]:
    """Constructs a deterministic argv list for Nmap execution.

    Invariants:
    1. Never uses shell=True or string-formatted command lines.
    2. Enforces TCP connect scan (-sT) to avoid raw socket privileges.
    3. Output is always emitted as XML (-oX -) for defusedxml parsing.
    4. Throttling maps to --max-rate.
    """
    argv = [binary_path, "-sT", "-oX", "-"]

    if rate_limit is not None and rate_limit > 0:
        argv.extend(["--max-rate", str(rate_limit)])

    if params.ports:
        argv.extend(["-p", params.ports])

    if params.profile == "discovery":
        pass  # Connect scan with specified or default ports
    elif params.profile == "service":
        argv.append("-sV")
    elif params.profile == "scripts":
        argv.append("-sV")
        if params.scripts:
            argv.extend(["--script", ",".join(params.scripts)])

    argv.append(params.target)
    return argv


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

    async def run(self, step: PlanStep, ctx: ExecutionContext) -> ExecutionResult:
        """Executes Nmap safely with argv list, capturing raw output into ArtifactStore."""
        # Validate parameters
        params_dict = dict(step.params)
        if "target" not in params_dict:
            params_dict["target"] = step.target
        params = NmapParams(**params_dict)

        argv = build_nmap_argv(params, rate_limit=ctx.rate_limit)

        start_time = time.perf_counter()
        try:
            # Execute subprocess without shell=True
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=ctx.timeout_seconds,
                shell=False,
            )
            duration = time.perf_counter() - start_time

            artifact_id = None
            if proc.stdout:
                meta = ctx.artifact_store.save_raw(
                    content=proc.stdout,
                    source_tool=self.name,
                    run_id=step.step_id,
                    extension="xml",
                )
                artifact_id = meta.artifact_id

            status: Literal["succeeded", "failed", "timed_out"] = (
                "succeeded" if proc.returncode == 0 else "failed"
            )
            return ExecutionResult(
                status=status,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                duration_seconds=duration,
                artifact_id=artifact_id,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start_time
            return ExecutionResult(
                status="timed_out",
                stdout=exc.stdout if isinstance(exc.stdout, str) else "",
                stderr=f"Nmap scan timed out after {ctx.timeout_seconds}s",
                exit_code=None,
                duration_seconds=duration,
                artifact_id=None,
            )
        except FileNotFoundError:
            duration = time.perf_counter() - start_time
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr="Nmap binary not found on PATH",
                exit_code=127,
                duration_seconds=duration,
                artifact_id=None,
            )

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[Observation | RawFinding]:
        """Parses Nmap XML output into Observations and RawFindings."""
        return parse_nmap_xml(raw_bytes, evidence_meta)
