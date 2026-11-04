"""Nikto web scanner adapter, argv builder, live runner, and defusedxml parser.

Design decisions:
- DECISION: Nikto alone can NEVER produce confidence='high'. All findings are 'medium' max.
  (AGENTS.md Rule 4: observed evidence and AI inference are separate; nikto heuristics
  are not confirmation-level evidence without corroboration.)
- DECISION: Target is validated with the same shell-injection patterns as NmapParams.
- DECISION: Parser uses defusedxml exclusively (AGENTS.md Rule 6).
"""

import os
import re
import shutil
import subprocess
import tempfile
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
    validate_safe_target,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.plan import PlanStep

# Reuse same shell-injection guard as the Nmap adapter
DISALLOWED_TARGET_CHARS = re.compile(r"[;&|`$\s\r\n]")


class NiktoParams(BaseModel):
    """Validated parameters for Nikto execution."""

    target: str
    port: int = Field(..., ge=1, le=65535)
    ssl: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return validate_safe_target(v)


def build_nikto_argv(
    params: NiktoParams,
    output_file: str | None = None,
    binary_path: str = "nikto",
) -> list[str]:
    """Constructs a deterministic argv list for Nikto execution.

    Invariants:
    1. Never uses shell=True or string-formatted command lines.
    2. Always outputs XML (-Format xml) for defusedxml parsing.
    3. Always non-interactive (-nointeractive) to prevent TTY prompts.
    4. Writes XML to specified output_file or fallback path.
    5. Disables 404 guessing and external redirect tracking (-no404) (ERR-27).
    """
    argv = [
        binary_path,
        "-host", params.target,
        "-port", str(params.port),
        "-Format", "xml",
        "-output", output_file or "-",
        "-nointeractive",
        "-no404",
    ]
    if params.ssl:
        argv.append("-ssl")
    return argv


def parse_nikto_xml(
    raw_bytes: bytes,
    evidence_meta: Evidence,
) -> list[RawFinding]:
    """Parses Nikto XML safely using defusedxml into RawFindings.

    Invariants:
    1. Parse XML exclusively with defusedxml to block XXE/entity expansion attacks.
    2. Confidence is always 'medium' — Nikto alone cannot confirm findings.
    3. Verbatim snippets and locators are attached to every generated record.
    4. CVE IDs are NEVER fabricated — Nikto output doesn't carry CVEs directly;
       OSVDB IDs are preserved as-is in the finding description.
    """
    root = ET.fromstring(raw_bytes)
    results: list[RawFinding] = []

    for scan_idx, scandetails in enumerate(root.findall("scandetails")):
        target_ip = scandetails.get("targetip", "")
        target_host = scandetails.get("targethostname", target_ip)
        target_port_str = scandetails.get("targetport", "80")
        try:
            target_port = int(target_port_str)
        except ValueError:
            target_port = 80

        scan_locator = f"/niktoscan/scandetails[{scan_idx + 1}]"

        asset = Asset(
            host=target_host or target_ip,
            ip=target_ip,
            port=target_port,
            protocol="tcp",
            service="http",
        )

        for item_idx, item_elem in enumerate(scandetails.findall("item")):
            item_id = item_elem.get("id", str(item_idx + 1))
            osvdb_id = item_elem.get("osvdbid", "0")
            method = item_elem.get("method", "GET")

            desc_elem = item_elem.find("description")
            uri_elem = item_elem.find("uri")

            description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
            uri = uri_elem.text.strip() if uri_elem is not None and uri_elem.text else "/"

            # Verbatim snippet from XML — never fabricated
            snippet_parts = [f"<item id='{item_id}' osvdbid='{osvdb_id}' method='{method}'>"]
            snippet_parts.append(f"  <description>{description}</description>")
            snippet_parts.append(f"  <uri>{uri}</uri>")
            snippet_parts.append("</item>")
            snippet = "\n".join(snippet_parts)

            # Severity: medium if OSVDB entry exists, low otherwise
            # DECISION: Never "high" from nikto alone — AGENTS.md Rule 4
            tool_severity: Literal["low", "medium", "high"] = (
                "medium" if osvdb_id and osvdb_id != "0" else "low"
            )

            item_locator = f"{scan_locator}/item[@id='{item_id}']"

            results.append(
                RawFinding(
                    title=f"[Nikto] {description[:80]}",
                    asset=asset,
                    tool_name="nikto",
                    tool_severity=tool_severity,
                    # DECISION: confidence is always 'medium' — Nikto heuristics are
                    # not confirmation-level evidence without corroboration.
                    confidence="medium",
                    raw_evidence=Evidence(
                        id=f"ev_nikto_{uuid.uuid4().hex[:8]}",
                        source_tool="nikto",
                        run_id=evidence_meta.run_id,
                        artifact_id=evidence_meta.artifact_id,
                        locator=item_locator,
                        raw_sha256=evidence_meta.raw_sha256,
                        snippet=snippet,
                        observed_at=datetime.now(UTC),
                        origin=evidence_meta.origin,
                    ),
                    cve=[],  # Nikto doesn't report CVEs directly
                    cwe=[],
                    description=description,
                )
            )

    return results


class NiktoAdapter(BaseAdapter):
    """Live and fixture parser adapter for Nikto web scanner."""

    name = "nikto"
    status = AdapterStatus.LIVE
    params_model = NiktoParams

    async def healthcheck(self) -> HealthResult:
        """Checks if nikto is installed on the local system."""
        nikto_path = shutil.which("nikto")
        if nikto_path:
            return HealthResult(
                status="healthy",
                message=f"Nikto executable found at {nikto_path}",
                details={"path": nikto_path},
            )
        return HealthResult(
            status="unavailable",
            message="Nikto binary not found on PATH. Required for live web scanning.",
        )

    async def run(self, step: PlanStep, ctx: ExecutionContext) -> ExecutionResult:
        """Executes Nikto safely with argv list, capturing raw output into ArtifactStore."""
        params_dict = dict(step.params)
        if "target" not in params_dict:
            params_dict["target"] = step.target
        params = NiktoParams(**params_dict)

        # Create temporary file for Nikto XML report output
        with tempfile.NamedTemporaryFile(prefix="nikto_out_", suffix=".xml", delete=False) as tmp_f:
            tmp_xml_path = tmp_f.name

        argv = build_nikto_argv(params, output_file=tmp_xml_path)

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

            # Nikto writes the XML report to the specified file; fallback to proc.stdout if file is empty
            xml_content = ""
            if os.path.exists(tmp_xml_path):
                try:
                    with open(tmp_xml_path, encoding="utf-8", errors="replace") as f:
                        xml_content = f.read()
                except OSError:
                    pass

            content_to_save = xml_content or proc.stdout

            artifact_id = None
            if content_to_save:
                meta = ctx.artifact_store.save_raw(
                    content=content_to_save,
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
                stderr=f"Nikto scan timed out after {ctx.timeout_seconds}s",
                exit_code=None,
                duration_seconds=duration,
                artifact_id=None,
            )
        except FileNotFoundError:
            duration = time.perf_counter() - start_time
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr="Nikto binary not found on PATH",
                exit_code=127,
                duration_seconds=duration,
                artifact_id=None,
            )
        finally:
            if os.path.exists(tmp_xml_path):
                try:
                    os.remove(tmp_xml_path)
                except OSError:
                    pass

    def parse(self, raw_bytes: bytes, evidence_meta: Evidence) -> list[RawFinding]:
        """Parses Nikto XML output into RawFindings."""
        return parse_nikto_xml(raw_bytes, evidence_meta)
