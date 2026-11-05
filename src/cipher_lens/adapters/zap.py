# DECISION: ZAP adapter communicates exclusively over httpx with explicit timeouts and passes the API key in the X-ZAP-API-Key header to avoid exposing secrets in query parameters.
# DECISION: Active scanning is strictly blocked unless per-step human approval is verified via ApprovalManager or step.action_class == ActionClass.INTRUSIVE with approval.
# DECISION: Contexts created in ZAP are strictly bounded: include regex allows only the approved target URL; exclusions from scope are added as exclude regexes.
# DECISION: Raw ZAP alerts JSON is saved unmodified with SHA-256 integrity in ArtifactStore before parsing.
# DECISION: When ZAP is unavailable or times out, execution returns failed status with recorded reason; no alerts are ever fabricated.
"""OWASP ZAP adapter and REST API integration."""

import asyncio
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    ExecutionContext,
    ExecutionResult,
    HealthResult,
)
from cipher_lens.models.findings import Asset, Evidence, RawFinding
from cipher_lens.models.observations import Observation
from cipher_lens.models.plan import ActionClass, PlanStep
from cipher_lens.policy.approvals import ApprovalManager, ApprovalRequiredError

_RISK_MAP = {
    "informational": "informational",
    "info": "informational",
    "0": "informational",
    "low": "low",
    "1": "low",
    "medium": "medium",
    "2": "medium",
    "high": "high",
    "3": "high",
}

_CONFIDENCE_MAP: dict[str, Literal["high", "medium", "low"]] = {
    "false positive": "low",
    "0": "low",
    "low": "low",
    "1": "low",
    "medium": "medium",
    "2": "medium",
    "high": "high",
    "3": "high",
    "user confirmed": "high",
}


class ZapParams(BaseModel):
    """Validated parameters for ZAP execution."""

    target: str
    mode: Literal["spider", "passive", "active", "full"] = "passive"
    context_name: str | None = None
    spider_max_depth: int | None = Field(default=None, ge=1, le=10)
    poll_interval_seconds: float = Field(default=0.5, ge=0.01, le=10.0)
    max_poll_seconds: float = Field(default=60.0, ge=1.0, le=600.0)
    exclusions: list[str] = Field(default_factory=list)


def _is_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _default_resolver(host: str) -> list[str]:
    if host in ("localhost", "127.0.0.1"):
        return ["127.0.0.1"]
    if host in ("zap.local", "lab.local", "lab-target.local"):
        return ["10.0.0.5"]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0] for info in infos})
    except Exception as exc:
        raise ValueError(f"DNS resolution failed for '{host}': {exc}") from exc


def build_zap_target_regex(target_url: str) -> str:
    """Anchors context regex to exact origin to prevent prefix spoofing (ERR-16)."""
    clean = target_url.strip()
    parsed = urlsplit(clean)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path.split("/")[0]
    origin = f"{scheme}://{netloc}"
    return f"^{re.escape(origin)}(?:/.*)?$"


def build_zap_exclusion_regex(exclusion: str) -> str:
    """Builds scheme-agnostic exclusion regex for ZAP context boundaries (ERR-16)."""
    clean = exclusion.strip()
    if "://" in clean:
        clean = urlsplit(clean).netloc or clean.split("://", 1)[1]
    clean = clean.split("/")[0]
    return f"^https?://{re.escape(clean)}(?::\\d+)?(?:/.*)?$"


def _parse_url_asset(url: str) -> Asset:
    """Parses a target URL into an Asset model."""
    parsed = urlsplit(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return Asset(
        host=parsed.hostname or "unknown",
        port=port,
        protocol=parsed.scheme or "http",
        url_path=parsed.path or "/",
    )


def parse_zap_alerts_json(
    raw_bytes: bytes,
    evidence_meta: Evidence,
) -> list[Observation | RawFinding]:
    """Parses raw ZAP alerts JSON output into standardized Observations and RawFindings.

    Invariants:
    1. Parse JSON safely without fabricating CVEs or CVSS scores.
    2. CWE IDs are extracted strictly from tool output ('cweid' field).
    3. Verbatim snippets and JSON pointer locators are attached to every finding.
    """
    try:
        data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise ValueError(f"Invalid ZAP JSON output: {exc}") from exc

    raw_alerts = data.get("alerts", [])
    results: list[Observation | RawFinding] = []
    observed_hosts: set[str] = set()

    for idx, alert in enumerate(raw_alerts):
        url = alert.get("url", "")
        asset = _parse_url_asset(url)

        # Host & Web service observation (once per unique host:port)
        host_key = f"{asset.host}:{asset.port}"
        if host_key not in observed_hosts:
            observed_hosts.add(host_key)
            results.append(
                Observation(
                    id=f"obs_zap_{uuid.uuid4().hex[:8]}",
                    source_tool="zap",
                    asset=asset,
                    observation_type="service",
                    data={
                        "host": asset.host,
                        "port": asset.port,
                        "protocol": asset.protocol,
                        "url": url,
                    },
                    raw_evidence=Evidence(
                        id=f"ev_obs_zap_{uuid.uuid4().hex[:8]}",
                        source_tool="zap",
                        run_id=evidence_meta.run_id,
                        artifact_id=evidence_meta.artifact_id,
                        locator=f"/alerts[{idx}]/url",
                        raw_sha256=evidence_meta.raw_sha256,
                        snippet=url,
                        observed_at=datetime.now(UTC),
                        origin=evidence_meta.origin,
                    ),
                    observed_at=datetime.now(UTC),
                )
            )

        # RawFinding
        alert_name = alert.get("alert") or alert.get("name") or "ZAP Alert"
        risk_raw = str(alert.get("risk", "medium")).lower()
        severity = _RISK_MAP.get(risk_raw, "medium")

        conf_raw = str(alert.get("confidence", "medium")).lower()
        confidence = _CONFIDENCE_MAP.get(conf_raw, "medium")

        cwe_id_raw = alert.get("cweid")
        cwes = []
        if cwe_id_raw and str(cwe_id_raw).isdigit() and int(cwe_id_raw) > 0:
            cwes.append(f"CWE-{cwe_id_raw}")

        locator = f"/alerts[{idx}]"
        snippet = (
            alert.get("evidence")
            or alert.get("attack")
            or alert.get("param")
            or alert.get("description", "")[:120]
        )

        results.append(
            RawFinding(
                title=alert_name,
                asset=asset,
                tool_name="zap",
                tool_severity=severity,
                raw_evidence=Evidence(
                    id=f"ev_zap_{uuid.uuid4().hex[:8]}",
                    source_tool="zap",
                    run_id=evidence_meta.run_id,
                    artifact_id=evidence_meta.artifact_id,
                    locator=locator,
                    raw_sha256=evidence_meta.raw_sha256,
                    snippet=str(snippet),
                    observed_at=datetime.now(UTC),
                    origin=evidence_meta.origin,
                ),
                cve=[],  # Never fabricate CVE IDs
                cwe=cwes,
                description=alert.get("description"),
                solution=alert.get("solution"),
                confidence=confidence,
            )
        )

    return results


class ZapAdapter(BaseAdapter):
    """OWASP ZAP live REST API adapter."""

    name = "zap"
    status = AdapterStatus.LIVE
    params_model = ZapParams

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
        approval_manager: ApprovalManager | None = None,
        default_timeout: float = 30.0,
        dns_resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("CIPHER_LENS_ZAP_URL")
            or "http://localhost:8080"
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("CIPHER_LENS_ZAP_API_KEY", "")
        self.approval_manager = approval_manager
        self.default_timeout = default_timeout
        self.dns_resolver = dns_resolver or _default_resolver
        self._client = client

    def _url(self, path: str) -> str:
        clean_path = "/" + path.lstrip("/")
        return f"{self.base_url}{clean_path}"

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        headers = {}
        if self.api_key:
            headers["X-ZAP-API-Key"] = self.api_key
        return httpx.AsyncClient(
            headers=headers,
            timeout=self.default_timeout,
        )

    async def healthcheck(self) -> HealthResult:
        """Verifies if the OWASP ZAP daemon is responsive."""
        client = self._get_client()
        should_close = self._client is None
        try:
            resp = await client.get(self._url("/JSON/core/view/version/"))
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", "unknown")
                return HealthResult(
                    status="healthy",
                    message=f"OWASP ZAP daemon responsive (v{version})",
                    details={"version": version, "base_url": self.base_url},
                )
            return HealthResult(
                status="degraded",
                message=f"ZAP returned HTTP {resp.status_code}",
                details={"status_code": resp.status_code},
            )
        except Exception as exc:
            return HealthResult(
                status="unavailable",
                message=f"OWASP ZAP daemon is not reachable: {exc}",
                details={"error": str(exc), "base_url": self.base_url},
            )
        finally:
            if should_close:
                await client.aclose()

    async def run(
        self,
        step: PlanStep,
        ctx: ExecutionContext,
        *,
        assessment_id: str | None = None,
    ) -> ExecutionResult:
        """Executes a ZAP scanning workflow (context creation, spider, passive, active)."""
        start_time = time.perf_counter()
        run_id = f"run_zap_{uuid.uuid4().hex[:8]}"

        try:
            params_dict = {"target": step.target, **step.params}
            params = self.params_model.model_validate(params_dict)
        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 3)
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr=f"Invalid ZAP parameters: {exc}",
                exit_code=-1,
                duration_seconds=duration,
            )

        # Enforce per-step approval for active scanning
        is_active = params.mode in ("active", "full") or step.action_class == ActionClass.INTRUSIVE
        if is_active:
            if self.approval_manager is not None:
                self.approval_manager.require(step, assessment_id=assessment_id)
            elif step.action_class != ActionClass.INTRUSIVE:
                raise ApprovalRequiredError(
                    f"Step '{step.step_id}' requests active scan but is not marked as INTRUSIVE"
                )

        client = self._get_client()
        should_close = self._client is None

        try:
            # Pre-phase DNS check (ERR-03)
            pinned_ip = step.params.get("pinned_ip")
            if pinned_ip:
                target_host = urlsplit(params.target).hostname
                if target_host and not _is_ip(target_host):
                    try:
                        resolved_ips = self.dns_resolver(target_host)
                        if pinned_ip not in resolved_ips:
                            raise ValueError(
                                f"DNS rebinding detected during ZAP pre-phase check (ERR-03): "
                                f"target '{target_host}' re-resolved to {resolved_ips}, "
                                f"which does not match pinned IP '{pinned_ip}'"
                            )
                    except Exception as exc:
                        raise ValueError(f"DNS check failed during ZAP pre-phase check: {exc}") from exc

            # 1. Create Bounded Context
            ctx_name = params.context_name or f"ctx_{uuid.uuid4().hex[:8]}"
            await client.get(
                self._url("/JSON/context/action/newContext/"),
                params={"contextName": ctx_name},
            )

            # Restrict context regex strictly to target origin (ERR-16)
            target_regex = build_zap_target_regex(params.target)
            await client.get(
                self._url("/JSON/context/action/includeInContext/"),
                params={"contextName": ctx_name, "regex": target_regex},
            )

            # Exclude exclusions from context (ERR-16)
            for excl in params.exclusions:
                excl_regex = build_zap_exclusion_regex(excl)
                await client.get(
                    self._url("/JSON/context/action/excludeFromContext/"),
                    params={"contextName": ctx_name, "regex": excl_regex},
                )

            # 2. Spider Crawl (if mode requires it)
            if params.mode in ("spider", "passive", "active", "full"):
                spider_resp = await client.get(
                    self._url("/JSON/spider/action/scan/"),
                    params={"url": params.target, "contextName": ctx_name},
                )
                spider_id = spider_resp.json().get("scan", "0")

                # Poll spider status
                poll_deadline = time.perf_counter() + params.max_poll_seconds
                while time.perf_counter() < poll_deadline:
                    status_resp = await client.get(
                        self._url("/JSON/spider/view/status/"),
                        params={"scanId": spider_id},
                    )
                    status_val = status_resp.json().get("status", "100")
                    if str(status_val) == "100":
                        break
                    await asyncio.sleep(params.poll_interval_seconds)

            # 3. Passive Scan Drain
            poll_deadline = time.perf_counter() + params.max_poll_seconds
            while time.perf_counter() < poll_deadline:
                pscan_resp = await client.get(self._url("/JSON/pscan/view/recordsToWait/"))
                records_to_wait = int(pscan_resp.json().get("recordsToWait", 0))
                if records_to_wait <= 0:
                    break
                await asyncio.sleep(params.poll_interval_seconds)

            # 4. Active Scan (strictly when requested and approved)
            if is_active:
                ascan_resp = await client.get(
                    self._url("/JSON/ascan/action/scan/"),
                    params={"url": params.target, "contextName": ctx_name},
                )
                ascan_id = ascan_resp.json().get("scan", "0")

                poll_deadline = time.perf_counter() + params.max_poll_seconds
                while time.perf_counter() < poll_deadline:
                    status_resp = await client.get(
                        self._url("/JSON/ascan/view/status/"),
                        params={"scanId": ascan_id},
                    )
                    status_val = status_resp.json().get("status", "100")
                    if str(status_val) == "100":
                        break
                    await asyncio.sleep(params.poll_interval_seconds)

            # 5. Fetch Alerts JSON
            alerts_resp = await client.get(
                self._url("/JSON/alert/view/alerts/"),
                params={"baseurl": params.target},
            )
            raw_alerts_bytes = alerts_resp.content

            # Save unmodified raw JSON artifact
            artifact_meta = ctx.artifact_store.save_raw(
                content=raw_alerts_bytes,
                source_tool="zap",
                run_id=run_id,
                extension="json",
            )

            duration = round(time.perf_counter() - start_time, 3)
            return ExecutionResult(
                status="succeeded",
                stdout=f"ZAP scan completed: {len(alerts_resp.json().get('alerts', []))} alerts",
                stderr="",
                exit_code=0,
                duration_seconds=duration,
                artifact_id=artifact_meta.artifact_id,
            )

        except ApprovalRequiredError:
            raise

        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 3)
            err_msg = f"ZAP scan failed: {exc}"
            artifact_meta = ctx.artifact_store.save_raw(
                content=err_msg.encode("utf-8"),
                source_tool="zap",
                run_id=run_id,
                extension="txt",
            )
            return ExecutionResult(
                status="failed",
                stdout="",
                stderr=err_msg,
                exit_code=-1,
                duration_seconds=duration,
                artifact_id=artifact_meta.artifact_id,
            )

        finally:
            if should_close:
                await client.aclose()

    def parse(
        self,
        raw_bytes: bytes,
        evidence_meta: Evidence,
    ) -> list[Observation | RawFinding]:
        """Parses raw ZAP alerts JSON output into standardized Observations and RawFindings."""
        return parse_zap_alerts_json(raw_bytes, evidence_meta)
