"""Failure and Chaos Engineering Subsystem (Task A14, Master Plan §7 Day 6).

Implements CLI/UI chaos switches to simulate real-world failure modes:
1. kill_zap_mid_scan: Terminate scanner mid-execution (SIGKILL, exit 137).
2. slow_nmap: Trigger execution timeout (status="timed_out").
3. malformed_xml: Injects corrupted / truncated XML into parsers; ensures defusedxml handles safely.
4. llm_down: Simulates AI provider failure; verifies deterministic rule-based fallback.
5. nvd_down: Simulates NVD/EPSS outage; verifies graceful fallback without fabricated data.
"""

import logging
from dataclasses import dataclass
from typing import Any

from cipher_lens.adapters.base import BaseAdapter, ExecutionResult
from cipher_lens.models.findings import Evidence

logger = logging.getLogger(__name__)


@dataclass
class ChaosConfig:
    """Configurable switches to simulate runtime failures."""

    kill_zap_mid_scan: bool = False
    slow_nmap: bool = False
    malformed_xml: bool = False
    llm_down: bool = False
    nvd_down: bool = False


class ChaosManager:
    """Coordinates fault injection, error containment, and limitations recording."""

    def __init__(self, config: ChaosConfig | None = None) -> None:
        self.config = config or ChaosConfig()
        self._limitations: dict[str, list[str]] = {}

    def intercept_tool_execution(
        self,
        tool: str,
        argv: list[str],
    ) -> tuple[bool, ExecutionResult | None]:
        """Intercepts subprocess tool execution if corresponding chaos switch is active."""
        tool_lower = tool.lower()
        if self.config.kill_zap_mid_scan and tool_lower == "zap":
            logger.warning("CHAOS: Simulating mid-scan kill on ZAP")
            return (
                True,
                ExecutionResult(
                    status="failed",
                    exit_code=137,
                    stdout="",
                    stderr="Process terminated by SIGKILL (chaos switch: kill_zap_mid_scan)",
                    duration_seconds=1.2,
                ),
            )

        if self.config.slow_nmap and tool_lower == "nmap":
            logger.warning("CHAOS: Simulating execution timeout on Nmap")
            return (
                True,
                ExecutionResult(
                    status="timed_out",
                    exit_code=-1,
                    stdout="",
                    stderr="Execution timed out after 30s (chaos switch: slow_nmap)",
                    duration_seconds=30.0,
                ),
            )

        return False, None

    def corrupt_content(self, content: bytes, tool: str = "generic") -> bytes:
        """Injects syntax corruption or truncation if malformed_xml switch is active."""
        if self.config.malformed_xml:
            logger.warning("CHAOS: Corrupting XML output for tool %s", tool)
            return b"<?xml version='1.0' encoding='UTF-8'?><corrupted_unclosed_tag>corrupted by chaos switch"
        return content

    def safe_parse(
        self,
        adapter: BaseAdapter,
        raw_bytes: bytes,
        ev_meta: Evidence,
    ) -> tuple[list[Any], str | None]:
        """Executes adapter parse with defusedxml protection, catching corruption safely."""
        try:
            items = adapter.parse(raw_bytes, ev_meta)
            return items, None
        except Exception as exc:
            err_msg = f"Failed to parse output from {adapter.name}: {exc}"
            logger.error("CHAOS PARSE ERROR: %s", err_msg)
            return [], err_msg

    def add_limitation(self, assessment_id: str, note: str) -> None:
        """Records an assessment gap or failure limitation note."""
        if assessment_id not in self._limitations:
            self._limitations[assessment_id] = []
        if note not in self._limitations[assessment_id]:
            self._limitations[assessment_id].append(note)

    def get_limitations(self, assessment_id: str) -> list[str]:
        """Retrieves recorded limitations for an assessment."""
        return list(self._limitations.get(assessment_id, []))
