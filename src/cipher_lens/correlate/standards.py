"""Standards mapping module (B13).

Maps vulnerability metadata to:
- OWASP Top 10 (2021 Edition)
- NIST CSF 2.0 functions (Identify, Protect, Detect, Respond, Recover)
- NIST SP 800-115 phases (Planning, Discovery, Attack, Reporting)
- MITRE ATT&CK technique suggestions (labeled as inference/mapping)

Invariant:
Unmapped categories must return 'unmapped', NEVER guessed or fabricated (AGENTS.md Rule 3 / Master Plan B13).
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class StandardsMapping(BaseModel):
    """Mapped standards categories for a vulnerability or plan step."""

    owasp_top_10: list[str] = Field(default_factory=list)
    nist_csf_functions: list[str] = Field(default_factory=list)
    nist_sp_800_115_phase: str = "unmapped"
    attck_techniques: list[str] = Field(default_factory=list)


class StandardsMapper:
    """Loads mappings from configuration and deterministically translates CWE/tools to standards."""

    def __init__(self, raw_config: dict) -> None:
        self._owasp = raw_config.get("owasp_top_10_2021", {})
        self._csf = raw_config.get("nist_csf_2_0", {})
        self._nist_phases = raw_config.get("nist_sp_800_115", {})
        self._attck = raw_config.get("attck_techniques", {})

    @classmethod
    def load(cls, config_path: Path | str) -> "StandardsMapper":
        """Loads standards mapping configuration from YAML file."""
        p = Path(config_path)
        if not p.exists():
            return cls({})
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    def map_finding(self, cwe: list[str], remediation_theme: str | None = None) -> StandardsMapping:
        """Deterministically maps CWEs to OWASP Top 10, NIST CSF 2.0, and ATT&CK techniques."""
        owasp_matches: list[str] = []
        attck_matches: list[str] = []
        csf_matches: list[str] = []

        for w in cwe:
            clean_w = w.upper().strip()
            if clean_w in self._owasp:
                owasp_matches.append(self._owasp[clean_w])
            if clean_w in self._attck:
                attck_matches.append(self._attck[clean_w])

        if remediation_theme and remediation_theme.lower() in self._csf:
            csf_matches.append(self._csf[remediation_theme.lower()])
        elif owasp_matches:
            # Default protect function for security remediations
            csf_matches.append(self._csf.get("injection", "PR.DS"))

        return StandardsMapping(
            owasp_top_10=list(dict.fromkeys(owasp_matches)) or ["unmapped"],
            nist_csf_functions=list(dict.fromkeys(csf_matches)) or ["unmapped"],
            nist_sp_800_115_phase="unmapped",
            attck_techniques=list(dict.fromkeys(attck_matches)) or ["unmapped"],
        )

    def map_step_phase(self, tool_name: str) -> str:
        """Maps tool execution step to NIST SP 800-115 phase."""
        return self._nist_phases.get(tool_name.lower().strip(), "unmapped")

