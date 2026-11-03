"""Risk scoring implementation (B14, Master Plan §8.3).

Published heuristic formula:
score = 100 * (0.35 * severity + 0.25 * exploitability + 0.15 * exposure + 0.10 * asset_criticality + 0.15 * confidence)

Invariants:
1. Monotonicity: Higher CVSS directly increases severity and total score.
2. KEV-boost: CISA KEV presence elevates exploitability to 1.0.
3. Missing-data transparency: Missing signals use documented defaults with explicit source annotations.
4. Each factor retains value (0-1), source, and description.
"""

from pathlib import Path

import yaml

from cipher_lens.enrichment.service import CveEnrichment
from cipher_lens.models.findings import FactorValue, Finding, RiskScore

_DEFAULT_WEIGHTS = {
    "severity": 0.35,
    "exploitability": 0.25,
    "exposure": 0.15,
    "asset_criticality": 0.10,
    "confidence": 0.15,
}

_DEFAULT_SEVERITY_BANDS = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "info": 0.0,
}

_DEFAULT_CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}

_DEFAULT_EXPOSURE_WEIGHTS = {
    "external": 1.0,
    "internal": 0.5,
    "isolated": 0.2,
    "default": 0.5,
}

_DEFAULT_CRITICALITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "default": 0.5,
}

_DEFAULT_RISK_BANDS = {
    "critical": 80.0,
    "high": 60.0,
    "medium": 40.0,
    "low": 20.0,
    "informational": 0.0,
}


class RiskScorer:
    """Calculates transparent composite risk scores with detailed factor breakdowns."""

    def __init__(self, config: dict) -> None:
        self.version = config.get("version", "1.0.0")
        self.weights = {**_DEFAULT_WEIGHTS, **config.get("weights", {})}
        self.severity_bands = {**_DEFAULT_SEVERITY_BANDS, **config.get("severity_bands", {})}
        self.confidence_weights = {**_DEFAULT_CONFIDENCE_WEIGHTS, **config.get("confidence_weights", {})}
        self.exposure_weights = {**_DEFAULT_EXPOSURE_WEIGHTS, **config.get("exposure_weights", {})}
        self.criticality_weights = {**_DEFAULT_CRITICALITY_WEIGHTS, **config.get("criticality_weights", {})}
        self.risk_bands = {**_DEFAULT_RISK_BANDS, **config.get("risk_bands", {})}

    @classmethod
    def load(cls, config_path: Path | str) -> "RiskScorer":
        """Loads weights and thresholds from YAML configuration."""
        p = Path(config_path)
        if not p.exists():
            return cls({})
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    def score_finding(
        self,
        finding: Finding,
        enrichment: CveEnrichment | None = None,
        scope_tags: dict[str, str] | None = None,
    ) -> RiskScore:
        """Calculates normalized composite risk score and factor breakdown."""
        tags = scope_tags or {}
        factors: dict[str, FactorValue] = {}

        # 1. Severity factor (CVSS / 10 if present, else mapped tool band)
        if finding.cvss and finding.cvss.score is not None:
            sev_val = min(max(finding.cvss.score / 10.0, 0.0), 1.0)
            sev_src = f"cvss_{finding.cvss.source}"
            sev_desc = f"CVSS {finding.cvss.version} base score of {finding.cvss.score}"
        else:
            band = finding.tool_severity.lower()
            sev_val = self.severity_bands.get(band, 0.5)
            sev_src = "tool band"
            sev_desc = f"Mapped from tool reported severity band '{finding.tool_severity}'"

        factors["severity"] = FactorValue(value=sev_val, source=sev_src, description=sev_desc)

        # 2. Exploitability factor (KEV -> 1.0, else EPSS percentile, else default)
        if enrichment and enrichment.cisa_kev:
            exp_val = 1.0
            exp_src = "cisa_kev"
            exp_desc = f"Active known exploitation in CISA KEV (Due: {enrichment.cisa_kev_due_date or 'N/A'})"
        elif enrichment and enrichment.epss_percentile is not None:
            exp_val = float(enrichment.epss_percentile)
            exp_src = "epss"
            exp_desc = f"FIRST EPSS percentile {enrichment.epss_percentile:.2f}"
        else:
            exp_val = 0.5
            exp_src = "unavailable"
            exp_desc = "Exploitability intelligence unavailable; neutral baseline applied"

        factors["exploitability"] = FactorValue(value=exp_val, source=exp_src, description=exp_desc)

        # 3. Exposure factor (from scope asset tags)
        exp_tag = tags.get("exposure", "").lower()
        if exp_tag in self.exposure_weights:
            exposure_val = self.exposure_weights[exp_tag]
            exp_source = "scope_tag"
            exp_d = f"Scope asset exposure tag: '{exp_tag}'"
        else:
            exposure_val = self.exposure_weights["default"]
            exp_source = "default"
            exp_d = "Not assessed; default exposure applied"

        factors["exposure"] = FactorValue(value=exposure_val, source=exp_source, description=exp_d)

        # 4. Criticality factor (from scope asset tags)
        crit_tag = tags.get("criticality", "").lower()
        if crit_tag in self.criticality_weights:
            crit_val = self.criticality_weights[crit_tag]
            crit_source = "scope_tag"
            crit_d = f"Scope asset criticality tag: '{crit_tag}'"
        else:
            crit_val = self.criticality_weights["default"]
            crit_source = "default"
            crit_d = "Not assessed; default asset criticality applied"

        factors["asset_criticality"] = FactorValue(value=crit_val, source=crit_source, description=crit_d)

        # 5. Confidence factor
        conf_val = self.confidence_weights.get(finding.confidence.lower(), 0.6)
        factors["confidence"] = FactorValue(
            value=conf_val,
            source="correlation_confidence",
            description=f"Finding confidence rating '{finding.confidence}'",
        )

        # Calculate composite score
        total_score = 100.0 * (
            self.weights["severity"] * factors["severity"].value
            + self.weights["exploitability"] * factors["exploitability"].value
            + self.weights["exposure"] * factors["exposure"].value
            + self.weights["asset_criticality"] * factors["asset_criticality"].value
            + self.weights["confidence"] * factors["confidence"].value
        )
        total_score = round(min(max(total_score, 0.0), 100.0), 1)

        # Assign risk band
        band = "informational"
        for b_name, threshold in sorted(self.risk_bands.items(), key=lambda x: x[1], reverse=True):
            if total_score >= threshold:
                band = b_name
                break

        return RiskScore(
            total=total_score,
            band=band,
            factors=factors,
            weights_version=self.version,
        )

