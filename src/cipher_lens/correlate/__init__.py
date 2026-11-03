"""Correlation, normalization, and standards mapping package."""

from cipher_lens.correlate.dedup import compute_correlation_key, correlate_findings
from cipher_lens.correlate.normalize import (
    normalize_asset,
    normalize_finding,
    normalize_severity,
    normalize_url_path,
)
from cipher_lens.correlate.standards import StandardsMapper, StandardsMapping
from cipher_lens.correlate.status import evaluate_status_and_confidence

__all__ = [
    "normalize_asset",
    "normalize_finding",
    "normalize_severity",
    "normalize_url_path",
    "compute_correlation_key",
    "correlate_findings",
    "evaluate_status_and_confidence",
    "StandardsMapper",
    "StandardsMapping",
]

