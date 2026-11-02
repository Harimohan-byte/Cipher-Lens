"""Tool adapters for Cipher-Lens."""

from cipher_lens.adapters.base import (
    AdapterStatus,
    BaseAdapter,
    ExecutionContext,
    ExecutionResult,
    HealthResult,
)
from cipher_lens.adapters.matrix import build_matrix, render_markdown
from cipher_lens.adapters.nikto import NiktoAdapter, NiktoParams, build_nikto_argv, parse_nikto_xml
from cipher_lens.adapters.nmap import NmapAdapter, NmapParams, build_nmap_argv, parse_nmap_xml

__all__ = [
    "AdapterStatus",
    "BaseAdapter",
    "ExecutionContext",
    "ExecutionResult",
    "HealthResult",
    "NmapAdapter",
    "NmapParams",
    "build_nmap_argv",
    "parse_nmap_xml",
    "NiktoAdapter",
    "NiktoParams",
    "build_nikto_argv",
    "parse_nikto_xml",
    "build_matrix",
    "render_markdown",
]
