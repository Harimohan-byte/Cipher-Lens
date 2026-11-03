# Cipher-Lens License Compliance & Attribution

**Project License:** MIT License  
**Copyright:** (c) 2026 Cipher-Lens Contributors  

---

## 1. Third-Party Python Dependencies

The following table documents all direct Python dependencies used by Cipher-Lens, their package licenses, and their compatibility with this project:

| Package | Version Range | Upstream License | Purpose / Component |
|---|---|---|---|
| `pydantic` | `>=2.6.0,<3.0.0` | MIT License | Strict schema definitions and input validation |
| `streamlit` | `>=1.32.0,<2.0.0` | Apache License 2.0 | Multi-page operator web interface and dashboard |
| `reportlab` | `>=4.1.0,<5.0.0` | BSD License | NIST SP 800-115 PDF document generation |
| `httpx` | `>=0.27.0,<1.0.0` | BSD License | Asynchronous HTTP client for ZAP API & enrichment |
| `google-genai` | `>=0.1.1,<1.0.0` | Apache License 2.0 | Google Gemini LLM API client |
| `defusedxml` | `>=0.7.1,<1.0.0` | Python Software Foundation | XXE-safe XML parsing for Nmap, Nessus, and Burp |
| `pyyaml` | `>=6.0,<7.0` | MIT License | Configuration loading for risk weights & mappings |
| `pytest` | `>=8.0.0` | MIT License | Automated test suite execution |
| `pytest-asyncio` | `>=0.23.0` | Apache License 2.0 | Asynchronous test execution runner |
| `ruff` | `>=0.3.0` | MIT / Apache 2.0 | Static analysis and code formatting |

---

## 2. Integrated Security Scanners & External Tools

Cipher-Lens coordinates external security tools via policy-enforced adapters. External binaries are executed via standard process invocation (`asyncio.create_subprocess_exec`) and are not linked or redistributed as part of the Cipher-Lens Python package:

| Tool | Minimum Version | Upstream License | License Type | Integration Mode |
|---|---|---|---|---|
| **Nmap** | `>= 7.94` | Nmap Public Source License (NPSL) v0.92 | Copyleft / Source-Available | Live Subprocess (XML parsing via `defusedxml`) |
| **Nikto** | `>= 2.1.6` | GNU General Public License (GPL) v2 | Strong Copyleft | Live Subprocess (JSON/Text parsing) |
| **OWASP ZAP** | `>= 2.15.0` | Apache License 2.0 | Permissive | REST API Client (`httpx` over HTTP) |
| **Burp Suite** | Any | Commercial / Proprietary | Proprietary | Import-Only Parser (XML export) |
| **Tenable Nessus** | Any | Commercial / Proprietary | Proprietary | Import-Only Parser (`.nessus` XML export) |
| **Greenbone OpenVAS**| Any | GNU General Public License (GPL) v2+ | Strong Copyleft | Import-Only Parser (XML export) |

### License Compatibility Analysis
- **Independent Process Execution:** In compliance with Free Software Foundation guidelines and standard copyright law, executing external copyleft binaries (such as Nmap or Nikto) via system process invocation with standard argv arguments over standard input/output streams does not create a derivative work of those tools.
- **Import-Only Decoupling:** Parsers for commercial/copyleft report exports (Burp Suite, Nessus, OpenVAS) only process data files exported by users, maintaining full independence from the upstream scanner binaries.

---

## 3. Data Source Attribution & Terms

Cipher-Lens enriches tool-reported findings using publicly accessible security databases:

1. **National Vulnerability Database (NVD):** Provided by the National Institute of Standards and Technology (NIST), U.S. Department of Commerce. This product uses the NVD API but is not endorsed or certified by the NVD.
2. **CISA Known Exploited Vulnerabilities (KEV) Catalog:** Provided by the Cybersecurity and Infrastructure Security Agency (CISA). Public domain information.
3. **Exploit Prediction Scoring System (EPSS):** Maintained by FIRST (Forum of Incident Response and Security Teams). EPSS data is made available under the Creative Commons Attribution 4.0 International (CC BY 4.0) license.
4. **OWASP Top 10 (2021 Edition):** Provided by the OWASP Foundation under Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
