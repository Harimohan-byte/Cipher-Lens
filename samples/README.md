# Golden Samples

This directory contains **synthetic, sanitized sample files** for testing and documentation.

> [!IMPORTANT]
> **None of these files contain real scan output.** They are hand-crafted synthetic examples
> that match the schema of real tool output but contain only fictional lab targets
> (`10.0.0.5`, `lab-target.local`). They have never been run against any real host.

## Files

| File | Tool | Origin | Purpose |
| --- | --- | --- | --- |
| `nmap_sample.xml` | Nmap | synthetic | Golden parse fixture, argv builder reference |
| `nikto_sample.xml` | Nikto | synthetic | Golden parse fixture, web finding reference |
| `cisa_kev_sample.json` | CISA KEV | sample | Synthetic snapshot for offline exploitability enrichment |

## Labeling Convention

All synthetic fixtures are labeled with:
- XML comment: `<!-- SYNTHETIC TEST FIXTURE: origin=sample, ... -->`
- Evidence records carry `origin="sample"` (per AGENTS.md Rule 12)

## Usage

These samples represent expected tool formats for reference.
`tests/adapters/test_nmap_parser.py` and `tests/adapters/test_nikto.py` consume fixtures under `tests/fixtures/`.
They are **NOT** to be used as evidence in real VAPT reports.

If you want to add a new sample:
1. Generate it synthetically (do not export from a real scan).
2. Sanitize all hostnames/IPs to use RFC 1918 private addresses (`10.0.0.0/8`) or RFC 5737 documentation ranges (`192.0.2.0/24`).
3. Add the `<!-- SYNTHETIC TEST FIXTURE -->` XML comment as the first comment.
4. Register it in this README.

