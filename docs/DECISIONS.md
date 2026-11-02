# Cipher-Lens decisions log

Every decision that changes how we build goes here with a date and a reason. Newest at the bottom.

| Date | Decision | Reason |
|---|---|---|
| 2026-11-02 | Python 3.12 on every machine, in a project-local `.venv` (`py -3.12 -m venv .venv`); ruff target `py312` | Matches AGENTS.md, CI and the master plan |
| 2026-11-02 | `src/` layout installed with `pip install -e .`; pytest uses `pythonpath = ["src"]` | Imports behave the same in tests, CLI and CI |
| 2026-11-02 | `requirements.txt` keeps version ranges; exact versions of the working environment are in `requirements-lock.txt` (`pip freeze --exclude-editable`) | Reproducible installs without hiding intent |
| 2026-11-02 | `main` is the default, protected branch: no direct pushes, PR with 1 approval from the other person, squash merge, delete branch | Two-person review (plan section 16.3) |
| 2026-11-02 | CI (`.github/workflows/ci.yml`, job `test`) runs ruff and offline pytest only; it never scans and uses no secrets | Plan section 4.1 |
| 2026-11-02 | Authorization reference for the local practice target: "self-hosted practice target" | Plan section 5.1 |
| 2026-11-02 | Integrations as in plan section 1: live = Nmap, Nikto, ZAP; import-only = Nessus, OpenVAS/Greenbone, Burp; manual = Metasploit | Honest and achievable |

## Open items to fill in
- Gemini free-tier model IDs and limits (requests per minute, tokens per minute, requests per day) from AI Studio, plan section 4.2.
- Lab target and exact scope from the organizers, once confirmed.
- GitHub Actions versions: currently `actions/checkout@v6` and `actions/setup-python@v6`; check for newer majors.
