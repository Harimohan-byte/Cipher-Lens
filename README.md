# Cipher-Lens

**AI-Powered Unified VAPT Agent** (conversational, human-supervised penetration-testing assistant)

## Overview
Cipher-Lens is an AI-assisted Vulnerability Assessment and Penetration Testing (VAPT) platform designed for authorized lab environments. It provides human-in-the-loop governance, automated scope enforcement, multi-tool orchestration, evidence correlation, and grounded reporting.

## Safety & Operating Rules
1. **Authorized targets only:** Scans run only against targets explicitly registered in the scope registry.
2. **Deterministic safety gate:** Tool commands are validated and constructed via argument lists; no `shell=True` and no unapproved intrusive actions.
3. **No fabrication:** Observed findings and AI inferences are strictly separated. Findings require cryptographic evidence artifacts.
4. **Hash-chained audit log:** Every state change and decision is cryptographically chained and tamper-evident.
