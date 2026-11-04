# Cipher-Lens Known Limitations

This document records architectural, tool-specific, and platform constraints identified during security audits.

## 1. OWASP ZAP DNS Pinning and IP Targeting (ERR-03)

### Background
CLI tools such as Nmap and Nikto allow direct network traffic destination specification:
- **Nmap**: Target is passed as an IP literal (`nmap <pinned_ip>`), completely bypassing DNS lookups at the transport layer.
- **Nikto**: Target IP literal is passed with `-host <pinned_ip>`, while preserved virtual host headers are provided via `-vhost <hostname>`.

### Constraint
OWASP ZAP operates as an HTTP/HTTPS proxy and scanner daemon driven by URL targets (e.g., `http://app.local:8080/`).
- Passing raw IP literals directly in target URLs breaks:
  1. Virtual host routing (`Host` header resolution).
  2. TLS SNI (Server Name Indication) and certificate validation for HTTPS targets.
- The standard ZAP REST API does not support per-target custom DNS resolver pinning without modifying global JVM or OS resolver configurations.

### Mitigation in Cipher-Lens
To defend against DNS rebinding attacks while maintaining scan capability:
1. **Pre-Phase Resolution Comparison**:
   Immediately before initiating the Spider crawl and Active scan phases, `ZapAdapter` performs a deterministic DNS re-resolution check of the target hostname.
2. **Rebinding Abort**:
   If the freshly resolved IP address differs from the `pinned_ip` established during `PolicyGate.authorize()`, or if resolution fails, execution immediately aborts with an error, preventing out-of-scope scanning.
