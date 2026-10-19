# Security Policy

## Supported Versions

We prioritize the security and integrity of SOC Alert Analyzer. Critical security patches and fixes are actively maintained for the latest release branch.

| Version | Supported          | Security Maintenance Status |
| ------- | ------------------ | --------------------------- |
| 1.2.x   | :white_check_mark: | Current Active Stable       |
| 1.1.x   | :x:                | Deprecated                  |
| 1.0.x   | :x:                | Deprecated                  |

---

## Defensive Architecture & Threat Model

SOC Alert Analyzer is designed as a defensive blue-team operations workbench, triage platform, and behavioral host security auditor (EDR-Lite). The application adheres to strict defensive security principles:

1. **Defense-in-Depth Authentication**:
   - Web application sessions use cryptographically secure 256-bit opaque tokens (`soc_...`) stored as `HttpOnly`, `SameSite=Lax`, and `Secure` (when TLS enabled) cookies.
   - Plaintext session tokens are never stored in memory; server-side lookup uses SHA-256 digests.
   - API clients utilize static or rotating tokens passed via `X-API-Key` or `Authorization: Bearer` headers.
2. **Cross-Site Request Forgery (CSRF) Protection**:
   - State-changing browser requests (`POST`, `PUT`, `DELETE`, `PATCH`) require cryptographic CSRF validation matching the `soc_csrf` cookie against the `X-CSRF-Token` header.
3. **Cross-Site WebSocket Hijacking (CSWSH) Defense**:
   - The `/ws/threats` WebSocket endpoint performs strict Origin header validation against configured allowed origins.
   - Single-use, short-lived (60s) tickets (`POST /api/v1/auth/ws-ticket`) prevent credential exposure in URLs or proxy logs.
4. **Data Isolation & Role-Based Access Control**:
   - Role-based permissions (`ADMIN`, `ANALYST`, `VIEWER`) restrict sensitive operational capabilities (such as alert deletion, log ingestion, or live host security audits).
   - Unauthenticated demo viewers only receive sanitized demonstration events (`SIMULATED_DEMO`); genuine host telemetry (`HOST_TELEMETRY`) and raw logs are strictly withheld.
5. **Ingestion Hardening**:
   - File uploads are bounded by `MAX_UPLOAD_SIZE_MB` (default 25 MB) and read via chunked memory-bounded streaming.
   - Executable and archive magic headers (`MZ`, `ELF`, Mach-O, `PK`, `7z`, `Rar`) are rejected.
   - XML parsing uses `defusedxml` to neutralize XML External Entity (XXE) and entity expansion (Billion Laughs) vectors.

---

## Reporting a Vulnerability

If you discover a security vulnerability within this repository, please do **NOT** open a public issue. We appreciate responsible disclosure to give us time to investigate and patch the issue.

### Disclosure Process

1. **Email Advisory**: Send details of the vulnerability to the project maintainer at `karayuuco@gmail.com` with the subject `[SECURITY ADVISORY] SOC Alert Analyzer`.
2. **Include Technical Details**:
   - Description of the vulnerability and attack vector.
   - Affected component(s) (e.g. API endpoint, parser, template, session manager).
   - Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
   - Estimated impact and severity assessment.
3. **Response Timeline**:
   - Initial acknowledgement: within 48 hours.
   - Vulnerability assessment & reproduction: within 5 business days.
   - Remediation patch and release notification: coordinated with the reporter.

---

## Automated Security Verifications

Our continuous integration pipeline automatically enforces the following security checks:
- **Bandit**: AST-based static application security testing (SAST) scanning for common Python vulnerabilities.
- **Pip-Audit**: Dependency scanning cross-referencing published CVE databases (PyPI Advisory Database).
- **Flake8**: Automated syntax, name binding, and code quality checks.
- **Pytest Suite**: Comprehensive unit and integration test coverage for authentication, RBAC, CSRF, and upload constraints.
