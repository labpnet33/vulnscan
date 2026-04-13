# VulnScan Website Security Hardening Checklist

This checklist is prioritized for internet-exposed deployments.

## Implementation status (current codebase)

- ✅ Session secret no longer uses a known static fallback.
- ✅ Session cookie hardening defaults applied.
- ✅ Security response headers applied globally.
- ✅ CSRF protection added for authenticated state-changing API requests.
- ✅ Basic rate limiting added for register/login/forgot/reset endpoints.
- ✅ Temporary account lockout added after repeated failed logins.
- ✅ Password policy strengthened (12+ chars, upper/lower/number/symbol).
- ✅ Idle session timeout enforced (configurable).
- ⏳ Remaining items below are deployment and operational controls to complete.

## 1) Immediate (same day)

- Set a strong, random `VULNSCAN_SECRET` in environment variables (at least 32 bytes).
- Serve the app only behind HTTPS (reverse proxy or load balancer).
- Set `VULNSCAN_COOKIE_SECURE=1` in production so session cookies are only sent over HTTPS.
- Restrict inbound access with a firewall/WAF to required ports only (typically 443).
- Remove public access to administrative routes unless authenticated and authorized.
- Rotate any credentials currently stored in plain environment files or scripts.

## 2) Application controls

- Add CSRF protection to state-changing endpoints (`POST`, `PUT`, `DELETE`) when browser sessions are used.
- Add rate limiting to authentication and sensitive routes (`/api/login`, `/api/register`, reset-password flows).
- Implement account lockout/backoff after repeated failed login attempts.
- Enforce stronger password policy:
  - minimum length 12+
  - upper/lower/number/symbol
  - deny common leaked passwords
- Add optional MFA for administrator accounts.
- Ensure every privileged endpoint uses role checks and server-side authorization.

## 3) Transport and headers

- Keep HSTS enabled after HTTPS is fully validated.
- Keep anti-clickjacking and MIME sniffing protections enabled:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
- Add and tune Content Security Policy (CSP) for UI pages.
- Use `Referrer-Policy` and `Permissions-Policy` with minimal privileges.

## 4) Infrastructure hardening

- Run the app with a non-root system user.
- Isolate scan tooling (nmap, nikto, sqlmap, etc.) in dedicated containers/VMs.
- Apply egress restrictions so only required destinations are reachable.
- Separate production DB/network from scanning worker network.
- Enable centralized logging (SIEM) and alerting for suspicious behavior.

## 5) Data and secrets

- Store secrets in a vault (AWS Secrets Manager, Vault, etc.), not in git or scripts.
- Encrypt backups at rest and in transit.
- Minimize retention of scan payload/output containing sensitive host data.
- Scrub PII/secrets from logs.

## 6) Agent security (very important)

- Prefer HTTPS for any agent installer/update endpoint.
- Sign agent scripts/binaries and verify signatures before execution.
- Rotate agent tokens and invalidate on disconnect/re-enroll.
- Restrict which hosts can register agents.
- Audit agent commands and uploaded results.

## 7) Continuous assurance

- Add dependency scanning (e.g., `pip-audit`, `npm audit`) in CI.
- Add static analysis (Bandit/Semgrep) in CI for Python and JS.
- Add DAST against staging before release.
- Patch operating system and security tools on a fixed schedule.

## Suggested quick verification commands

```bash
# Python dependency risk scan
pip-audit

# Python code security lint
bandit -r . -x vulnscan-ui,node_modules

# Frontend dependency audit
cd vulnscan-ui && npm audit --production
```
