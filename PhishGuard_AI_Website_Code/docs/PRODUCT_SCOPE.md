# PhishGuard AI — Product scope and implementation status

## Included in this MVP package

- Responsive Flask interface and existing explainable URL scan result.
- Rule-based URL indicator score and separate experimental ML signal.
- SQLite scan history scoped to the current account/session for newly created records.
- Account registration and login with password hashing; optional admin bootstrap via environment variables.
- Role-gated analyst/admin console for report triage and status changes.
- CSRF token checks for state-changing requests, in-process rate limiting for sensitive endpoints, request-size cap and security response headers.
- Five learning modules, a five-question quiz, progress tracking, and fictional phishing-email simulation.
- Local phishing report intake and analyst review history.
- Versioned JSON endpoints for auth, scans, reports, training modules and CSRF token retrieval.
- Audit log records for key actions; IP values are stored as short one-way hashes.

## Deliberate limitations

This is a local academic MVP, not a production-ready threat-intelligence service. The URL scanner does not fetch the destination page, follow redirects, or safely detonate files. DNS resolution and optional WHOIS lookup may disclose the hostname to DNS/WHOIS infrastructure. The bundled ML model has known training-data quality problems and its confidence is uncalibrated. Reports are stored locally and are not automatically submitted to Google Safe Browsing, CERT-In, a bank, or law enforcement.

## Before public deployment

- Production startup now requires a strong `FLASK_SECRET` and `TRUSTED_HOSTS`, refuses debug mode, sets secure session cookies, and requires Waitress behind a TLS reverse proxy. The reverse proxy, TLS certificates, HSTS, firewalling, monitoring/alerting and log rotation must still be configured and maintained by the operator.
- Replace the in-process rate limiter with Redis-backed rate limiting for multiple workers.
- Move SQLite to PostgreSQL for multi-user concurrent production use and add schema migrations.
- Add email verification, account recovery, MFA, session revocation, and review the implemented default retention policy against legal/privacy requirements.
- Review CSRF and authentication for the exact deployment topology; add automated security testing and dependency scanning.
- Add SSRF protections before any future feature fetches submitted URLs. Do not fetch user-provided URLs from the web server without a hardened isolated fetch service, IP-range blocking, redirect validation, and egress restrictions.
- Improve and independently evaluate the model on a deduplicated, representative dataset before presenting predictive performance claims.
- Integrate an external reporting provider only after verifying its official API, credentials, data policy and terms.
- Configure and test scheduled encrypted off-host backups, restore procedures, alerting, and the 90/365-day retention cleanup process.
