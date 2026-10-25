# PhishGuard AI — Complete Product MVP

A cybersecurity web application prototype for explainable URL analysis, phishing-awareness learning, quizzes, user progress, report intake and analyst triage.

## Quick start (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
$env:APP_ENV = "development"
$env:FLASK_SECRET = (py -c "import secrets; print(secrets.token_hex(32))")
py app/app.py
```

Open `http://127.0.0.1:5000`.
If no secret is supplied in development, a random temporary key is generated;
existing sessions will expire when the process restarts.

## Production deployment (starting point only)

This is not a one-command public deployment. Put the app behind a maintained
HTTPS reverse proxy, keep the Waitress listener bound to localhost, and provide
production secrets through the hosting platform's secret manager:

```powershell
$env:APP_ENV = "production"
$env:FLASK_DEBUG = "0"
$env:FLASK_SECRET = (py -c "import secrets; print(secrets.token_hex(32))")
$env:TRUSTED_HOSTS = "phishguard.example.com"
waitress-serve --listen=127.0.0.1:5000 wsgi:app
```

The production app refuses to start without a 32-byte `FLASK_SECRET` and
`TRUSTED_HOSTS`, forces secure session cookies, and does not use Flask's
development server. Configure TLS, HTTP-to-HTTPS redirects, HSTS, access
controls, log rotation, and host-level firewall rules at the reverse proxy and
operating-system layers. Do not use the local development setup scripts in
production.

### Render Free demo

The `PhishGuard_AI_Website_Code/render.yaml` Blueprint configures
`phishguard-ai` on Render's Free plan with Waitress, `/healthz`, a generated
application secret, and the service hostname allowlist. SQLite is placed at
`/tmp/scan_history.db` on ephemeral storage. Free services spin down after
inactivity, can take time to wake, and lose local data on spin-down, restart,
or redeploy. **This is a demo deployment only: do not use it for real users or
data that must be retained.** Use a paid service with persistent storage or a
managed database for production.

The existing Render Blueprint is configured to read
`PhishGuard_AI_Website_Code/render.yaml`. Connect the repository to Render and
use that path when creating or updating the Blueprint. Configure the initial
admin email and a unique password directly in Render's environment settings;
never commit credentials. Keep `TRUSTED_HOSTS` aligned with the actual Render
hostname and any custom domains.

The Blueprint prompts you to provide the initial admin email and a unique
password through Render's environment settings; use a password of at least 12
characters and keep it out of source control. `TRUSTED_HOSTS` must exactly
match the service's assigned Render hostname (`phishguard-ai-7pzp.onrender.com`
for the current deployment) and any custom domains. If Render assigns a
different hostname or you add a custom domain, update the environment variable
in the Render dashboard; otherwise Flask will reject requests, including health
checks.

Do not accept real user reports on this Free demo because its local database is
ephemeral. For production, configure durable storage, encrypted off-host
backups, retention jobs, monitoring/alerting, and a tested restore process.

For a local admin account, set both variables before starting the app (use your own credentials):

```powershell
$env:PHISHGUARD_ADMIN_EMAIL = "your-admin-email@example.com"
$env:PHISHGUARD_ADMIN_PASSWORD = "a-unique-password-at-least-12-chars"
py app/app.py
```

On startup, the app creates the account or promotes the matching account to the `admin` role. Do not use the example credentials from `.env.example` as real credentials.

## Main user journey

Home → Scan URL → Review rule reasons and ML signal → Learn red flags → Try phishing-email simulation → Take quiz → View progress → Report a suspicious URL.

## Operations

- `/admin` — analyst/admin report queue and audit log
- `/api/v1/...` — versioned JSON endpoints; see `docs/API.md`
- `docs/PRODUCT_SCOPE.md` — included features and production gaps
- `docs/ARCHITECTURE.md` — architecture overview
- `docs/MODEL_EVALUATION.md` — dataset, validation results, and limitations
- `docs/FINAL_CHECKLIST.md` — project review checklist

## Security and model limitations

The heuristic score is an indicator summary, not a calibrated probability. The previous toy ML model is disabled and no model is bundled as production-ready. To evaluate a candidate, install requirements and run `python scripts/download_datasets.py`, then `python scripts/train_and_evaluate.py`. This uses PhiUSIIL from UCI with registrable-domain-separated cross-validation. For a strict forward-time external test, run `python scripts/evaluate_live_feeds.py` periodically after candidate training; it collects new PhishTank and Tranco snapshots and reports no metrics until enough post-training samples exist. See `docs/MODEL_EVALUATION.md` for the observed cross-source stress-test failure and readiness requirements. The candidate is not loaded by the app. A low rule score does not prove a site is safe. The server does not open submitted URLs. Reports are saved locally and are not sent to an external organization. Do not deploy publicly without completing the hardening checklist in `docs/PRODUCT_SCOPE.md`.

## Tests

```powershell
py -m pytest -q
```

Dependency versions are pinned in `requirements.txt`; install them before
running the tests or the model evaluation workflow.

## Backups and retention

Create a consistent SQLite backup with
`py scripts\backup_database.py`. Review the retention dry run with
`py scripts\retention_cleanup.py`; after taking and verifying a backup, run
`py scripts\retention_cleanup.py --apply` to delete expired records. Schedule
these tasks with the host's task scheduler, restrict backup access, encrypt
backups at rest, and test restore procedures before accepting real user data.
The default policy retains scans, reports, learning progress and quiz records
for 90 days and audit/review history for 365 days.
