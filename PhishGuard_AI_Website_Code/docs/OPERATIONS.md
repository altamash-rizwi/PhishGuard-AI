# Operations runbook (local MVP)

## Startup

- Install requirements in a virtual environment.
- Set `APP_ENV=development` for local work.
- Keep `FLASK_DEBUG=0` outside local debugging.
- Optionally set `PHISHGUARD_ADMIN_EMAIL` and `PHISHGUARD_ADMIN_PASSWORD` before startup to bootstrap an admin.
- Start with `py app/app.py`; default bind is `127.0.0.1:5000`.

## Production startup

- Set `APP_ENV=production`, `FLASK_DEBUG=0`, a unique `FLASK_SECRET` of at
  least 32 bytes, and `TRUSTED_HOSTS` to the comma-separated public hostnames.
  The app refuses production startup if these requirements are missing.
- Run `waitress-serve --listen=127.0.0.1:5000 wsgi:app` behind a maintained
  reverse proxy that terminates TLS. Keep the Waitress port private.
- The Render Blueprint uses the paid `starter` web-service plan and a 1 GB
  persistent disk mounted at `/var/data`; SQLite is configured at
  `/var/data/scan_history.db`. The attached disk requires a single service
  instance. Review current compute and disk pricing in Render before applying
  the Blueprint; this configuration can incur charges. If the service name or
  custom domains change, update `TRUSTED_HOSTS` to the exact public hostnames.
- The Blueprint is at the Git repository root as `render.yaml`; its `rootDir`
  points to `PhishGuard_AI_Website_Code`. Configure the initial admin email
  and a unique password in Render's environment settings; never commit
  credentials.
- Configure HTTPS redirects, HSTS, firewalling, access controls, and log
  rotation at the reverse proxy/host. Flask's development server is blocked
  when `APP_ENV=production`.
- Store secrets in a deployment secret manager; do not put real values in
  `.env`, source control, or process logs.

## Health checks

- Check `/healthz` for process/database readiness; it returns 200 when SQLite
  responds and 503 when the database check fails. It does not prove that DNS,
  WHOIS, model inference, or external network services are available.
- Open `/` and `/scanner`.
- Submit a public test URL such as `example.com`; expect an indicator-based result and no destination-page fetch.
- Open `/education`, complete a lesson, take `/quiz`, then check `/progress`.
- Submit a fictional URL to `/report-phishing`; confirm it appears in `/admin` after signing in as an analyst/admin.
- Check `/api/v1/training/modules` and `/api/v1/csrf`.

## Data and backup

The default local SQLite database is `app/scan_history.db`. Render stores the
production SQLite database at `/var/data/scan_history.db` on its persistent
disk. Create a consistent live backup
with `py scripts\backup_database.py`; backups are stored in the ignored
`backups/` directory by default. Restrict access, encrypt backups at rest, keep
off-host copies, and regularly test restoring into a separate database.
Set `DB_PATH=/var/data/scan_history.db` for the backup/retention scripts when
running them against the Render database. A persistent disk survives service
deploys but is not an off-host backup; configure and test off-host backups
before accepting real user data.

The default retention policy is 90 days for scans, reports, learning progress,
and quiz attempts, and 365 days for audit and report-review history. Review
first with `py scripts\retention_cleanup.py` (dry run). After verifying a
backup, apply with `py scripts\retention_cleanup.py --apply`. Schedule both
tasks and document any legally required changes to these periods before
collecting real user data.

## Incident / abuse handling

- Disable an affected account in the `users.is_active` field if needed.
- Review `audit_logs` and report status history.
- Rotate `FLASK_SECRET` if session cookies may be compromised; this invalidates existing sessions.
- Do not investigate submitted links by opening them on the app server or an analyst workstation. Use an isolated, controlled analysis environment if that capability is added later.
