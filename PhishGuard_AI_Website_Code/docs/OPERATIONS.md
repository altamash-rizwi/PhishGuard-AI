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
- The current Render Blueprint is a free demo: it starts Waitress on the
  platform port and sets `DB_PATH=/tmp/scan_history.db` without a persistent
  disk. Render free web services spin down after inactivity, and local files are
  lost on spin-down, restart, or redeploy. Do not use this configuration for
  real users or data that must be retained. For production, use a paid service
  with a persistent disk or migrate to a managed database, and configure
  encrypted off-host backups. If the service name or custom domains change,
  update `TRUSTED_HOSTS` to the actual hostnames.
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

The default local SQLite database is `app/scan_history.db`. The Render free
demo stores SQLite at `/tmp/scan_history.db`; that file is ephemeral and must
not be treated as a backup or durable storage. For a paid Render deployment
with a persistent disk, set `DB_PATH` to a location on that disk. Create a
consistent live backup
with `py scripts\backup_database.py`; backups are stored in the ignored
`backups/` directory by default. Restrict access, encrypt backups at rest, keep
off-host copies, and regularly test restoring into a separate database.
Set `DB_PATH` for the backup/retention scripts when managing a durable
database. A persistent disk survives service deploys but is not an off-host
backup.

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
