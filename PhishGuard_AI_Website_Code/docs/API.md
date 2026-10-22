# PhishGuard AI JSON API (MVP)

All routes are local to the Flask application and use `/api/v1/` versioning. JSON write requests use the same session cookie and CSRF token protection as the web interface.

## CSRF/session setup

1. `GET /api/v1/csrf` returns a CSRF token and establishes a session cookie.
2. Send that cookie and `X-CSRF-Token: <token>` on write requests.
3. The API login/refresh response returns a replacement CSRF token when appropriate.

## Endpoints

- `POST /api/v1/auth/register` — JSON `{ "email": "user@example.com", "password": "a-long-unique-password" }`
- `POST /api/v1/auth/login` — authenticate using a session cookie
- `POST /api/v1/auth/refresh` — refresh CSRF/session activity for an authenticated session (not a JWT refresh-token implementation)
- `POST /api/v1/auth/logout` — end the session
- `POST /api/v1/scans` — JSON `{ "url": "https://example.com" }`; returns explainable indicators and model metadata
- `GET /api/v1/scans` — list visible scans; accepts optional `status` and `verdict` text filters
- `GET /api/v1/scans/<id>` — retrieve a stored scan
- `POST /api/v1/reports` — JSON `{ "url": "https://example.com/suspicious", "details": "Unexpected message" }`
- `GET /api/v1/reports` — analyst/admin only
- `PATCH /api/v1/reports/<id>/status` — analyst/admin only; JSON `{ "status": "triage", "note": "Review started" }`
- `GET /api/v1/training/modules` — list learning modules

## Report status values

`new`, `triage`, `confirmed`, `false_positive`.

## Safety notes

The scanner does not fetch the submitted page. JSON API responses are a prototype contract and may evolve; this MVP does not yet implement a distributed task queue or production token-refresh system.
