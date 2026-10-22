# Prototype upgrade notes

## Changed
- `app/app.py`: environment-based Flask secret/debug settings; URL validation; explainable rule-based risk score; separate experimental ML signal; additional URL checks; SQLite migration for `risk_score` and `checks_json`; real dashboard counters and searchable history.
- `app/templates/index.html`: redesigned dashboard with real scan metrics, recent scans, and model-limitations notice.
- `app/templates/scanner.html`: improved input, scan instructions, safety note, and check overview.
- `app/templates/scan_result.html`: detailed report with score band, rule explanations, URL checks, features, model output, and print action.
- `app/templates/history.html`: removed static fabricated rows; displays real database records and search.
- `app/templates/results.html`, `security.html`, `education.html`, `faq.html`, `about.html`: concise consistent pages instead of repeated filler blocks.
- `app/static/css/style.css`: responsive redesign and print styles; templates use a versioned stylesheet URL to avoid stale cache.
- `tests/test_upgrade.py`: regression checks for normalization, scoring explanations, scan report, and history.

## Important limitation
The score is a transparent heuristic indicator score, not a calibrated phishing probability. The bundled model is labeled experimental because the demo dataset has known duplicates and label leakage. The app does not fetch the target page or follow redirects. Optional WHOIS lookup may be unavailable depending on network access.

## Verification status
Python syntax is checked with `py_compile`. Automated Flask tests could not be executed in the current build environment because Flask is not installed here and package installation is blocked by unavailable network access. Run `py -m pip install -r requirements.txt` and `pytest -q` on the project machine before presenting.


## Console visual refresh
- `app/templates/index.html`: replaced the simple hero-first landing page with a dashboard-style intelligence console matching the requested neon blue/cyan reference: top navigation, workspace sidebar, live DB-backed metrics, recent scans, analysis engine status, and available URL-check inventory.
- `app/templates/scanner.html`: added quick-fill URL examples without auto-submitting or changing scan behavior.
- `app/static/css/style.css`: added responsive dashboard styles and cache-busting stylesheet version `v=4` across templates.
- Kept database-backed counts and scan history; did not add fabricated scan records or trend values. Small chart-like bars are decorative only.


## Full user journey integration
- Added lesson completion, five-question quiz, progress dashboard, and local phishing report form.
- Reports are local-only; no external submission or URL fetching occurs.
- Added tests in `tests/test_user_journey.py`.


## Example button fix
- Clicking `example.com` or `URL shortener pattern` now fills the URL field and submits the existing scanner form, so the example runs through the normal scan route.
- The script waits for DOM readiness and prevents duplicate event listeners.
