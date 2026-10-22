# PhishGuard AI — Full User Journey

Home → Scan URL → Result with reasons → Learn red flags → 5-question quiz → View progress → Report phishing.

## New features
- Five short lessons with local completion tracking.
- Five-question multiple-choice quiz with answer explanations.
- Quiz attempt history and learning progress dashboard.
- Phishing URL report form with validation and optional context (maximum 1,000 characters).
- Reports are saved in local SQLite only; they are not forwarded externally. URLs are never opened/fetched.
- Existing heuristic score and experimental ML signal remain separate.

## Windows setup
1. Extract the ZIP.
2. Open PowerShell in the extracted folder.
3. `py -m pip install -r requirements.txt`
4. `py app/app.py`
5. Open `http://127.0.0.1:5000`.
6. Test with `py -m pytest -q`.

## Limitations
This is an academic local prototype, not a live threat-intelligence reporting service. For public deployment add CSRF protection, authentication, rate limiting, secure secret configuration, retention controls and a verified external reporting integration. Model confidence is uncalibrated and the demo dataset has known quality issues.
