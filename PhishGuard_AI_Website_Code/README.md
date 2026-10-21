# PhishGuard AI

**AI-Based Phishing Detection & Secure Website Analysis System**  
Academic prototype · Flask · scikit-learn · SQLite

---

## Overview

PhishGuard AI is a Python/Flask web application that classifies submitted URLs as
*Potentially Phishing* or *Potentially Legitimate* using a TF-IDF + Random Forest
machine-learning pipeline, combined with a live DNS resolution check that confirms
whether the domain actually exists before presenting a result.

This is an academic prototype built for a Problem-Based Learning (PBL) project.
**It does not guarantee that any URL is safe or malicious.**

---

## Project structure

```
PhishGuard_AI_Website_Code/
├── app/
│   ├── app.py                  # Flask application (routes, model loading, DNS check)
│   ├── train_model.py          # Training script (TF-IDF + Random Forest)
│   ├── evaluate_model.py       # Evaluation script (dedup CV, LODO, scheme-swap probes)
│   ├── model.pkl               # Trained Random Forest (sklearn 1.9.0)
│   ├── vectorizer.pkl          # Fitted TF-IDF vectorizer (sklearn 1.9.0)
│   ├── requirements.txt        # Pinned Python dependencies
│   ├── scan_history.db         # SQLite scan history (created on first run)
│   ├── templates/
│   │   ├── index.html
│   │   ├── scanner.html
│   │   ├── scan_result.html
│   │   ├── history.html
│   │   ├── results.html
│   │   ├── security.html
│   │   ├── education.html
│   │   ├── faq.html
│   │   └── about.html
│   └── tests/
│       ├── conftest.py         # pytest fixtures (FLASK_SECRET, temp DB)
│       ├── test_phase1.py      # 36 tests: startup, normalisation, DNS, model
│       ├── test_phase2.py      # 25 tests: dataset integrity, scheme-swap probes
│       └── test_phase3.py      # 34 tests: templates, bare-domain input, history
├── models/
│   ├── final_random_forest.pkl    # Production model copy (sklearn 1.9.0)
│   └── final_tfidf_vectorizer.pkl # Production vectorizer copy (sklearn 1.9.0)
├── data/
│   └── phishing_urls.csv          # 400-row training dataset
├── tests/
│   └── test_app.py                # Original 5-test smoke suite
└── docs/
```

---

## Quick start

```bash
# 1. Create and activate a virtual environment (recommended)
py -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

# 2. Install dependencies
pip install -r app/requirements.txt

# 3. Set the Flask secret key (required in production)
set FLASK_SECRET=your-secret-here       # Windows cmd
# export FLASK_SECRET=your-secret-here  # Linux / macOS

# 4. Run the application
cd app
py app.py
# open http://127.0.0.1:5000
```

If `FLASK_SECRET` is not set, the application starts with a random dev key and
prints a `UserWarning`. This is intentional — never skip this warning in production.

---

## Running the tests

```bash
# From the app/ directory
py -m pytest tests/ -v

# Treat all UserWarnings and InconsistentVersionWarnings as errors
py -m pytest tests/ -v -W error::UserWarning -W error::sklearn.exceptions.InconsistentVersionWarning
```

All 95 tests pass with zero warnings on Python 3.14 / scikit-learn 1.9.0.

---

## How it works

### URL normalisation
Raw input (bare domain, `http://`, or `https://`) is normalised to a full URL.
Only `http://` and `https://` schemes are accepted; anything else is rejected with
an HTTP 302 redirect.

### DNS verification
`socket.getaddrinfo()` is called on the extracted hostname.  
- Domain resolves → ML classification is shown as an additional signal.  
- Domain does not resolve → result is labelled **Unverified / Domain Not Resolving**.  
- DNS lookup errors → result is labelled **Unable to Verify Domain**.

The application **never fetches the submitted URL**, eliminating the SSRF risk that
would arise from blindly requesting user-supplied addresses.

### ML classification
A character-level TF-IDF vectorizer converts the URL string into a feature vector.
A Random Forest classifier (100 trees) predicts label 0 (legitimate) or 1 (phishing).
The raw class-probability score is shown as **Model Score** — not a calibrated
confidence value.

### Scan history
Every completed scan is written to `scan_history.db` (SQLite). The `/history` route
reads and displays all records in reverse-chronological order.

---

## Model limitations (academic prototype)

The bundled training dataset (`data/phishing_urls.csv`) contains **400 rows with
380 exact duplicates** (20 unique URLs). Cross-validated accuracy appears at 1.0 due
to duplicate leakage across train/test folds. A scheme-swap analysis further shows
the model has learned that `http://` correlates with phishing and `https://` with
legitimate — a scheme proxy rather than genuine URL-pattern recognition.

These limitations are documented in `evaluate_model.py` and `docs/`. Do not report
the bundled model's accuracy as final performance in any academic submission without
re-training on a larger, deduplicated dataset.

---

## Environment variables

| Variable | Required | Default | Effect |
|---|---|---|---|
| `FLASK_SECRET` | Recommended | random (dev fallback) | Flask session secret key |
| `FLASK_DEBUG` | No | not set | Set to `1` to enable Flask debug mode |

---

## Dependencies

| Package | Version |
|---|---|
| Flask | 3.1.1 |
| scikit-learn | 1.9.0 |
| pandas | 2.2.3 |
| numpy | 2.2.6 |
| python-whois | 0.9.5 |

See `app/requirements.txt` for exact pinned versions.

---

## Git history

| Commit | Description |
|---|---|
| `242fa62` | Original submission (tagged `phase1-baseline`) |
| `c801e77` | Phase 1: secret key env var, debug gate, requirements.txt, 36 tests |
| `445de14` | Phase 2: dataset analysis, evaluate_model.py, 25 tests |
| `625c641` | Phase 3: template cleanup, bare-domain input, SQLite safety, 34 tests |
| `41e483b` | Final fix: regenerate ../models/ pkl files to sklearn 1.9.0 |

---

## Disclaimer

This application is an academic prototype. Neither the DNS check nor the ML
classification proves that a website is safe. Always exercise caution and use
professional security tooling before trusting any URL classifier.
