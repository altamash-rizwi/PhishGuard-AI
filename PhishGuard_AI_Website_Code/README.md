# PhishGuard AI — FINAL PBL PROJECT PACKAGE

## Project
**AI-Based Phishing Detection & Secure Website Analysis System**

## What is included
This package contains the complete academic prototype structure:
- Flask backend and routes
- Large HTML frontend (10K+ HTML lines)
- CSS
- Dynamic URL scanning
- URL validation
- URL feature extraction
- TF-IDF character-level text representation
- Random Forest classifier
- Model training and evaluation script
- Public large phishing datasets download pipeline
- SQLite scan history
- Optional WHOIS/domain-age lookup
- Test suite
- Dataset attribution and license documentation
- Architecture documentation
- Final-submission checklist
- Windows and Linux/macOS setup scripts
- Small demo model/dataset for offline UI fallback

## IMPORTANT: large dataset
The final ZIP includes the **download-and-training pipeline for the official UCI PhiUSIIL dataset** rather than fabricating a large dataset. UCI's PhiUSIIL dataset contains 235,795 instances and 54 features. The original dataset is CC BY 4.0. See `docs/DATASETS.md`.

Run:
1. `python -m pip install -r requirements.txt`
2. `python scripts/download_datasets.py`
3. `python scripts/train_and_evaluate.py --max-rows 100000 --trees 200`
4. `python app/app.py`
5. Open `http://127.0.0.1:5000`

Use `--max-rows 0` to train on all downloaded PhiUSIIL rows if the computer has enough RAM/time.

## Model convention
The UCI PhiUSIIL dataset uses label 1 = legitimate and 0 = phishing. The training script converts this to the project convention:
- 0 = legitimate
- 1 = phishing

## Academic honesty
Do not report the demo model's numbers as final performance. After downloading and training on the public dataset, use the generated `reports/metrics.json`, `reports/classification_report.txt`, and confusion matrix in your report.

The application is a preliminary cybersecurity classifier. It does not guarantee that a URL is safe or malicious.


## Important Review-2 Fix: Domain Verification
The scanner now performs a DNS resolution check before presenting a URL as potentially legitimate. The ML model classifies URL text patterns, but it cannot establish that a domain actually exists.

- If the hostname does not resolve: the result is **Unverified / Domain Not Resolving**.
- If DNS verification cannot be completed: the result is **Unable to Verify Domain**.
- If the domain resolves: the ML classification is shown as an additional signal, not proof of safety.
- The application does **not** fetch arbitrary submitted URLs, avoiding the SSRF risk that would come from blindly requesting user-supplied URLs.

The result page now labels the classifier output as **Model Score** rather than treating it as calibrated confidence.
