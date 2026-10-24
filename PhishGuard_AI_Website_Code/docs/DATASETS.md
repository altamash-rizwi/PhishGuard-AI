# Dataset Sources and Attribution

## 1. PhiUSIIL Phishing URL (Website)
UCI Machine Learning Repository, dataset 967.

- 235,795 instances
- 54 features
- 134,850 legitimate URLs
- 100,945 phishing URLs
- UCI label convention: 1 = legitimate, 0 = phishing
- License: Creative Commons Attribution 4.0 (CC BY 4.0)
- Citation: Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository. DOI: 10.1016/j.cose.2023.103545

Official page:
https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset

## 2. Phishing Websites
UCI Machine Learning Repository, dataset 327.

- 11,055 instances
- 30 features
- License: Creative Commons Attribution 4.0 (CC BY 4.0)
- Citation: Mohammad, R. & McCluskey, L. (2012). Phishing Websites. UCI Machine Learning Repository. DOI: 10.24432/C51W2X

Official page:
https://archive.ics.uci.edu/dataset/327/phishing

## Reproducibility
Only PhiUSIIL is used for the URL-text classifier. The separate UCI Phishing
Websites dataset contains engineered features rather than raw URL text and is
not part of this model's training pipeline.

After installing requirements, retrieve the original public data with
`python scripts/download_datasets.py`. The download is kept under
`data/raw/` and is not committed. Labels are converted to the app convention:
`0 = legitimate`, `1 = phishing`. Exact duplicate URLs are removed; conflicting
labels stop training.

Evaluation uses five-fold stratified grouping by registrable domain, with
character n-gram vocabulary fit only on each training fold. The report also
includes a scheme-only diagnostic baseline and phishing-focused metrics.
PhiUSIIL does not provide per-URL collection timestamps, so this evaluation
cannot measure temporal generalization. A candidate model must not be
promoted until separate, later-dated validation and a human review of the
domain-held-out metrics are complete.

The separate prospective evaluator in `scripts/evaluate_live_feeds.py`
collects PhishTank and Tranco snapshots after candidate training. It will not
report forward-time performance until there are at least 500 independent
examples per class with source timestamps later than the candidate.
