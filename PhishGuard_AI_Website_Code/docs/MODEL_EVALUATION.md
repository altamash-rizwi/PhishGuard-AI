# URL Model Evaluation

## Run and data snapshot

The evaluation was run on 2026-10-25 using UCI PhiUSIIL dataset 967. The
reproducible commands are:

```powershell
py scripts\download_datasets.py
py scripts\train_and_evaluate.py
```

The run loaded 235,795 source rows, removed 425 exact duplicate URLs, and
evaluated 235,370 unique URLs from 197,709 registrable domains:

| Class | Unique URLs |
|---|---:|
| Legitimate | 134,850 |
| Phishing | 100,520 |

Label convention is `0 = legitimate`, `1 = phishing`. The URL-list SHA-256
fingerprint was `30d93cfedd90cdf546d9cadd6b642bc5966dc009bb1664e91d7565a90d2a635a`.

## Domain-held-out results

Five-fold `StratifiedGroupKFold` kept registrable domains separate between
training and testing. TF-IDF character features were fit only on each
training fold. The following values are pooled out-of-fold results at a 0.5
score threshold:

| Metric | Result |
|---|---:|
| Accuracy | 99.41% |
| Phishing precision | 100.00% |
| Phishing recall | 98.62% |
| Phishing F1 | 99.31% |
| False-positive rate | 0.00% |
| Average precision | 99.84% |
| ROC AUC | 99.79% |

Confusion counts: **134,850** legitimate URLs correctly passed, **0** false
phishing alerts, **1,386** phishing URLs missed, and **99,134** phishing URLs
detected. A diagnostic rule that labels every `http://` URL phishing achieved
79.23% accuracy on this dataset; HTTP/HTTPS is therefore a substantial
dataset signal and must not be treated as proof of phishing or legitimacy.

| URL scheme | Legitimate | Phishing |
|---|---:|---:|
| HTTP | 0 | 51,635 |
| HTTPS | 134,850 | 48,885 |

## Interpretation and release status

These results are useful evidence that the new pipeline generalizes across
registrable domains *within this dataset*, and are more informative than the
previous 20-URL demo evaluation. They are **not yet evidence of production
or live-phishing performance**:

- The evaluation uses one public dataset and its labeling/collection process;
  a separate independent source has not been evaluated.
- The dataset has no per-URL collection timestamps, so temporal generalization
  and performance on newer campaigns cannot be measured.
- The out-of-fold phishing scores are uncalibrated and must not be displayed as
  probabilities or safety guarantees.
- Domain-disjoint random folds do not eliminate all dataset-source, campaign,
  or collection bias. The zero false-positive count must not be interpreted as
  zero real-world false positives.

The generated model is saved as `models/candidate_url_model.pkl` and
`models/candidate_url_vectorizer.pkl`. It is deliberately **not loaded by the
web app**. Before promoting it, evaluate a separate, later-dated dataset with
reviewed labels, choose a decision threshold based on acceptable false
positives and missed phishing, assess calibration, and document the release
decision.

See [DATASETS.md](./DATASETS.md) for source attribution and setup.

## Live-feed readiness check

An additional, domain-disjoint challenge was collected on 2026-10-24 from
PhishTank's verified/online CSV feed and Tranco's latest top-1m list. The
candidate scored on 5,198 recent PhishTank domains and 5,198 Tranco domains
after removing overlaps with the UCI training domains. At the unadjusted 0.5
threshold:

| Metric | Result |
|---|---:|
| Accuracy on this balanced sample | 50.85% |
| Phishing precision | 50.44% |
| Phishing recall | 97.10% |
| False-alert rate on Tranco reference domains | 95.40% |
| Average precision | 85.38% |
| ROC AUC | 81.64% |

The model flagged **4,959 of 5,198** Tranco reference domains and missed **151
of 5,198** PhishTank phishing domains. Tranco is a popularity list, not a
verified-benign feed; these results are a stress test, not a clean population
estimate. Even with that limitation, the very high false-alert rate is a
strong warning that the model is not ready for user-facing phishing verdicts.
Changing the threshold based on this test would tune on the test set, so these
results were not used to select a replacement threshold.

For diagnosis only, fixed-threshold sensitivity on that same sample was:

| Score threshold | Tranco-reference false-alert rate | PhishTank recall |
|---:|---:|---:|
| 0.50 | 95.40% | 97.10% |
| 0.75 | 48.98% | 84.80% |
| 0.90 | 0.23% | 28.99% |
| 0.95 | 0.02% | 19.80% |
| 0.99 | 0.00% | 7.14% |

These values describe the stress set only. They are post-hoc diagnostics, not
threshold selection evidence or estimates of real-world operating rates.

This first feed snapshot does **not** qualify as a strict forward-in-time test:
the PhishTank feed's `Last-Modified` time was 2026-10-24 20:21:57 UTC, while
the candidate artifact was trained at 2026-10-24 20:41:28 UTC; the Tranco
snapshot also predates the candidate. Therefore, there were no qualifying
post-training positives or benign snapshots in that run. The initial balanced
results above are domain-disjoint and cross-source, but not later-dated.

For strict collection, run the evaluator periodically after training. It saves
each feed snapshot locally, keeps only phishing URLs whose PhishTank
`verification_time` is strictly later than the candidate file's training time,
and accepts Tranco lists whose `Last-Modified` is later than that time. It
requires at least 500 independent examples in each class before calculating
forward-time metrics:

```powershell
py scripts\evaluate_live_feeds.py --recent-days 90 --min-samples-per-class 500
```

To re-check the snapshots already collected without making another feed request,
add `--offline`.

The evaluator does not visit URL destinations. Feed snapshots and the resulting
machine-readable report are git-ignored and remain local. PhishTank recommends
a descriptive User-Agent and an application key for automated/frequent
downloads; set `PHISHTANK_APP_KEY` when one is available. If there are too few
new verified URLs or no later Tranco list yet, the script records that
evaluation is **not ready** instead of reporting metrics. If one feed is
unavailable, the script records its error and saves the other feed when
available; this partial snapshot still cannot satisfy the evaluation gate
without sufficient independent samples from both classes.

Official feed information:

- [PhishTank developer feed documentation](https://phishtank.org/developer_info.php)
- [Tranco latest list and update information](https://tranco-list.eu/)
