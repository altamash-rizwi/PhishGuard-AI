"""Evaluate and train a URL-text classifier with domain-separated validation.

Download the source data first with ``python scripts/download_datasets.py``.
The trained model is written as a candidate and is not loaded by the web app.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import time
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline, make_pipeline

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
FEATURES_PATH = RAW / "phiusiil_features.csv"
TARGETS_PATH = RAW / "phiusiil_targets.csv"
RANDOM_STATE = 42
FOLDS = 5
EXTRACT_DOMAIN = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def registered_domain(url: str) -> str:
    """Return the registrable domain using the bundled Public Suffix List."""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError(f"URL has no hostname: {url!r}")
    result = EXTRACT_DOMAIN(host)
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"
    return host


def load_phiusiil(
    features_path: Path = FEATURES_PATH,
    targets_path: Path = TARGETS_PATH,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Load UCI labels, remove exact duplicates, and reject conflicting labels."""
    if not features_path.is_file() or not targets_path.is_file():
        raise FileNotFoundError(
            "PhiUSIIL source files are missing. Run "
            "'python scripts/download_datasets.py' first."
        )

    features = pd.read_csv(features_path)
    targets = pd.read_csv(targets_path)
    if "URL" not in features.columns or targets.shape[1] < 1:
        raise ValueError("PhiUSIIL data must contain a URL column and a target column.")
    if len(features) != len(targets):
        raise ValueError("PhiUSIIL feature and target row counts do not match.")

    target = pd.to_numeric(targets.iloc[:, 0], errors="raise")
    observed_labels = set(target.dropna().unique())
    if observed_labels != {0, 1} or target.isna().any():
        raise ValueError(f"Expected complete binary UCI targets 0 and 1; found {observed_labels}.")

    # UCI PhiUSIIL uses 1=legitimate and 0=phishing. The app convention is
    # 0=legitimate and 1=phishing.
    frame = pd.DataFrame(
        {
            "url": features["URL"].astype("string").str.strip(),
            "label": (target == 0).astype(int),
        }
    )
    frame = frame.dropna(subset=["url"])
    frame = frame[frame["url"] != ""].reset_index(drop=True)
    if frame.empty:
        raise ValueError("PhiUSIIL contains no non-empty URLs.")

    conflicting = frame.groupby("url", sort=False)["label"].nunique()
    conflicting_urls = conflicting[conflicting > 1]
    if not conflicting_urls.empty:
        raise ValueError(
            f"Found {len(conflicting_urls)} URL(s) with conflicting labels; "
            "resolve them before training."
        )
    raw_rows = len(frame)
    frame = frame.drop_duplicates(subset=["url"]).reset_index(drop=True)
    frame["domain"] = frame["url"].map(registered_domain)
    counts = frame["label"].value_counts().to_dict()
    if set(counts) != {0, 1}:
        raise ValueError("Both legitimate (0) and phishing (1) classes are required.")

    return frame, {
        "source": "PhiUSIIL Phishing URL (Website), UCI dataset 967",
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "raw_rows": int(raw_rows),
        "duplicate_urls_removed": int(raw_rows - len(frame)),
        "unique_urls": int(len(frame)),
        "unique_registrable_domains": int(frame["domain"].nunique()),
        "class_counts": {
            "legitimate": int(counts[0]),
            "phishing": int(counts[1]),
        },
        "url_sha256": hashlib.sha256(
            "\n".join(frame["url"].tolist()).encode("utf-8")
        ).hexdigest(),
        "temporal_validation": (
            "Not performed: source data does not provide per-URL collection timestamps."
        ),
    }


def build_model() -> Pipeline:
    """Build the URL-text baseline; vocabulary is fit only on each training fold."""
    return make_pipeline(
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=200_000,
            sublinear_tf=True,
            lowercase=True,
        ),
        SGDClassifier(
            loss="log_loss",
            class_weight="balanced",
            max_iter=1000,
            tol=1e-3,
            random_state=RANDOM_STATE,
        ),
    )


def calculate_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict[str, object]:
    predictions = (probabilities >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision_phishing": float(precision_score(labels, predictions, zero_division=0)),
        "recall_phishing": float(recall_score(labels, predictions, zero_division=0)),
        "f1_phishing": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "average_precision": float(average_precision_score(labels, probabilities)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "confusion_matrix": {
            "true_legitimate": int(tn),
            "false_phishing_alert": int(fp),
            "missed_phishing": int(fn),
            "detected_phishing": int(tp),
        },
    }


def evaluate(
    frame: pd.DataFrame,
    folds: int = FOLDS,
) -> tuple[dict[str, object], np.ndarray]:
    """Return pooled out-of-fold metrics where no registrable domain crosses folds."""
    labels = frame["label"].to_numpy(dtype=int)
    groups = frame["domain"].to_numpy()
    urls = frame["url"].to_numpy()
    splitter = StratifiedGroupKFold(
        n_splits=folds,
        shuffle=True,
        random_state=RANDOM_STATE,
    )
    probabilities = np.full(len(frame), np.nan, dtype=float)
    fold_reports = []
    for fold_number, (train_indices, test_indices) in enumerate(
        splitter.split(urls, labels, groups), start=1
    ):
        train_groups = set(groups[train_indices])
        test_groups = set(groups[test_indices])
        if train_groups & test_groups:
            raise RuntimeError("Domain leakage detected between a training and test fold.")
        if set(labels[train_indices]) != {0, 1} or set(labels[test_indices]) != {0, 1}:
            raise ValueError(
                f"Fold {fold_number} does not contain both classes. "
                "More independent domains per class are required for this split."
            )

        model = build_model()
        model.fit(urls[train_indices], labels[train_indices])
        fold_probabilities = model.predict_proba(urls[test_indices])[:, 1]
        probabilities[test_indices] = fold_probabilities
        fold_reports.append(
            {
                "fold": fold_number,
                "train_rows": int(len(train_indices)),
                "test_rows": int(len(test_indices)),
                "train_domains": int(len(train_groups)),
                "test_domains": int(len(test_groups)),
                "metrics": calculate_metrics(labels[test_indices], fold_probabilities),
            }
        )

    if np.isnan(probabilities).any():
        raise RuntimeError("Cross-validation did not produce exactly one prediction per URL.")

    schemes = np.array([(urlsplit(url).scheme or "").lower() for url in urls])
    scheme_predictions = (schemes == "http").astype(int)
    scheme_label_distribution = pd.crosstab(
        pd.Series(schemes, name="scheme"),
        pd.Series(labels, name="label"),
    ).to_dict(orient="index")
    report = {
        "validation_protocol": (
            f"{folds}-fold StratifiedGroupKFold; registrable domains held out; "
            "character vocabulary fit inside each training fold"
        ),
        "probability_note": (
            "SGD log-loss outputs are not calibrated probabilities and must not "
            "be presented as phishing likelihood."
        ),
        "pooled_out_of_fold": calculate_metrics(labels, probabilities),
        "http_means_phishing_baseline": {
            "accuracy": float(accuracy_score(labels, scheme_predictions)),
            "note": "Diagnostic only; reveals how predictive the URL scheme is by itself.",
        },
        "scheme_label_distribution": {
            scheme: {str(label): int(count) for label, count in counts.items()}
            for scheme, counts in scheme_label_distribution.items()
        },
        "folds": fold_reports,
    }
    return report, probabilities


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folds", type=int, default=FOLDS, choices=range(3, 11))
    args = parser.parse_args()

    started = time.time()
    frame, dataset_report = load_phiusiil()
    evaluation, _ = evaluate(frame, folds=args.folds)

    # Train only a candidate after evaluation has completed successfully.
    candidate = build_model()
    candidate.fit(frame["url"].to_numpy(), frame["label"].to_numpy(dtype=int))
    MODELS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    with (MODELS / "candidate_url_model.pkl").open("wb") as model_file:
        pickle.dump(candidate.steps[-1][1], model_file)
    with (MODELS / "candidate_url_vectorizer.pkl").open("wb") as vectorizer_file:
        pickle.dump(candidate.steps[0][1], vectorizer_file)

    report = {
        **dataset_report,
        **evaluation,
        "model": "character TF-IDF (3-5 grams) + SGD logistic classifier",
        "random_state": RANDOM_STATE,
        "runtime_seconds": round(time.time() - started, 2),
        "candidate_artifacts": [
            "models/candidate_url_model.pkl",
            "models/candidate_url_vectorizer.pkl",
        ],
        "release_status": (
            "Candidate only. Review the held-out-domain metrics and conduct "
            "separate time-based validation before promoting this model."
        ),
    }
    report_path = REPORTS / "domain_holdout_metrics.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nCandidate artifacts and report saved under {ROOT}.")


if __name__ == "__main__":
    main()
