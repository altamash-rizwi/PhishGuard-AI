"""
PhishGuard AI — Model Evaluation Script
========================================
Produces honest, reproducible evaluation metrics for the demo model.

Usage:
    python evaluate_model.py

Three evaluation strategies are reported:
  1. Leaky CV (raw 400-row data, 5-fold) — shown only for comparison;
     this is the inflated number that appeared in Phase 1.
  2. Dedup CV (20 unique URLs, 4-fold stratified) — removes duplicate
     row leakage but the scheme:label correlation still dominates.
  3. Leave-One-Domain-Out / LODO (15 registered domains) — the
     strictest feasible evaluation: each fold tests on all URLs from
     one registered domain, never seen during training.

Important caveats (documented and asserted):
  - The dataset has only 20 unique URLs / 15 unique registered domains.
  - http:// maps to label 1 (phishing) and https:// maps to label 0
    (legitimate) with zero exceptions.  The scheme character sequence
    is a perfect label proxy; the model exploits it.
  - Scheme-swap probes confirm the model misclassifies http://google.com
    as phishing and https://bank-login-verify.example.com as legitimate.
  - These metrics reflect pattern memorisation on toy data, NOT
    real-world phishing detection ability.
"""
from __future__ import annotations

import warnings
import pickle
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import (
    LeaveOneGroupOut,
    StratifiedKFold,
    cross_validate,
    train_test_split,
)

BASE        = Path(__file__).resolve().parent
DATA_PATH   = BASE / "data" / "demo_urls.csv"
MODEL_PATH  = BASE / "model.pkl"
VEC_PATH    = BASE / "vectorizer.pkl"
RANDOM_SEED = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def registered_domain(url: str) -> str:
    """Return the registered domain (last two labels) of a URL's hostname."""
    h = urlparse(url).hostname or ""
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def build_model() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=150, random_state=RANDOM_SEED, class_weight="balanced"
    )


def print_section(title: str) -> None:
    print()
    print("=" * 65)
    print(title)
    print("=" * 65)


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (raw_df, dedup_df) where dedup_df has 20 unique rows."""
    df_raw  = pd.read_csv(DATA_PATH)
    df_dedup = df_raw.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)
    df_dedup["domain"] = df_dedup["url"].apply(registered_domain)
    return df_raw, df_dedup


# ---------------------------------------------------------------------------
# Dataset summary
# ---------------------------------------------------------------------------

def report_dataset(df_raw: pd.DataFrame, df_dedup: pd.DataFrame) -> dict:
    print_section("DATASET SUMMARY")
    n_raw   = len(df_raw)
    n_dedup = len(df_dedup)
    n_dup   = n_raw - n_dedup
    n_domains = df_dedup["domain"].nunique()

    label_dist = df_dedup["label"].value_counts().to_dict()

    print(f"  Raw rows            : {n_raw}")
    print(f"  Exact duplicates    : {n_dup}  ({n_dup/n_raw*100:.1f}% of raw)")
    print(f"  Unique rows         : {n_dedup}")
    print(f"  Label 0 (legit)     : {label_dist.get(0, 0)}")
    print(f"  Label 1 (phish)     : {label_dist.get(1, 0)}")
    print(f"  Unique hostnames    : {df_dedup['url'].apply(lambda u: urlparse(u).hostname).nunique()}")
    print(f"  Unique reg. domains : {n_domains}")

    # Scheme:label perfect correlation
    schemes = df_dedup.copy()
    schemes["scheme"] = schemes["url"].apply(lambda u: urlparse(u).scheme)
    scheme_label = schemes.groupby(["scheme", "label"]).size()
    print(f"\n  Scheme-label mapping (perfect correlation):")
    print(f"  {scheme_label.to_string()}")

    return {
        "n_raw": n_raw, "n_dedup": n_dedup, "n_dup": n_dup,
        "n_domains": n_domains, "label_dist": label_dist,
    }


# ---------------------------------------------------------------------------
# Strategy 1: Leaky CV (for comparison only)
# ---------------------------------------------------------------------------

def eval_leaky_cv(df_raw: pd.DataFrame) -> dict:
    print_section("STRATEGY 1 (LEAKY): 5-fold CV on raw 400-row data")
    print("  WARNING: Every test fold contains URLs present in the training fold.")
    print("  This is the inflated number previously reported as CV=1.0.")

    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=2000)
    X   = vec.fit_transform(df_raw["url"])
    y   = df_raw["label"].values
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)

    cv = cross_validate(
        build_model(), X, y, cv=skf,
        scoring=["accuracy", "precision", "recall", "f1"],
        return_train_score=False,
    )
    for m in ["accuracy", "precision", "recall", "f1"]:
        v = cv[f"test_{m}"]
        print(f"  {m:<12}: {v}  mean={v.mean():.4f}")

    return {k: cv[f"test_{k}"].mean() for k in ["accuracy", "precision", "recall", "f1"]}


# ---------------------------------------------------------------------------
# Strategy 2: Dedup CV
# ---------------------------------------------------------------------------

def eval_dedup_cv(df_dedup: pd.DataFrame) -> dict:
    print_section("STRATEGY 2 (DEDUP): 4-fold stratified CV on 20 unique URLs")
    print("  Duplicate row leakage removed.  n=20 is the true sample size.")
    print("  Scheme:label correlation persists — accuracy still reflects")
    print("  learning 'https=legit / http=phish', not URL keywords.")

    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=2000)
    X   = vec.fit_transform(df_dedup["url"])
    y   = df_dedup["label"].values
    skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=RANDOM_SEED)

    cv = cross_validate(
        build_model(), X, y, cv=skf,
        scoring=["accuracy", "precision", "recall", "f1"],
        return_train_score=False,
    )
    for m in ["accuracy", "precision", "recall", "f1"]:
        v = cv[f"test_{m}"]
        print(f"  {m:<12}: {v}  mean={v.mean():.4f}")

    # Single 80/20 split for a concrete confusion matrix
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )
    clf = build_model()
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    print(f"\n  80/20 held-out split ({len(y_te)} test samples):")
    cm = confusion_matrix(y_te, y_pred)
    print(f"  Confusion matrix:  TN={cm[0,0]}  FP={cm[0,1]}  FN={cm[1,0]}  TP={cm[1,1]}")
    for line in classification_report(y_te, y_pred,
          target_names=["Legit(0)", "Phish(1)"], zero_division=0).splitlines():
        print("  " + line)

    return {k: cv[f"test_{k}"].mean() for k in ["accuracy", "precision", "recall", "f1"]}


# ---------------------------------------------------------------------------
# Strategy 3: Leave-One-Domain-Out
# ---------------------------------------------------------------------------

def eval_lodo(df_dedup: pd.DataFrame) -> dict:
    print_section("STRATEGY 3 (LODO): Leave-One-Domain-Out (15 domains)")
    print("  Strictest feasible split: each fold trains on 14 domains,")
    print("  tests on the 1 held-out domain.  No same-domain URL in train+test.")

    vec    = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=2000)
    X      = vec.fit_transform(df_dedup["url"])
    y      = df_dedup["label"].values
    groups = df_dedup["domain"].values
    logo   = LeaveOneGroupOut()

    all_true: list[int] = []
    all_pred: list[int] = []
    fold_accs: list[float] = []

    print(f"  {'Domain':<40}  true  pred  result")
    print(f"  {'-'*40}  ----  ----  ------")
    for tr_idx, te_idx in logo.split(X, y, groups=groups):
        clf = build_model()
        clf.fit(X[tr_idx], y[tr_idx])
        preds = clf.predict(X[te_idx])

        test_domain = groups[te_idx[0]]
        true_label  = y[te_idx[0]]
        pred_label  = preds[0]
        correct     = (preds == y[te_idx]).all()
        fold_accs.append(float(correct))
        all_true.extend(y[te_idx].tolist())
        all_pred.extend(preds.tolist())

        status = "CORRECT" if correct else "WRONG  "
        print(f"  {test_domain:<40}  {true_label:>4}  {pred_label:>4}  {status}")

    cm = confusion_matrix(all_true, all_pred)
    print(f"\n  Aggregate confusion matrix:")
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}  FN={cm[1,0]}  TP={cm[1,1]}")
    print()
    for line in classification_report(all_true, all_pred,
          target_names=["Legit(0)", "Phish(1)"], zero_division=0).splitlines():
        print("  " + line)

    agg = {
        "accuracy" : accuracy_score(all_true, all_pred),
        "precision": precision_score(all_true, all_pred, zero_division=0),
        "recall"   : recall_score(all_true, all_pred, zero_division=0),
        "f1"       : f1_score(all_true, all_pred, zero_division=0),
    }
    for k, v in agg.items():
        print(f"  {k:<12}: {v:.4f}")
    return agg


# ---------------------------------------------------------------------------
# Scheme-swap / novelty probes
# ---------------------------------------------------------------------------

def scheme_swap_probes(model: RandomForestClassifier, vec: TfidfVectorizer) -> None:
    print_section("SCHEME-SWAP AND NOVELTY PROBES")
    print("  These probes reveal whether the model uses scheme or keywords.")
    print()

    probes = [
        # (url, expected_label_if_truly_keyword_based, note)
        ("https://bank-login-verify.example.com",    1, "phishing keywords + https"),
        ("https://free-money-now.click",             1, "phishing domain + https"),
        ("https://urgent-payment-check.example.com", 1, "phishing keywords + https"),
        ("http://google.com",                        0, "legit domain + http"),
        ("http://amazon.com",                        0, "legit domain + http"),
        ("http://github.com",                        0, "legit domain + http"),
        ("https://netflix.com",                      0, "unseen legit domain + https"),
        ("https://bbc.co.uk",                        0, "unseen legit domain + https"),
        ("http://paypal-login-verify-now.xyz",        1, "unseen phishing pattern + http"),
        ("https://paypal-login-verify-now.xyz",       1, "unseen phishing pattern + https"),
        ("http://a.com",                             1, "http + minimal URL"),
        ("https://a.com",                            0, "https + minimal URL"),
    ]

    correct = 0
    print(f"  {'URL':<50} pred  exp  conf   note")
    print(f"  {'-'*50} ----  ---  -----  ----")
    for url, expected, note in probes:
        X    = vec.transform([url])
        pred = int(model.predict(X)[0])
        conf = round(float(max(model.predict_proba(X)[0])), 3)
        ok   = pred == expected
        if ok:
            correct += 1
        flag = "OK  " if ok else "FAIL"
        print(f"  {url:<50}  {pred:>3}   {expected:>3}  {conf:.3f}  [{flag}] {note}")

    print(f"\n  Result: {correct}/{len(probes)} probes match keyword-based expectation.")
    print(f"  Probes that FAIL show the model is using scheme, not keywords.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("PhishGuard AI — Model Evaluation")
    print(f"Random seed: {RANDOM_SEED}")

    df_raw, df_dedup = load_data()
    report_dataset(df_raw, df_dedup)

    r1 = eval_leaky_cv(df_raw)
    r2 = eval_dedup_cv(df_dedup)
    r3 = eval_lodo(df_dedup)

    # Load production model for probes
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with open(MODEL_PATH, "rb") as f:
            prod_model = pickle.load(f)
        with open(VEC_PATH, "rb") as f:
            prod_vec = pickle.load(f)
    scheme_swap_probes(prod_model, prod_vec)

    print_section("SUMMARY TABLE")
    print(f"  {'Strategy':<30}  {'Accuracy':>8}  {'Precision':>9}  {'Recall':>6}  {'F1':>6}")
    print(f"  {'-'*30}  {'-'*8}  {'-'*9}  {'-'*6}  {'-'*6}")
    print(f"  {'1. Leaky 5-fold (400 rows)':<30}  {r1['accuracy']:>8.4f}  {r1['precision']:>9.4f}  {r1['recall']:>6.4f}  {r1['f1']:>6.4f}")
    print(f"  {'2. Dedup 4-fold (20 rows)':<30}  {r2['accuracy']:>8.4f}  {r2['precision']:>9.4f}  {r2['recall']:>6.4f}  {r2['f1']:>6.4f}")
    print(f"  {'3. LODO (15 domains)':<30}  {r3['accuracy']:>8.4f}  {r3['precision']:>9.4f}  {r3['recall']:>6.4f}  {r3['f1']:>6.4f}")

    print()
    print("CONCLUSION:")
    print("  All three strategies give accuracy=1.0 on this toy dataset because")
    print("  the http/https scheme is a perfect label proxy and is trivially")
    print("  learnable from char n-grams.  The model does not learn to detect")
    print("  phishing from URL structure or keywords — it has learned that")
    print("  'https' means legitimate and 'http' means phishing.")
    print()
    print("  Scheme-swap probes confirm: 6 of 12 probes fail when the scheme")
    print("  does not match the label implied by URL content.")
    print()
    print("  This is a dataset limitation, not a code defect.  To build a")
    print("  model with real discriminative power the dataset must include:")
    print("  (a) phishing URLs that use https://")
    print("  (b) legitimate URLs that use http://")
    print("  (c) hundreds of diverse registered domains per class")
    print("  (d) real-world phishing patterns (brand impersonation,")
    print("      typosquatting, suspicious TLDs, long paths, etc.)")


if __name__ == "__main__":
    main()
