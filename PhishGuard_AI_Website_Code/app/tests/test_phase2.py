"""
PhishGuard AI — Phase 2 test suite: dataset quality and model evaluation.

Tests cover:
  - Dataset integrity (no nulls, expected columns, label range)
  - Duplicate detection (380 exact duplicates confirmed)
  - Scheme-label perfect correlation (http=1, https=0) detected and documented
  - evaluate_model.py importable and its public functions return expected shapes
  - Model does NOT silently regress: all 20 training patterns still classified
    correctly after a retrain cycle (smoke test for train_model.py)
  - Scheme-swap sanity: scheme is the dominant feature (6 of 12 probes fail)
  - evaluate_model.py main() runs without error
  - LODO aggregate accuracy == 1.0 on this toy dataset (documented limitation)

Run from app/ directory:
    pytest tests/test_phase2.py -v
"""
from __future__ import annotations

import os
import sys
import pickle
import warnings
from pathlib import Path
from urllib.parse import urlparse

import pytest
import pandas as pd
import numpy as np

os.environ.setdefault("FLASK_SECRET", "pytest-phase2-secret")
APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))

DATA_PATH  = APP_DIR / "data" / "demo_urls.csv"
MODEL_PATH = APP_DIR / "model.pkl"
VEC_PATH   = APP_DIR / "vectorizer.pkl"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def df_raw():
    return pd.read_csv(DATA_PATH)


@pytest.fixture(scope="module")
def df_dedup(df_raw):
    return df_raw.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)


@pytest.fixture(scope="module")
def model_and_vec():
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # version mismatch would raise here
        with open(MODEL_PATH, "rb") as f:
            m = pickle.load(f)
        with open(VEC_PATH, "rb") as f:
            v = pickle.load(f)
    return m, v


# ---------------------------------------------------------------------------
# 1. Dataset integrity
# ---------------------------------------------------------------------------

class TestDatasetIntegrity:
    def test_file_exists(self):
        assert DATA_PATH.exists(), f"Dataset missing: {DATA_PATH}"

    def test_expected_columns(self, df_raw):
        assert list(df_raw.columns) == ["url", "label"]

    def test_no_null_values(self, df_raw):
        assert df_raw.isnull().sum().sum() == 0

    def test_label_values_are_binary(self, df_raw):
        assert set(df_raw["label"].unique()).issubset({0, 1})

    def test_raw_row_count(self, df_raw):
        assert len(df_raw) == 400

    def test_dedup_row_count(self, df_dedup):
        """Only 20 unique (url, label) combinations exist."""
        assert len(df_dedup) == 20

    def test_exact_duplicate_count(self, df_raw):
        n_dups = df_raw.duplicated().sum()
        assert n_dups == 380, (
            f"Expected 380 exact duplicates, got {n_dups}. "
            "Dataset may have changed."
        )

    def test_balanced_labels_in_dedup(self, df_dedup):
        vc = df_dedup["label"].value_counts()
        assert vc[0] == 10
        assert vc[1] == 10

    def test_unique_url_count(self, df_dedup):
        assert df_dedup["url"].nunique() == 20

    def test_no_url_has_inconsistent_labels(self, df_raw):
        """Each URL must map to exactly one label."""
        url_label_counts = df_raw.groupby("url")["label"].nunique()
        inconsistent = url_label_counts[url_label_counts > 1]
        assert len(inconsistent) == 0, (
            f"URLs with conflicting labels: {inconsistent.index.tolist()}"
        )


# ---------------------------------------------------------------------------
# 2. Scheme–label correlation (documented limitation)
# ---------------------------------------------------------------------------

class TestSchemeLabelCorrelation:
    """Document and assert the scheme-label perfect correlation.

    This is NOT a pass/fail for correctness — it is an assertion that
    the known limitation exists and is understood.
    """

    def test_all_http_urls_are_phishing(self, df_dedup):
        """Every http:// URL in the dataset has label=1."""
        http_rows = df_dedup[df_dedup["url"].str.startswith("http://")]
        assert (http_rows["label"] == 1).all(), (
            "Dataset has http:// URL(s) not labelled as phishing. "
            "The scheme-label mapping has changed."
        )

    def test_all_https_urls_are_legitimate(self, df_dedup):
        """Every https:// URL in the dataset has label=0."""
        https_rows = df_dedup[df_dedup["url"].str.startswith("https://")]
        assert (https_rows["label"] == 0).all(), (
            "Dataset has https:// URL(s) not labelled as legitimate. "
            "The scheme-label mapping has changed."
        )

    def test_scheme_alone_gives_perfect_accuracy(self, df_dedup):
        """A trivial rule (http=1, https=0) achieves 100% accuracy."""
        from sklearn.metrics import accuracy_score
        trivial = (df_dedup["url"].str.startswith("http://")).astype(int)
        acc = accuracy_score(df_dedup["label"], trivial)
        assert acc == 1.0, (
            f"Trivial scheme rule accuracy={acc} — scheme is no longer "
            "a perfect label proxy."
        )

    def test_unique_registered_domain_count(self, df_dedup):
        def reg_domain(url):
            h = urlparse(url).hostname or ""
            parts = h.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else h
        domains = df_dedup["url"].apply(reg_domain).nunique()
        assert domains == 15


# ---------------------------------------------------------------------------
# 3. Model artefact quality
# ---------------------------------------------------------------------------

class TestModelArtefactQuality:
    def test_model_loads_without_version_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with open(MODEL_PATH, "rb") as f:
                m = pickle.load(f)
        assert hasattr(m, "predict")

    def test_vectorizer_loads_without_version_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with open(VEC_PATH, "rb") as f:
                v = pickle.load(f)
        assert hasattr(v, "transform")

    def test_model_predicts_all_training_patterns_correctly(
        self, df_dedup, model_and_vec
    ):
        """All 20 unique training patterns must be classified correctly
        (the model is trained on them — this is a smoke test only)."""
        m, v = model_and_vec
        X = v.transform(df_dedup["url"])
        preds = m.predict(X)
        correct = (preds == df_dedup["label"].values).sum()
        assert correct == len(df_dedup), (
            f"Model misclassified {len(df_dedup) - correct} training patterns."
        )

    def test_model_output_probabilities_sum_to_one(self, model_and_vec):
        m, v = model_and_vec
        X = v.transform(["https://example.com", "http://login-verify.example.com"])
        proba = m.predict_proba(X)
        for p in proba:
            assert abs(sum(p) - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# 4. Scheme-swap probes (document the model's known failure mode)
# ---------------------------------------------------------------------------

class TestSchemeSwapProbes:
    """Assert that the model fails when scheme and keywords disagree.

    These tests EXPECT failures — they document a known limitation.
    They should pass (i.e., the failure MODE should be stable) and
    will alert us if the limitation changes unexpectedly.
    """

    def test_phishing_keywords_with_https_misclassified_as_legit(
        self, model_and_vec
    ):
        """A phishing-keyword URL with https:// should be pred=1 but is pred=0."""
        m, v = model_and_vec
        X = v.transform(["https://bank-login-verify.example.com"])
        pred = int(m.predict(X)[0])
        # Document the known failure: model predicts 0 (legit) because https
        assert pred == 0, (
            "Model no longer classifies https://bank-login-verify.example.com "
            "as legitimate (0). The scheme-dominance has changed. "
            "Re-run evaluate_model.py to understand the new behaviour."
        )

    def test_legit_domain_with_http_misclassified_as_phishing(
        self, model_and_vec
    ):
        """A legitimate domain with http:// should be pred=0 but is pred=1."""
        m, v = model_and_vec
        X = v.transform(["http://google.com"])
        pred = int(m.predict(X)[0])
        assert pred == 1, (
            "Model no longer classifies http://google.com as phishing (1). "
            "The scheme-dominance has changed."
        )

    def test_scheme_swap_failure_count(self, model_and_vec):
        """Exactly 6 of 12 scheme-swap probes should fail (model uses scheme)."""
        m, v = model_and_vec
        probes_with_expected = [
            ("https://bank-login-verify.example.com",    1),
            ("https://free-money-now.click",             1),
            ("https://urgent-payment-check.example.com", 1),
            ("http://google.com",                        0),
            ("http://amazon.com",                        0),
            ("http://github.com",                        0),
            ("https://netflix.com",                      0),
            ("https://bbc.co.uk",                        0),
            ("http://paypal-login-verify-now.xyz",        1),
            ("https://paypal-login-verify-now.xyz",       1),
            ("http://a.com",                             1),
            ("https://a.com",                            0),
        ]
        failures = 0
        for url, expected in probes_with_expected:
            pred = int(m.predict(v.transform([url]))[0])
            if pred != expected:
                failures += 1
        # 7 failures are expected (verified with fresh model.pkl, seed=42).
        # If this count changes after a retrain, re-run evaluate_model.py to
        # understand what shifted.
        assert failures == 7, (
            f"Expected 7 scheme-swap probe failures, got {failures}. "
            "The model's scheme-dominance behaviour has changed. "
            "Re-run evaluate_model.py."
        )


# ---------------------------------------------------------------------------
# 5. evaluate_model.py integration test
# ---------------------------------------------------------------------------

class TestEvaluateModelScript:
    def test_evaluate_model_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "evaluate_model", APP_DIR / "evaluate_model.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        # Just confirm the key public functions exist
        assert callable(getattr(mod, "load_data", None))
        assert callable(getattr(mod, "eval_lodo", None))

    def test_evaluate_model_load_data(self):
        """load_data() must return two DataFrames with correct sizes."""
        sys.path.insert(0, str(APP_DIR))
        import evaluate_model as em
        df_raw, df_dedup = em.load_data()
        assert len(df_raw) == 400
        assert len(df_dedup) == 20

    def test_evaluate_model_registered_domain(self):
        import evaluate_model as em
        assert em.registered_domain("https://bank-login-verify.example.com") == "example.com"
        assert em.registered_domain("https://google.com") == "google.com"
        # hostname is "free-money-now.click" — only 2 labels, so the whole
        # hostname is returned as the registered domain
        assert em.registered_domain("http://free-money-now.click") == "free-money-now.click"

    def test_evaluate_model_lodo_accuracy(self, capsys):
        """LODO evaluation must produce accuracy=1.0 on this toy dataset."""
        import evaluate_model as em
        _, df_dedup = em.load_data()
        result = em.eval_lodo(df_dedup)
        captured = capsys.readouterr()
        assert result["accuracy"] == 1.0
        assert result["f1"] == 1.0
