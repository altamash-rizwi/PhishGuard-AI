import sys
import csv
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import train_and_evaluate as training
import evaluate_live_feeds as external_evaluation


def test_registered_domain_groups_subdomains_and_private_suffixes():
    assert training.registered_domain("https://login.example.co.uk/path") == "example.co.uk"
    assert training.registered_domain("https://tenant.github.io/path") == "tenant.github.io"


def test_load_phiusiil_maps_labels_and_deduplicates(tmp_path):
    features_path = tmp_path / "features.csv"
    targets_path = tmp_path / "targets.csv"
    pd.DataFrame(
        {"URL": ["https://legit.example", "http://bad.example", "http://bad.example"]}
    ).to_csv(features_path, index=False)
    pd.DataFrame({"target": [1, 0, 0]}).to_csv(targets_path, index=False)

    frame, metadata = training.load_phiusiil(features_path, targets_path)

    assert frame[["url", "label"]].to_dict("records") == [
        {"url": "https://legit.example", "label": 0},
        {"url": "http://bad.example", "label": 1},
    ]
    assert metadata["raw_rows"] == 3
    assert metadata["duplicate_urls_removed"] == 1
    assert metadata["class_counts"] == {"legitimate": 1, "phishing": 1}


def test_load_phiusiil_rejects_conflicting_duplicate_labels(tmp_path):
    features_path = tmp_path / "features.csv"
    targets_path = tmp_path / "targets.csv"
    pd.DataFrame({"URL": ["https://same.example", "https://same.example"]}).to_csv(
        features_path, index=False
    )
    pd.DataFrame({"target": [0, 1]}).to_csv(targets_path, index=False)

    with pytest.raises(ValueError, match="conflicting labels"):
        training.load_phiusiil(features_path, targets_path)


def test_evaluation_keeps_registered_domains_out_of_training_folds():
    rows = []
    for index in range(30):
        label = index % 2
        domain = f"domain{index}.example"
        scheme = "http" if label else "https"
        rows.append(
            {
                "url": f"{scheme}://{domain}/path-{index}",
                "label": label,
                "domain": domain,
            }
        )
    frame = pd.DataFrame(rows)

    report, probabilities = training.evaluate(frame, folds=3)

    assert len(probabilities) == len(frame)
    assert np.isfinite(probabilities).all()
    assert report["pooled_out_of_fold"]["confusion_matrix"]["detected_phishing"] >= 0
    assert report["validation_protocol"].startswith("3-fold StratifiedGroupKFold")


def test_phishtank_reader_requires_verified_online_recent_records():
    feed = (
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
        "1,https://fresh-phish.example/path,,2026-10-20T00:00:00+00:00,yes,2026-10-21T00:00:00+00:00,yes,brand\n"
        "2,https://old-phish.example/path,,2025-01-01T00:00:00+00:00,yes,2025-01-02T00:00:00+00:00,yes,brand\n"
        "3,https://unverified.example/path,,2026-10-20T00:00:00+00:00,no,,yes,brand\n"
        "4,https://offline.example/path,,2026-10-20T00:00:00+00:00,yes,2026-10-21T00:00:00+00:00,no,brand\n"
    ).encode()

    frame, metadata = external_evaluation.read_phishtank(
        feed,
        datetime(2026, 10, 1, tzinfo=timezone.utc),
    )

    assert frame["url"].tolist() == ["https://fresh-phish.example/path"]
    assert metadata["feed_rows"] == 4
    assert metadata["unique_domains"] == 1


def test_feed_fetch_preserves_available_feed_when_other_is_rate_limited(monkeypatch):
    def fake_fetch(url):
        if "phishtank.com" in url:
            raise RuntimeError("Feed request was denied or rate limited (HTTP 429).")
        return b"tranco", {"last_modified": "Sun, 25 Oct 2026 00:00:00 GMT"}

    monkeypatch.setattr(external_evaluation, "fetch_bytes", fake_fetch)

    payloads, headers, errors = external_evaluation.fetch_available_feeds(
        "https://data.phishtank.com/data/online-valid.csv"
    )

    assert payloads == {"tranco": b"tranco"}
    assert headers["tranco"]["last_modified"].startswith("Sun")
    assert errors == {
        "phishtank": "Feed request was denied or rate limited (HTTP 429)."
    }


def test_feed_fetch_reports_when_all_feeds_fail(monkeypatch):
    def fail_fetch(url):
        raise RuntimeError("Feed unavailable.")

    monkeypatch.setattr(external_evaluation, "fetch_bytes", fail_fetch)

    with pytest.raises(RuntimeError, match="Could not download any public feed"):
        external_evaluation.fetch_available_feeds(
            "https://data.phishtank.com/data/online-valid.csv"
        )


def test_tranco_reader_parses_compressed_domain_list():
    csv_bytes = b"1,example.com\n2,example.org\n"
    compressed = io.BytesIO()
    with zipfile.ZipFile(compressed, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("top-1m.csv", csv_bytes)

    domains, digest = external_evaluation.read_tranco(compressed.getvalue())

    assert domains == ["example.com", "example.org"]
    assert len(digest) == 64


def test_external_sample_excludes_training_domain_overlap():
    phishing = pd.DataFrame(
        [
            {
                "url": "https://phish.example.com/login",
                "label": 1,
                "verified_at": "2026-10-20T00:00:00+00:00",
                "domain": "example.com",
            },
            {
                "url": "https://unique-phish.invalid/login",
                "label": 1,
                "verified_at": "2026-10-21T00:00:00+00:00",
                "domain": "unique-phish.invalid",
            },
        ]
    )

    frame, metadata = external_evaluation.build_external_set(
        phishing,
        ["trained.example", "clean-reference.test", "unique-phish.invalid"],
        {"example.com", "trained.example"},
        max_benign=10,
    )

    assert set(frame["domain"]).isdisjoint({"example.com", "trained.example"})
    assert frame["label"].value_counts().to_dict() == {1: 1, 0: 1}
    assert metadata["training_domain_overlaps_removed"] == 1


def test_external_sample_can_report_not_ready_without_later_phishing_rows():
    frame, metadata = external_evaluation.build_external_set(
        pd.DataFrame(columns=["url", "label", "verified_at", "domain"]),
        ["clean-reference.test"],
        set(),
        max_benign=10,
    )

    assert frame["label"].tolist() == [0]
    assert metadata["phish_domains_tested"] == 0
    with pytest.raises(ValueError, match="at least one sample from each class"):
        external_evaluation.score_external_set(None, None, frame)
