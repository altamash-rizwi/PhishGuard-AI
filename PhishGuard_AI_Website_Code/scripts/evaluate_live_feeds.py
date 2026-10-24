"""Prospectively evaluate an approved candidate on independent public feeds.

PhishTank supplies verified, currently online phishing URLs. Tranco supplies a
popular-domain reference set, not a guarantee that each URL is benign. No
submitted destination is opened. Feed snapshots and results are kept locally
under data/external_snapshots/ and are not committed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import pickle
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

import train_and_evaluate as training

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"
SNAPSHOTS = ROOT / "data" / "external_snapshots"
PHISHTANK_BASE = "https://data.phishtank.com/data"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
USER_AGENT = "PhishGuard-AI-research-evaluation/1.0 (URL classification benchmark)"
MAX_DOWNLOAD_BYTES = 100_000_000


def fetch_bytes(url: str) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = response.read(MAX_DOWNLOAD_BYTES + 1)
            if len(payload) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"Feed exceeds the {MAX_DOWNLOAD_BYTES:,}-byte download limit.")
            return payload, {
                "last_modified": response.headers.get("Last-Modified", ""),
                "etag": response.headers.get("ETag", ""),
                "content_type": response.headers.get("Content-Type", ""),
            }
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403, 429}:
            raise RuntimeError(
                f"Feed request was denied or rate limited (HTTP {exc.code}). "
                "Set PHISHTANK_APP_KEY to a registered key and retry later."
            ) from exc
        raise RuntimeError(f"Feed request failed with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not download public feed: {exc.reason}") from exc


def fetch_available_feeds(
    phishtank_url: str,
) -> tuple[dict[str, bytes], dict[str, dict[str, str]], dict[str, str]]:
    feeds = {"phishtank": phishtank_url, "tranco": TRANCO_URL}
    payloads = {}
    headers = {}
    errors = {}
    for name, url in feeds.items():
        try:
            payloads[name], headers[name] = fetch_bytes(url)
        except RuntimeError as exc:
            errors[name] = str(exc)
    if not payloads:
        details = "; ".join(f"{name}: {error}" for name, error in errors.items())
        raise RuntimeError(f"Could not download any public feed. {details}")
    return payloads, headers, errors


def read_phishtank(
    payload: bytes,
    cutoff: datetime,
) -> tuple[pd.DataFrame, dict[str, int]]:
    rows = list(csv.DictReader(io.StringIO(payload.decode("utf-8-sig"))))
    required = {"url", "verified", "verification_time", "online"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("PhishTank feed is empty or does not match its documented CSV schema.")

    candidates = []
    for row in rows:
        if row["verified"].strip().lower() != "yes" or row["online"].strip().lower() != "yes":
            continue
        verified_at = pd.to_datetime(row["verification_time"], utc=True, errors="coerce")
        if pd.isna(verified_at) or verified_at.to_pydatetime() <= cutoff:
            continue
        url = row["url"].strip()
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        candidates.append(
            {
                "url": url,
                "label": 1,
                "verified_at": verified_at.isoformat(),
                "domain": training.registered_domain(url),
            }
        )

    frame = pd.DataFrame(candidates)
    if frame.empty:
        return frame, {"feed_rows": len(rows), "verified_online_recent": 0}

    before_dedup = len(frame)
    frame = frame.sort_values("verified_at", ascending=False).drop_duplicates("url")
    unique_urls = len(frame)
    frame = frame.drop_duplicates("domain").reset_index(drop=True)
    return frame, {
        "feed_rows": len(rows),
        "verified_online_recent": int(before_dedup),
        "unique_urls": int(unique_urls),
        "unique_domains": int(frame["domain"].nunique()),
        "same_domain_urls_removed": int(unique_urls - len(frame)),
    }


def read_tranco(payload: bytes) -> tuple[list[str], str]:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if len(csv_names) != 1:
                raise ValueError("Tranco archive must contain exactly one CSV file.")
            with archive.open(csv_names[0]) as data:
                rows = list(csv.reader(io.TextIOWrapper(data, encoding="utf-8-sig")))
    except zipfile.BadZipFile as exc:
        raise ValueError("Tranco download was not a valid ZIP archive.") from exc

    domains = []
    for row in rows:
        if len(row) < 2:
            continue
        domain = row[1].strip().lower().rstrip(".")
        if domain and "/" not in domain and ":" not in domain and " " not in domain:
            domains.append(domain)
    if not domains:
        raise ValueError("Tranco archive did not contain any recognizable domains.")
    return domains, hashlib.sha256(payload).hexdigest()


def build_external_set(
    phishtank: pd.DataFrame,
    tranco_domains: list[str],
    training_domains: set[str],
    max_benign: int,
) -> tuple[pd.DataFrame, dict[str, int]]:
    original_phishing = len(phishtank)
    phishing = phishtank[~phishtank["domain"].isin(training_domains)].copy()
    after_training_overlap = len(phishing)
    phishing = phishing.drop_duplicates("domain").reset_index(drop=True)
    phishing_domains = set(phishing["domain"])

    benign_rows = []
    seen_benign = set()
    for domain in tranco_domains:
        registered = training.registered_domain(f"https://{domain}/")
        if registered in training_domains or registered in phishing_domains or registered in seen_benign:
            continue
        seen_benign.add(registered)
        benign_rows.append(
            {
                "url": f"https://{domain}/",
                "label": 0,
                "verified_at": "",
                "domain": registered,
            }
        )
        if len(benign_rows) >= max_benign:
            break

    benign = pd.DataFrame(benign_rows)

    # Tranco is used only as a limited benign reference set; balance the counts
    # to make the class-specific error rates comparable, not deployment precision.
    if not phishing.empty:
        benign = benign.head(min(len(benign), len(phishing))).reset_index(drop=True)
    frame = pd.concat([phishing, benign], ignore_index=True)
    return frame, {
        "recent_verified_online_phish_before_overlap": int(original_phishing),
        "phish_after_removing_training_domains": int(after_training_overlap),
        "phish_domains_tested": int(len(phishing)),
        "benign_tranco_domains_tested": int(len(benign)),
        "training_domain_overlaps_removed": int(original_phishing - after_training_overlap),
        "class_balance_note": (
            "A balanced convenience sample is used. Precision and accuracy do not "
            "represent production prevalence."
        ),
    }


def score_external_set(model, vectorizer, frame: pd.DataFrame) -> dict[str, object]:
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("External metrics require at least one sample from each class.")
    labels = frame["label"].to_numpy(dtype=int)
    scores = model.predict_proba(vectorizer.transform(frame["url"].tolist()))[:, 1]
    predictions = (scores >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": 0.5,
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision_phishing": float(precision_score(labels, predictions, zero_division=0)),
        "recall_phishing": float(recall_score(labels, predictions, zero_division=0)),
        "f1_phishing": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate_on_tranco_reference": float(fp / (fp + tn)) if fp + tn else None,
        "average_precision": float(average_precision_score(labels, scores)),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "confusion_matrix": {
            "tranco_reference_correct": int(tn),
            "tranco_reference_flagged": int(fp),
            "phishtank_missed": int(fn),
            "phishtank_detected": int(tp),
        },
        "probability_note": "Candidate scores are uncalibrated; not probabilities or safety guarantees.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recent-days", type=int, default=90)
    parser.add_argument("--max-benign", type=int, default=10_000)
    parser.add_argument("--min-samples-per-class", type=int, default=500)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Re-evaluate saved snapshots without downloading feeds.",
    )
    args = parser.parse_args()
    if args.recent_days < 1 or args.max_benign < 1 or args.min_samples_per_class < 1:
        parser.error("All numeric options must be positive.")

    model_path = MODELS / "candidate_url_model.pkl"
    vectorizer_path = MODELS / "candidate_url_vectorizer.pkl"
    if not model_path.is_file() or not vectorizer_path.is_file():
        raise FileNotFoundError(
            "Candidate artifacts are missing. Run scripts/train_and_evaluate.py first."
        )

    started = datetime.now(timezone.utc)
    candidate_trained_at = datetime.fromtimestamp(model_path.stat().st_mtime, timezone.utc)
    cutoff = max(
        started - timedelta(days=args.recent_days),
        candidate_trained_at + timedelta(microseconds=1),
    )
    if args.offline:
        prior_snapshots = sorted(
            path for path in SNAPSHOTS.iterdir() if path.is_dir()
        ) if SNAPSHOTS.is_dir() else []
        if not prior_snapshots:
            raise FileNotFoundError("No saved feed snapshots are available for offline evaluation.")
        snapshot_dir = prior_snapshots[-1]
        metadata_path = snapshot_dir / "snapshot_metadata.json"
        snapshot_metadata = (
            json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata_path.is_file()
            else {}
        )
        feed_headers = {
            name: snapshot_metadata.get(name, {})
            for name in ("phishtank", "tranco")
        }
        feed_errors = snapshot_metadata.get("fetch_errors", {})
    else:
        app_key = os.environ.get("PHISHTANK_APP_KEY", "").strip()
        feed_path = f"{app_key}/online-valid.csv" if app_key else "online-valid.csv"
        feed_payloads, feed_headers, feed_errors = fetch_available_feeds(
            f"{PHISHTANK_BASE}/{feed_path}"
        )

        timestamp = started.strftime("%Y%m%dT%H%M%SZ")
        snapshot_dir = SNAPSHOTS / timestamp
        snapshot_dir.mkdir(parents=True, exist_ok=False)
        phishtank_path = snapshot_dir / "phishtank_online_valid.csv"
        tranco_path = snapshot_dir / "tranco_top_1m.csv.zip"
        if "phishtank" in feed_payloads:
            phishtank_path.write_bytes(feed_payloads["phishtank"])
        if "tranco" in feed_payloads:
            tranco_path.write_bytes(feed_payloads["tranco"])
        snapshot_metadata = {
            "captured_at_utc": started.isoformat(),
            "phishtank": feed_headers.get("phishtank", {}),
            "tranco": feed_headers.get("tranco", {}),
            "fetch_errors": feed_errors,
        }
        (snapshot_dir / "snapshot_metadata.json").write_text(
            json.dumps(snapshot_metadata, indent=2),
            encoding="utf-8",
        )

    training_frame, training_metadata = training.load_phiusiil()
    training_domains = set(training_frame["domain"])
    phishtank_frames = []
    phishtank_snapshot_count = 0
    latest_phishtank_headers = {}
    latest_tranco_last_modified = ""
    tranco_candidates = []
    for prior_snapshot in sorted(SNAPSHOTS.iterdir()):
        if not prior_snapshot.is_dir():
            continue
        prior_phishtank = prior_snapshot / "phishtank_online_valid.csv"
        prior_tranco = prior_snapshot / "tranco_top_1m.csv.zip"
        prior_metadata_path = prior_snapshot / "snapshot_metadata.json"
        prior_report_path = prior_snapshot / "external_metrics.json"
        if prior_metadata_path.is_file():
            prior_metadata = json.loads(prior_metadata_path.read_text(encoding="utf-8"))
        elif prior_report_path.is_file():
            prior_report = json.loads(prior_report_path.read_text(encoding="utf-8"))
            prior_metadata = {
                "phishtank": prior_report.get("phishtank", {}),
                "tranco": prior_report.get("tranco", {}),
            }
        else:
            continue

        if prior_phishtank.is_file():
            latest_phishtank_headers = prior_metadata.get("phishtank", {})
            prior_frame, _ = read_phishtank(prior_phishtank.read_bytes(), cutoff)
            if not prior_frame.empty:
                phishtank_frames.append(prior_frame)
                phishtank_snapshot_count += 1

        last_modified = prior_metadata.get("tranco", {}).get("last_modified", "")
        if prior_tranco.is_file():
            latest_tranco_last_modified = last_modified
        try:
            tranco_modified_at = parsedate_to_datetime(last_modified)
            if tranco_modified_at.tzinfo is None:
                tranco_modified_at = tranco_modified_at.replace(tzinfo=timezone.utc)
            else:
                tranco_modified_at = tranco_modified_at.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            continue
        if prior_tranco.is_file() and tranco_modified_at > candidate_trained_at:
            tranco_candidates.append((tranco_modified_at, prior_tranco, last_modified))

    if phishtank_frames:
        phishtank_frame = (
            pd.concat(phishtank_frames, ignore_index=True)
            .sort_values("verified_at", ascending=False)
            .drop_duplicates("url")
            .drop_duplicates("domain")
            .reset_index(drop=True)
        )
    else:
        phishtank_frame = pd.DataFrame(
            columns=["url", "label", "verified_at", "domain"]
        )

    if tranco_candidates:
        tranco_modified_at, selected_tranco_path, tranco_last_modified = max(
            tranco_candidates,
            key=lambda item: item[0],
        )
        tranco_payload = selected_tranco_path.read_bytes()
        tranco_domains, tranco_sha256 = read_tranco(tranco_payload)
    else:
        tranco_modified_at = None
        selected_tranco_path = None
        tranco_last_modified = ""
        tranco_domains = []
        tranco_sha256 = ""

    external_frame, sampling_metadata = build_external_set(
        phishtank_frame,
        tranco_domains,
        training_domains,
        args.max_benign,
    )

    has_both_classes = set(external_frame["label"].unique()) == {0, 1}
    enough_data = (
        sampling_metadata["phish_domains_tested"] >= args.min_samples_per_class
        and sampling_metadata["benign_tranco_domains_tested"] >= args.min_samples_per_class
    )
    metrics = None
    if has_both_classes and enough_data:
        with model_path.open("rb") as file:
            model = pickle.load(file)
        with vectorizer_path.open("rb") as file:
            vectorizer = pickle.load(file)
        metrics = score_external_set(model, vectorizer, external_frame)
    report = {
        "evaluation_started_utc": started.isoformat(),
        "evaluation_completed_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_trained_at_utc": candidate_trained_at.isoformat(),
        "phish_verification_cutoff_utc": cutoff.isoformat(),
        "recent_days": args.recent_days,
        "minimum_samples_per_class": args.min_samples_per_class,
        "candidate_model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "candidate_vectorizer_sha256": hashlib.sha256(vectorizer_path.read_bytes()).hexdigest(),
        "training_source_sha256": training_metadata["url_sha256"],
        "phishtank": {
            "source": f"{PHISHTANK_BASE}/online-valid.csv",
            "format": "CSV; verified=yes, online=yes, verification_time strictly after candidate training and within recent window",
            "last_modified": latest_phishtank_headers.get("last_modified", ""),
            "etag": latest_phishtank_headers.get("etag", ""),
            "latest_snapshot_file": "phishtank_online_valid.csv",
            "eligible_snapshots_combined": phishtank_snapshot_count,
            "verified_domains_after_training": int(len(phishtank_frame)),
            "fetch_error": feed_errors.get("phishtank"),
        },
        "tranco": {
            "source": TRANCO_URL,
            "format": "latest standard top-1m domain list with Last-Modified strictly after candidate training",
            "last_modified": latest_tranco_last_modified,
            "selected_last_modified": tranco_last_modified,
            "selected_snapshot_file": (
                str(selected_tranco_path.relative_to(SNAPSHOTS))
                if selected_tranco_path is not None
                else None
            ),
            "selected_snapshot_sha256": tranco_sha256 or None,
            "sha256": tranco_sha256,
            "domains_in_snapshot": len(tranco_domains),
            "fetch_error": feed_errors.get("tranco"),
            "label_limitation": (
                "Popularity-ranked reference only; not a verified-benign feed. "
                "A popular domain can be compromised."
            ),
        },
        "sample": sampling_metadata,
        "metrics": metrics,
        "readiness": (
            "Metrics calculated; candidate remains unapproved."
            if metrics is not None
            else "Insufficient strictly later-dated or independent samples. Capture future snapshots; no performance metrics were calculated."
        ),
        "release_status": "Do not promote without manual label review, another independent phishing source, and calibration/threshold analysis.",
        "privacy_note": (
            "URLs came from public feeds. The evaluator did not visit or fetch any URL destinations."
        ),
    }
    report_path = snapshot_dir / "external_metrics.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if metrics is None:
        print(
            "\nNo metrics were calculated. Run this collector periodically; "
            "snapshots are accumulated locally and filtered against the candidate training time."
        )
    print(f"\nFeed snapshots and report saved locally at: {snapshot_dir}")


if __name__ == "__main__":
    main()
