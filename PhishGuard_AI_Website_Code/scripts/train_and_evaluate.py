"""
Train and evaluate the final URL-classification model.

Primary source: PhiUSIIL UCI dataset.
The model uses the URL text column with character n-gram TF-IDF + Random Forest.
A stratified sample can be used to control local RAM/time with --max-rows.
The script writes model artifacts and evaluation reports.
"""
from pathlib import Path
import argparse, json, pickle, time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
MODELS.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)

def load_phiusiil():
    Xp = RAW / "phiusiil_features.csv"
    yp = RAW / "phiusiil_targets.csv"
    if not Xp.exists() or not yp.exists():
        raise FileNotFoundError("Run scripts/download_datasets.py first.")
    X = pd.read_csv(Xp)
    y = pd.read_csv(yp).iloc[:, 0]
    if "URL" not in X.columns:
        raise ValueError("PhiUSIIL features file does not contain URL column.")
    urls = X["URL"].astype(str)
    # UCI specifies label 1 = legitimate and 0 = phishing.
    # Convert to project convention: 0 = legitimate, 1 = phishing.
    labels = (pd.to_numeric(y) == 0).astype(int)
    return urls, labels

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=100000,
                    help="Maximum rows used for training/evaluation. Use 0 for all rows.")
    ap.add_argument("--trees", type=int, default=200)
    args = ap.parse_args()

    t0 = time.time()
    urls, labels = load_phiusiil()
    if args.max_rows and len(urls) > args.max_rows:
        df = pd.DataFrame({"url": urls, "label": labels})
        # Stratified sampling keeps both classes represented.
        sample_parts = []
        per_class = args.max_rows // 2
        for cls in [0, 1]:
            part = df[df.label == cls].sample(n=min(per_class, (df.label == cls).sum()), random_state=42)
            sample_parts.append(part)
        df = pd.concat(sample_parts).sample(frac=1, random_state=42)
        urls, labels = df.url, df.label

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        urls, labels, test_size=0.20, random_state=42, stratify=labels
    )

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        min_df=2,
        max_features=120000,
        lowercase=True,
        sublinear_tf=True
    )
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    model = RandomForestClassifier(
        n_estimators=args.trees,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        max_features="sqrt"
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    metrics = {
        "dataset": "PhiUSIIL Phishing URL (Website)",
        "dataset_id": 967,
        "rows_used": int(len(urls)),
        "training_rows": int(len(X_train_text)),
        "test_rows": int(len(X_test_text)),
        "features_after_tfidf": int(X_train.shape[1]),
        "trees": args.trees,
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, pred, zero_division=0)),
        "confusion_matrix": cm.tolist(),
        "label_convention": {"0": "legitimate", "1": "phishing"},
        "runtime_seconds": round(time.time() - t0, 2)
    }

    with open(MODELS / "final_tfidf_vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    with open(MODELS / "final_random_forest.pkl", "wb") as f:
        pickle.dump(model, f)

    (REPORTS / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (REPORTS / "classification_report.txt").write_text(
        classification_report(y_test, pred, target_names=["legitimate", "phishing"], zero_division=0),
        encoding="utf-8"
    )
    print(json.dumps(metrics, indent=2))
    print("Saved model artifacts to models/ and reports to reports/.")

if __name__ == "__main__":
    main()
