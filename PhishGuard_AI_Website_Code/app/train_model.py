"""Train the PhishGuard AI demo model.

Run this script whenever scikit-learn is upgraded or the dataset changes.
It saves model.pkl and vectorizer.pkl into the app/ directory.

NOTE: demo_urls.csv is a small educational dataset (400 rows, 20 unique URLs).
      The model learns to classify http:// as phishing and https:// as
      legitimate — it does NOT learn real URL structural patterns.
      See evaluate_model.py for a full honest evaluation with scheme-swap
      probes confirming this limitation.
      Do not claim production accuracy.
"""
from pathlib import Path
import pickle
import sklearn
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score

BASE = Path(__file__).resolve().parent

# ── Load dataset ──────────────────────────────────────────────────────────────
df = pd.read_csv(BASE / "data" / "demo_urls.csv")
n_raw   = len(df)
n_dedup = df.drop_duplicates(subset=["url", "label"]).shape[0]
print(f"Dataset: {n_raw} raw rows  ({n_raw - n_dedup} exact duplicates)  "
      f"{n_dedup} unique URLs")
print(f"Label distribution: {df['label'].value_counts().to_dict()}")

# ── Train (on full raw data — matches what the app loads at runtime) ──────────
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=2000)
X = vectorizer.fit_transform(df["url"])

model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X, df["label"])

# ── Evaluation note ───────────────────────────────────────────────────────────
# Cross-validation on the raw 400-row data appears to give 1.0 accuracy
# because 95% of rows are exact duplicates; the same URL appears in both
# the training and test folds of every CV split.
#
# A dedup-CV on the 20 unique URLs and a Leave-One-Domain-Out evaluation
# also give 1.0 — but for a different reason: http:// perfectly predicts
# label=1 (phishing) and https:// perfectly predicts label=0 (legitimate)
# across all 20 training patterns.  The TF-IDF char n-gram model has
# simply learned this scheme correlation.
#
# Run evaluate_model.py for full metrics including scheme-swap probes.
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(model, X, df["label"], cv=skf, scoring="accuracy")
print(f"CV accuracy (5-fold, raw data): {scores.mean():.4f} +/- {scores.std():.4f}")
print("WARNING: This CV is inflated due to duplicate-row leakage.")
print("         Run evaluate_model.py for honest evaluation.")

# ── Save artefacts ────────────────────────────────────────────────────────────
with open(BASE / "vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)
with open(BASE / "model.pkl", "wb") as f:
    pickle.dump(model, f)

print(f"Saved vectorizer.pkl and model.pkl  (sklearn {sklearn.__version__})")
print("NOTE: This is a small educational/demo dataset. Do not claim production accuracy.")
