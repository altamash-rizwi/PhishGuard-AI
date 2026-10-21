"""Train the PhishGuard AI demo model.

Run this script whenever scikit-learn is upgraded or the dataset changes.
It saves model.pkl and vectorizer.pkl into the app/ directory.

NOTE: demo_urls.csv is a small educational dataset (400 rows, 20 unique URLs).
      The 1.0 CV accuracy reflects memorisation of these patterns, not
      real-world generalisation ability.  Do not claim production accuracy.
"""
from pathlib import Path
import pickle
import sklearn
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

BASE = Path(__file__).resolve().parent

# ── Load dataset ──────────────────────────────────────────────────────────────
df = pd.read_csv(BASE / "data" / "demo_urls.csv")
print(f"Dataset: {len(df)} rows, {df['label'].value_counts().to_dict()}")

# ── Train ─────────────────────────────────────────────────────────────────────
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=2000)
X = vectorizer.fit_transform(df["url"])

model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X, df["label"])

# ── Evaluate (cross-validation) ───────────────────────────────────────────────
scores = cross_val_score(model, X, df["label"], cv=5, scoring="accuracy")
print(f"CV accuracy: {scores.mean():.4f} +/- {scores.std():.4f}  (5-fold)")

# ── Save artefacts ────────────────────────────────────────────────────────────
with open(BASE / "vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)
with open(BASE / "model.pkl", "wb") as f:
    pickle.dump(model, f)

print(f"Saved vectorizer.pkl and model.pkl  (sklearn {sklearn.__version__})")
print("NOTE: This is a small educational/demo dataset. Do not claim production accuracy.")
