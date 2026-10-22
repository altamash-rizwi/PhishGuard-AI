from pathlib import Path
import pickle, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

BASE = Path(__file__).resolve().parent
df = pd.read_csv(BASE/"data"/"demo_urls.csv")
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2,5), max_features=2000)
X = vectorizer.fit_transform(df["url"])
model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X, df["label"])

with open(BASE/"vectorizer.pkl","wb") as f:
    pickle.dump(vectorizer,f)
with open(BASE/"model.pkl","wb") as f:
    pickle.dump(model,f)

print("Saved vectorizer.pkl and model.pkl")
print("NOTE: This is a small educational/demo dataset. Do not claim production accuracy.")
