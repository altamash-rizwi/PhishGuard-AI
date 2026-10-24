"""Download the PhiUSIIL URL dataset used by the phishing URL model."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)

try:
    from ucimlrepo import fetch_ucirepo
except ImportError:
    print("Install requirements first: python -m pip install -r requirements.txt")
    raise

print("Fetching PhiUSIIL Phishing URL (Website), UCI dataset 967 ...")
dataset = fetch_ucirepo(id=967)
features = dataset.data.features
targets = dataset.data.targets
if "URL" not in features.columns or targets.empty:
    raise ValueError("UCI dataset 967 did not return the expected URL and target columns.")

features_path = RAW / "phiusiil_features.csv"
targets_path = RAW / "phiusiil_targets.csv"
features.to_csv(features_path, index=False)
targets.to_csv(targets_path, index=False)
print(f"Saved {features_path}")
print(f"Saved {targets_path}")
print(f"Rows: {len(features):,}; feature columns: {features.shape[1]:,}")
