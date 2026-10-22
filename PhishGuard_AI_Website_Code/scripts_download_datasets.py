"""
Download public phishing datasets used by the final PBL project.

Primary dataset:
PhiUSIIL Phishing URL (Website), UCI ML Repository dataset 967.
It contains 235,795 instances and 54 features, with 134,850 legitimate and
100,945 phishing URLs. UCI reports label 1 = legitimate and label 0 = phishing.

Secondary dataset:
Phishing Websites, UCI dataset 327, with 11,055 instances and 30 integer features.

The script intentionally downloads the original data rather than silently
creating synthetic copies. See docs/DATASETS.md for attribution and license.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)

try:
    from ucimlrepo import fetch_ucirepo
except ImportError:
    print("Install requirements first: python -m pip install -r requirements.txt")
    raise

def save_dataset(dataset_id, filename):
    print(f"Fetching UCI dataset {dataset_id} ...")
    ds = fetch_ucirepo(id=dataset_id)
    X = ds.data.features
    y = ds.data.targets
    out_x = RAW / f"{filename}_features.csv"
    out_y = RAW / f"{filename}_targets.csv"
    X.to_csv(out_x, index=False)
    y.to_csv(out_y, index=False)
    print(f"Saved {out_x}")
    print(f"Saved {out_y}")
    print(f"Rows: {len(X):,}; features: {X.shape[1]:,}")

save_dataset(967, "phiusiil")
save_dataset(327, "uci_phishing_websites")
print("Dataset download complete.")
