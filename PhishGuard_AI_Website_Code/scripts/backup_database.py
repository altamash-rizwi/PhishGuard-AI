"""Create a consistent SQLite backup using SQLite's online backup API."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = Path(os.environ.get("DB_PATH", str(ROOT / "app" / "scan_history.db"))).expanduser()
DEFAULT_BACKUP_DIR = ROOT / "backups"


def create_backup(database: Path, backup_dir: Path) -> Path:
    if not database.is_file():
        raise FileNotFoundError(f"Database does not exist: {database}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_dir / f"scan_history-{timestamp}.db"
    with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(destination)) as target:
        source.backup(target)
    with closing(sqlite3.connect(destination)) as verification:
        result = verification.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise sqlite3.DatabaseError(f"Backup integrity check failed: {result}")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    args = parser.parse_args()
    print(create_backup(args.database, args.backup_dir))


if __name__ == "__main__":
    main()
