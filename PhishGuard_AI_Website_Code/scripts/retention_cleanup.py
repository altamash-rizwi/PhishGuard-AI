"""Review or delete application records older than the configured retention windows."""
import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = Path(os.environ.get("DB_PATH", str(ROOT / "app" / "scan_history.db"))).expanduser()
RETENTION_WINDOWS = {
    "scans": ("scans", "created_at", 90),
    "lesson_completions": ("lesson_completions", "completed_at", 90),
    "lesson_progress": ("lesson_progress", "completed_at", 90),
    "quiz_attempts": ("quiz_attempts", "created_at", 90),
    "user_quiz_attempts": ("user_quiz_attempts", "created_at", 90),
    "phishing_reports": ("phishing_reports", "created_at", 90),
    "audit_logs": ("audit_logs", "created_at", 365),
}


def expired_counts(database: Path) -> dict[str, int]:
    counts = {}
    with closing(sqlite3.connect(database)) as con:
        for name, (table, timestamp_column, days) in RETENTION_WINDOWS.items():
            columns = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
            if timestamp_column not in columns:
                counts[name] = 0
                continue
            counts[name] = con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE datetime({timestamp_column}) < datetime('now', ?)",
                (f"-{days} days",),
            ).fetchone()[0]
        review_columns = {row[1] for row in con.execute("PRAGMA table_info(report_reviews)")}
        if "created_at" in review_columns:
            counts["report_reviews"] = con.execute(
                """SELECT COUNT(*) FROM report_reviews
                   WHERE datetime(created_at) < datetime('now', '-365 days')
                      OR report_id IN (
                          SELECT id FROM phishing_reports
                          WHERE datetime(created_at) < datetime('now', '-90 days')
                      )"""
            ).fetchone()[0]
        else:
            counts["report_reviews"] = 0
    return counts


def clean_expired_records(database: Path, apply: bool = False) -> dict[str, int]:
    counts = expired_counts(database)
    if not apply:
        return counts
    with closing(sqlite3.connect(database)) as con:
        con.execute("PRAGMA foreign_keys = ON")
        review_columns = {row[1] for row in con.execute("PRAGMA table_info(report_reviews)")}
        if "created_at" in review_columns:
            con.execute(
                """DELETE FROM report_reviews
                   WHERE datetime(created_at) < datetime('now', '-365 days')
                      OR report_id IN (
                          SELECT id FROM phishing_reports
                          WHERE datetime(created_at) < datetime('now', '-90 days')
                      )"""
            )
        for _name, (table, timestamp_column, days) in RETENTION_WINDOWS.items():
            columns = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
            if timestamp_column in columns:
                con.execute(
                    f"DELETE FROM {table} WHERE datetime({timestamp_column}) < datetime('now', ?)",
                    (f"-{days} days",),
                )
        con.commit()
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete expired records; default is a dry-run count only.",
    )
    args = parser.parse_args()
    counts = clean_expired_records(args.database, apply=args.apply)
    mode = "Deleted" if args.apply else "Would delete"
    for table, count in counts.items():
        print(f"{mode} {count} expired {table} record(s)")
    if not args.apply:
        print("Dry run only. Back up the database, then pass --apply to delete.")


if __name__ == "__main__":
    main()
