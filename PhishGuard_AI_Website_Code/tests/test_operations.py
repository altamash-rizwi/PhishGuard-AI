import sqlite3
from pathlib import Path

from scripts.backup_database import create_backup
from scripts.retention_cleanup import clean_expired_records


def create_test_database(path: Path):
    with sqlite3.connect(path) as con:
        con.execute(
            """CREATE TABLE scans (
                id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, url TEXT NOT NULL
            )"""
        )
        con.execute(
            "INSERT INTO scans(created_at,url) VALUES (?,?)",
            ("2000-01-01T00:00:00+00:00", "https://expired.example"),
        )


def test_backup_creates_restorable_sqlite_copy(tmp_path):
    database = tmp_path / "source.db"
    create_test_database(database)

    backup = create_backup(database, tmp_path / "backups")

    with sqlite3.connect(backup) as con:
        assert con.execute("SELECT url FROM scans").fetchone()[0] == "https://expired.example"


def test_retention_dry_run_does_not_delete_and_apply_does(tmp_path):
    database = tmp_path / "retention.db"
    create_test_database(database)

    dry_run = clean_expired_records(database)
    assert dry_run["scans"] == 1
    with sqlite3.connect(database) as con:
        assert con.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1

    applied = clean_expired_records(database, apply=True)
    assert applied["scans"] == 1
    with sqlite3.connect(database) as con:
        assert con.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
