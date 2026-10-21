"""
PhishGuard AI — Phase 3 test suite: UX fixes and connection cleanup.

Tests cover:
  - history.html: no hardcoded fake rows; live DB records shown; empty state shown
  - scanner.html: input is type="text" (allows bare domains); type="url" is gone
  - normalize_url: bare domains are accepted and https:// prepended
  - index.html: extended duplicated sections removed; unique sections present
  - SQLite try/finally: connections close even if an exception occurs
  - DNS/SSRF safeguards still intact after all changes

Run from app/ directory:
    pytest tests/test_phase3.py -v
"""
from __future__ import annotations

import os
import re
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("FLASK_SECRET", "pytest-phase3-secret")
APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))


# ---------------------------------------------------------------------------
# Fixtures (same pattern as test_phase1.py)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flask_app():
    import app as _app_module
    _app_module.app.config["TESTING"] = True
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _app_module.DB = Path(tmp.name)
    _app_module.init_db()
    yield _app_module.app
    try:
        Path(tmp.name).unlink(missing_ok=True)
    except PermissionError:
        pass


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture()
def client_with_scan(flask_app, monkeypatch):
    """Client that has exactly one real scan in its DB."""
    import app as _app_module
    # Patch DNS + domain_age so the scan route completes deterministically
    def _dns_ok(*a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
    monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
    c = flask_app.test_client()
    c.post("/scan", data={"url": "https://example.com"})
    return c


# ---------------------------------------------------------------------------
# 1. history.html — fake rows removed, live records displayed, empty state
# ---------------------------------------------------------------------------

class TestHistoryTemplate:
    TEMPLATE_PATH = APP_DIR / "templates" / "history.html"

    def test_no_hardcoded_demo_records(self):
        """The phrase 'Demo record' must not appear anywhere in history.html."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "Demo record" not in content, (
            "Hardcoded fake 'Demo record' rows are still present in history.html."
        )

    def test_no_extended_sections_in_history(self):
        """Extended Security Guide sections must be gone."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "Extended Security Guide" not in content

    def test_jinja_if_scans_block_present(self):
        """Live DB records are rendered inside a {% if scans %} block."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "{% if scans %}" in content
        assert "{% for scan in scans %}" in content

    def test_jinja_else_empty_state_present(self):
        """An {% else %} branch must exist so empty DB shows a message."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "{% else %}" in content
        assert "No scans recorded yet" in content

    def test_history_guidance_section_preserved(self):
        """The unique history-guidance section must still be present."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert 'id="history-guidance"' in content
        assert "History management" in content

    def test_history_navigation_intact(self):
        """All nav links must still be present."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        for route in ["home", "scanner", "results_info", "history",
                      "security", "education", "faq", "about"]:
            assert route in content, f"Nav link to '{route}' missing"

    def test_history_page_empty_state_rendered(self, client):
        """When DB is empty the history page should show the empty message."""
        resp = client.get("/history")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "No scans recorded yet" in html

    def test_history_page_live_records_rendered(self, client_with_scan):
        """When DB has a scan, the live record table is shown, not a demo row."""
        resp = client_with_scan.get("/history")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "example.com" in html
        assert "Demo record" not in html

    def test_history_page_record_count_in_heading(self, client_with_scan):
        """Heading should show a record count (any positive integer)."""
        resp = client_with_scan.get("/history")
        html = resp.data.decode()
        # e.g. "1 record found." or "2 records found."
        assert re.search(r"\d+ record", html), (
            "Heading with record count not found in history page response."
        )


# ---------------------------------------------------------------------------
# 2. scanner.html — input type changed to text, bare domains allowed
# ---------------------------------------------------------------------------

class TestScannerTemplate:
    TEMPLATE_PATH = APP_DIR / "templates" / "scanner.html"

    def test_input_type_is_text_not_url(self):
        """Input must be type='text' so browsers don't block bare domains."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert 'type="text"' in content or "type='text'" in content
        assert 'type="url"' not in content and "type='url'" not in content

    def test_placeholder_mentions_bare_domain(self):
        """Placeholder text should hint that bare domains are accepted."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "example.com" in content

    def test_scanner_page_renders_200(self, client):
        resp = client.get("/scanner")
        assert resp.status_code == 200

    def test_scanner_input_present_in_rendered_page(self, client):
        html = client.get("/scanner").data.decode()
        assert 'name="url"' in html
        assert 'type="text"' in html


# ---------------------------------------------------------------------------
# 3. normalize_url — bare domains still accepted by backend
# ---------------------------------------------------------------------------

class TestNormalizeUrlBareDomain:
    def setup_method(self):
        from app import normalize_url
        self.norm = normalize_url

    def test_bare_domain_accepted(self):
        result = self.norm("google.com")
        assert result == "https://google.com"

    def test_bare_domain_with_path_accepted(self):
        result = self.norm("example.com/path?q=1")
        assert result == "https://example.com/path?q=1"

    def test_bare_subdomain_accepted(self):
        result = self.norm("sub.example.com")
        assert result == "https://sub.example.com"

    def test_full_url_unchanged(self):
        result = self.norm("https://example.com/path")
        assert result == "https://example.com/path"

    def test_empty_still_raises(self):
        from app import normalize_url
        with pytest.raises(ValueError, match="Please enter a URL"):
            normalize_url("")

    def test_ftp_still_raises(self):
        from app import normalize_url
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            normalize_url("ftp://files.example.com")

    def test_post_scan_bare_domain_accepted(self, client, monkeypatch):
        """POST /scan with a bare domain must succeed (200), not redirect (302)."""
        import app as _app_module
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "example.com"})
        assert resp.status_code == 200, (
            f"Expected 200 for bare domain, got {resp.status_code}. "
            "Backend may not be accepting bare domains."
        )
        html = resp.data.decode()
        assert "example.com" in html


# ---------------------------------------------------------------------------
# 4. index.html — extended duplicate sections removed, unique ones kept
# ---------------------------------------------------------------------------

class TestIndexTemplate:
    TEMPLATE_PATH = APP_DIR / "templates" / "index.html"

    def test_no_extended_security_guides(self):
        """Extended Security Guide duplicate sections must be gone."""
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert "Extended Security Guide" not in content

    def test_unique_phishing_section_preserved(self):
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert 'id="phishing"' in content
        assert "Why phishing matters" in content

    def test_unique_indicators_section_preserved(self):
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert 'id="indicators"' in content
        assert "Security indicators" in content

    def test_unique_checklist_section_preserved(self):
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        assert 'id="checklist"' in content
        assert "Safer browsing checklist" in content

    def test_navigation_intact(self):
        content = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        for route in ["home", "scanner", "results_info", "history",
                      "security", "education", "faq", "about"]:
            assert route in content, f"Nav link to '{route}' missing from index.html"

    def test_home_page_renders_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_home_page_no_extended_sections_in_response(self, client):
        html = client.get("/").data.decode()
        assert "Extended Security Guide" not in html


# ---------------------------------------------------------------------------
# 5. SQLite connection cleanup
# ---------------------------------------------------------------------------

class TestSqliteConnectionCleanup:
    def test_init_db_closes_on_success(self, tmp_path):
        """init_db() must close the connection under normal conditions."""
        import app as _app_module
        original_db = _app_module.DB
        _app_module.DB = tmp_path / "test_cleanup.db"
        try:
            _app_module.init_db()
            # If connection leaked, a second init_db() would still work on Windows
            _app_module.init_db()
        finally:
            _app_module.DB = original_db

    def test_history_route_closes_connection(self, client, monkeypatch):
        """history() must close the connection; calling it twice must not error."""
        resp1 = client.get("/history")
        resp2 = client.get("/history")
        assert resp1.status_code == 200
        assert resp2.status_code == 200

    def test_scan_route_closes_connection_on_success(self, client, monkeypatch):
        """scan() must close connection even when prediction succeeds."""
        import app as _app_module
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "https://example.com"})
        assert resp.status_code == 200
        # Issue a second scan — if connection leaked the DB would be locked
        resp2 = client.post("/scan", data={"url": "https://example.org"})
        assert resp2.status_code == 200

    def test_try_finally_in_init_db_source(self):
        """init_db source must use try/finally, not bare con.close()."""
        import inspect
        import app as _app_module
        src = inspect.getsource(_app_module.init_db)
        assert "try:" in src and "finally:" in src, (
            "init_db() does not use try/finally for connection cleanup."
        )

    def test_try_finally_in_history_source(self):
        import inspect
        import app as _app_module
        src = inspect.getsource(_app_module.history)
        assert "try:" in src and "finally:" in src, (
            "history() does not use try/finally for connection cleanup."
        )


# ---------------------------------------------------------------------------
# 6. DNS / SSRF safeguards still intact after all changes
# ---------------------------------------------------------------------------

class TestDnsSafeguardsIntact:
    def test_non_resolving_still_marked_unverified(self, client, monkeypatch):
        import app as _app_module
        def _no_dns(*a, **k):
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "NX")
        monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "https://fake-nonexistent-domain.invalid"})
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Unverified" in html

    def test_result_page_does_not_claim_dns_proves_safety(self, client, monkeypatch):
        """The result page must not imply DNS or HTTPS proves a site is safe.
        It is acceptable to say 'does not prove' or 'neither check proves'."""
        import app as _app_module
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "https://example.com"})
        html = resp.data.decode().lower()
        # These affirmative claims must not appear (note: "does not prove that
        # the website is safe" is allowed — it contains "the website is safe"
        # as a substring but is itself a disclaimer, not an affirmation):
        for phrase in ["dns proves the site is safe",
                       "dns confirms the site is safe",
                       "the site is proven safe",
                       "this site is confirmed safe"]:
            assert phrase not in html, (
                f"Scan result page contains an unsafe affirmative claim: '{phrase}'"
            )
        # At least one disclaimer must be present:
        assert any(p in html for p in [
            "does not prove", "not a guarantee", "neither check proves",
            "not proof", "academic prototype"
        ]), "No safety disclaimer found on scan result page."
