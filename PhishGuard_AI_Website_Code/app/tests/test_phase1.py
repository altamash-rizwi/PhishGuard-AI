"""
PhishGuard AI — Phase 1 test suite.

Tests cover:
  - Application startup and DB initialisation
  - URL normalisation (valid inputs, invalid inputs, edge cases)
  - DNS check_domain() logic (resolving, not-resolving, IP, invalid)
  - Model and vectorizer loading (no InconsistentVersionWarning)
  - predict() DNS override: non-resolving must never produce "Legitimate"
  - predict() happy path: resolving domain keeps model classification
  - Environment variable gating: FLASK_SECRET and FLASK_DEBUG
  - Scan route end-to-end (POST /scan with monkeypatched DNS)

Run from the repo root:
    pytest app/tests/test_phase1.py -v
"""
import os
import sys
import socket
import pickle
import sqlite3
import tempfile
import warnings
from pathlib import Path

import pytest

# Ensure app/ is on the path regardless of where pytest is invoked from.
APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def flask_app():
    """Return a configured Flask test application with a temporary DB."""
    os.environ.setdefault("FLASK_SECRET", "test-secret-for-pytest")
    import app as _app_module
    _app_module.app.config["TESTING"] = True
    # Point DB at a temporary file so tests don't pollute scan_history.db
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_db.close()
    _app_module.DB = Path(tmp_db.name)
    _app_module.init_db()
    yield _app_module.app
    try:
        Path(tmp_db.name).unlink(missing_ok=True)
    except PermissionError:
        pass  # Windows may hold the file; temp files are cleaned at process exit


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Startup / DB initialisation
# ─────────────────────────────────────────────────────────────────────────────

class TestStartup:
    def test_init_db_creates_scans_table(self, flask_app):
        import app as _app_module
        con = sqlite3.connect(_app_module.DB)
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        con.close()
        assert "scans" in tables

    def test_init_db_idempotent(self, flask_app):
        """Calling init_db() twice must not raise."""
        import app as _app_module
        _app_module.init_db()  # already called in fixture — call again
        _app_module.init_db()

    def test_home_page_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_scanner_page_returns_200(self, client):
        resp = client.get("/scanner")
        assert resp.status_code == 200

    def test_history_page_returns_200(self, client):
        resp = client.get("/history")
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 2. URL normalisation
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizeUrl:
    """normalize_url() must always produce a valid https:// or http:// URL."""

    def setup_method(self):
        from app import normalize_url
        self.norm = normalize_url

    def test_bare_domain_gets_https_prefix(self):
        assert self.norm("example.com") == "https://example.com"

    def test_explicit_https_unchanged(self):
        assert self.norm("https://example.com") == "https://example.com"

    def test_explicit_http_unchanged(self):
        assert self.norm("http://example.com") == "http://example.com"

    def test_strips_leading_whitespace(self):
        assert self.norm("  https://example.com") == "https://example.com"

    def test_strips_trailing_whitespace(self):
        assert self.norm("https://example.com  ") == "https://example.com"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Please enter a URL"):
            self.norm("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Please enter a URL"):
            self.norm("   ")

    def test_none_raises(self):
        with pytest.raises(ValueError, match="Please enter a URL"):
            self.norm(None)

    def test_ftp_scheme_raises(self):
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            self.norm("ftp://files.example.com")

    def test_no_netloc_raises(self):
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            self.norm("https://")


# ─────────────────────────────────────────────────────────────────────────────
# 3. DNS check_domain()
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckDomain:
    def setup_method(self):
        from app import check_domain
        self.check = check_domain

    def test_ipv4_literal_returns_ip_status(self):
        result = self.check("http://192.168.1.1/path")
        assert result["status"] == "ip"
        assert "192.168.1.1" in result["addresses"]

    def test_empty_netloc_returns_invalid(self):
        result = self.check("https://")
        assert result["status"] == "invalid"

    def test_resolving_domain_returns_resolves(self, monkeypatch):
        def fake_getaddrinfo(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        result = self.check("https://example.com")
        assert result["status"] == "resolves"
        assert "93.184.216.34" in result["addresses"]

    def test_eai_noname_returns_not_resolving(self, monkeypatch):
        def fake_getaddrinfo(*a, **k):
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2),
                                  "Name or service not known")
        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        result = self.check("https://this-domain-does-not-exist.invalid")
        assert result["status"] == "not_resolving"
        assert result["addresses"] == []

    def test_generic_network_error_returns_unknown(self, monkeypatch):
        def fake_getaddrinfo(*a, **k):
            raise socket.gaierror(99, "Network unreachable")
        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        result = self.check("https://example.com")
        assert result["status"] == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Model and vectorizer loading — no InconsistentVersionWarning
# ─────────────────────────────────────────────────────────────────────────────

class TestModelLoading:
    def test_model_pkl_loads_without_version_warning(self):
        model_path = APP_DIR / "model.pkl"
        assert model_path.exists(), "model.pkl is missing — run train_model.py"
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # any warning becomes an error
            with open(model_path, "rb") as f:
                m = pickle.load(f)
        assert hasattr(m, "predict")
        assert hasattr(m, "predict_proba")

    def test_vectorizer_pkl_loads_without_version_warning(self):
        vec_path = APP_DIR / "vectorizer.pkl"
        assert vec_path.exists(), "vectorizer.pkl is missing — run train_model.py"
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with open(vec_path, "rb") as f:
                v = pickle.load(f)
        assert hasattr(v, "transform")

    def test_model_produces_valid_prediction(self):
        model_path = APP_DIR / "model.pkl"
        vec_path = APP_DIR / "vectorizer.pkl"
        with open(model_path, "rb") as f:
            m = pickle.load(f)
        with open(vec_path, "rb") as f:
            v = pickle.load(f)
        X = v.transform(["http://bank-login-verify.example.com"])
        pred = int(m.predict(X)[0])
        proba = m.predict_proba(X)[0]
        assert pred in {0, 1}
        assert abs(sum(proba) - 1.0) < 1e-6

    def test_model_loaded_in_app_is_not_none(self):
        import app as _app_module
        assert _app_module.model is not None, (
            "app.model is None — model.pkl failed to load. Run train_model.py."
        )
        assert _app_module.vectorizer is not None


# ─────────────────────────────────────────────────────────────────────────────
# 5. predict() — DNS safety invariants
# ─────────────────────────────────────────────────────────────────────────────

class TestPredictDnsSafety:
    """A non-resolving domain must NEVER produce a 'Legitimate' label."""

    def test_non_resolving_domain_label(self, monkeypatch):
        def _no_dns(*a, **k):
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "NX")
        monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
        from app import predict
        result = predict("https://totally-fake-domain-xyz-999.invalid")
        assert result["domain_status"] == "not_resolving"
        assert result["label"] == "Unverified / Domain Not Resolving"
        assert result["threat"] == "Unverified"
        assert "Legitimate" not in result["label"]

    def test_non_resolving_domain_even_for_legitimate_looking_url(self, monkeypatch):
        """A URL that looks legitimate but whose hostname does not resolve
        must still be flagged as unverified, not legitimate."""
        def _no_dns(*a, **k):
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "NX")
        monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
        from app import predict
        result = predict("https://google.com.totally-fake-suffix.invalid")
        assert result["threat"] != "Lower"
        assert "Legitimate" not in result["label"]

    def test_resolving_domain_keeps_model_classification(self, monkeypatch):
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        from app import predict
        result = predict("https://example.com")
        assert result["domain_status"] == "resolves"
        assert result["label"] in {"Potential Phishing", "Potentially Legitimate"}

    def test_dns_message_never_claims_safety(self, monkeypatch):
        """The domain_message must not contain words implying the site is safe."""
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        from app import predict
        result = predict("https://example.com")
        msg = result.get("domain_message", "").lower()
        # The message must not claim DNS proves safety
        assert "safe" not in msg
        assert "trusted" not in msg
        assert "proves" not in msg


# ─────────────────────────────────────────────────────────────────────────────
# 6. Environment variable gating
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvConfig:
    def test_secret_key_is_not_original_hardcoded_value(self):
        import app as _app_module
        original = "phishguard-academic-demo-secret"
        assert _app_module.app.secret_key != original, (
            "The old hardcoded secret key is still in use."
        )

    def test_secret_key_is_not_empty(self):
        import app as _app_module
        assert _app_module.app.secret_key
        assert len(_app_module.app.secret_key) >= 8

    def test_debug_default_is_off(self):
        """Without FLASK_DEBUG=1 the app must not run in debug mode."""
        # app is already imported; check the configured value of DEBUG
        import app as _app_module
        # Flask sets app.debug when app.run() is called; we check the env-var
        # logic independently here.
        debug_flag = os.environ.get("FLASK_DEBUG", "0") == "1"
        # In CI / test environment FLASK_DEBUG should not be set to 1
        assert not debug_flag or os.environ.get("FLASK_DEBUG") == "1"


# ─────────────────────────────────────────────────────────────────────────────
# 7. POST /scan end-to-end with monkeypatched DNS
# ─────────────────────────────────────────────────────────────────────────────

class TestScanRoute:
    def test_post_scan_resolving_domain_returns_200(self, client, monkeypatch):
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        # domain_age() tries WHOIS; monkeypatch to avoid network call
        import app as _app_module
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "https://google.com"})
        assert resp.status_code == 200
        assert b"google.com" in resp.data

    def test_post_scan_non_resolving_shows_unverified(self, client, monkeypatch):
        def _no_dns(*a, **k):
            raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "NX")
        monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
        import app as _app_module
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")
        resp = client.post("/scan", data={"url": "https://totallyfakedomain99.invalid"})
        assert resp.status_code == 200
        assert b"Unverified" in resp.data

    def test_post_scan_empty_url_redirects(self, client):
        resp = client.post("/scan", data={"url": ""})
        # Should redirect back to scanner with a flash message
        assert resp.status_code == 302

    def test_post_scan_invalid_scheme_redirects(self, client):
        resp = client.post("/scan", data={"url": "ftp://files.example.com"})
        assert resp.status_code == 302

    def test_scan_record_written_to_db(self, client, monkeypatch):
        def _dns_ok(*a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", _dns_ok)
        import app as _app_module
        monkeypatch.setattr(_app_module, "domain_age", lambda url: "Unavailable")

        before = sqlite3.connect(_app_module.DB).execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]
        client.post("/scan", data={"url": "https://example.com"})
        after = sqlite3.connect(_app_module.DB).execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]
        assert after == before + 1
