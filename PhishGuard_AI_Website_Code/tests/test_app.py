import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import app as app_module
import re
def csrf_token(client, path="/"):
    response = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"No CSRF token found on {path}"
    return match.group(1).decode()



def test_normalize_url():
    assert app_module.normalize_url("example.com") == "https://example.com"
    assert app_module.normalize_url("https://example.com") == "https://example.com"


def test_production_settings_require_secret_hosts_and_debug_off():
    with pytest.raises(RuntimeError, match="FLASK_SECRET"):
        app_module.validate_production_settings("production", "", "0", ["example.test"])
    with pytest.raises(RuntimeError, match="FLASK_DEBUG"):
        app_module.validate_production_settings("production", "x" * 32, "1", ["example.test"])
    with pytest.raises(RuntimeError, match="TRUSTED_HOSTS"):
        app_module.validate_production_settings("production", "x" * 32, "0", [])


def test_init_db_creates_missing_database_directory(monkeypatch, tmp_path):
    nested_db = tmp_path / "nested" / "data" / "scan_history.db"
    monkeypatch.setattr(app_module, "DB", nested_db)
    app_module.init_db()
    assert nested_db.exists()


def test_normalize_rejects_non_http_scheme():
    try:
        app_module.normalize_url("javascript:alert(1)")
    except ValueError:
        return
    raise AssertionError("Non-HTTP schemes must be rejected")


def test_features_and_score_explanations():
    url = "http://user@login-verify.example.com/path?a=1"
    f = app_module.extract_features(url)
    assert f["HTTPS"] == "No"
    assert f["Hyphen Count"] >= 1
    assert "login" in f["Suspicious Words"]
    score, level, reasons = app_module.risk_assessment(url, f)
    assert 0 <= score <= 100
    assert level in {"Low", "Moderate", "High"}
    assert {"No HTTPS", "At-sign in URL"}.issubset({r["title"] for r in reasons})


def test_predict_reports_phishing_class_score_not_max_class_score(monkeypatch):
    class FakeVectorizer:
        def transform(self, urls):
            return urls

    class FakeModel:
        classes_ = [0, 1]

        def predict(self, _features):
            return [0]

        def predict_proba(self, _features):
            return [[0.99, 0.01]]

    monkeypatch.setattr(app_module, "vectorizer", FakeVectorizer())
    monkeypatch.setattr(app_module, "model", FakeModel())
    monkeypatch.setattr(app_module, "check_domain", lambda _url: {
        "status": "resolves",
        "message": "The hostname resolves in DNS.",
        "addresses": ["192.0.2.1"],
    })
    monkeypatch.setattr(app_module, "domain_age", lambda _url: "Unavailable (test)")

    result = app_module.predict("https://ordinary.example")

    assert result["model_label"] == "Potentially Legitimate"
    assert result["confidence"] == pytest.approx(0.01)


def test_scanner_page():
    response = app_module.app.test_client().get("/scanner")
    assert response.status_code == 200
    assert b"New URL scan" in response.data
    assert b"/static/js/prototype.js?v=1" in response.data
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]


def test_home_example_buttons_use_csp_compatible_script():
    response = app_module.app.test_client().get("/")
    assert response.status_code == 200
    assert b"/static/js/prototype.js?v=1" in response.data
    assert b"<script>" not in response.data


def test_non_resolving_domain_is_unverified(monkeypatch):
    import socket
    monkeypatch.setattr(app_module, "domain_age", lambda url: "Unavailable (test)")
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = app_module.predict("https://definitely-not-a-real-test-domain.invalid")
    assert result["domain_status"] == "not_resolving"
    assert result["label"] == "Unverified / Domain Not Resolving"
    assert result["threat"] == "Unverified"


def test_scan_report_and_database(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "scan-test.db")
    app_module.init_db()
    monkeypatch.setattr(app_module, "domain_age", lambda url: "Unavailable (test)")
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))])
    client = app_module.app.test_client()
    response = client.post("/scan", data={"url": "http://login-verify.example.test/path", "csrf_token": csrf_token(client, "/scanner")})
    assert response.status_code == 200
    assert b"URL INDICATOR SCORE" in response.data
    assert b"Findings that added risk points" in response.data
    assert b"Inspection checklist" in response.data
    history = client.get("/history")
    assert history.status_code == 200
    assert b"login-verify.example.test" in history.data
    assert b"Demo record 001" not in history.data


def test_home_dashboard_loads(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "home-test.db")
    app_module.init_db()
    response = app_module.app.test_client().get("/")
    assert response.status_code == 200
    assert b"URL Intelligence" in response.data


def test_dashboard_high_risk_count_uses_score_band(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "dashboard-risk.db")
    app_module.init_db()
    with app_module.db() as con:
        con.executemany(
            """INSERT INTO scans
               (created_at,url,label,confidence,threat,domain_age,risk_score,checks_json,owner_key)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            [
                ("2026-01-01T00:00:00+00:00", "https://high.example", "Unverified",
                 0.0, "Unverified", "Unavailable", 70, "[]", "guest"),
                ("2026-01-02T00:00:00+00:00", "https://low.example", "High-risk indicators found",
                 0.0, "Higher", "Unavailable", 10, "[]", "guest"),
            ],
        )

    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["guest_key"] = "guest"
        session["csrf_token"] = "test-token"
    body = client.get("/").get_data(as_text=True)
    assert re.search(r"High-risk indicators</span\s*><strong>\s*1\s*</strong", body)
    assert 'href="/scanner"' in body
    assert 'href="/results"' in body


def test_dashboard_reports_model_availability(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "dashboard-model.db")
    app_module.init_db()
    monkeypatch.setattr(app_module, "model", None)
    monkeypatch.setattr(app_module, "vectorizer", None)

    body = app_module.app.test_client().get("/").get_data(as_text=True)
    assert "ML signal</span><strong>Unavailable</strong" in body


def test_scan_detail_is_private_to_guest_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "guest-scan-privacy.db")
    app_module.init_db()
    with app_module.db() as con:
        cursor = con.execute(
            """INSERT INTO scans
               (created_at,url,label,confidence,threat,domain_age,risk_score,checks_json,owner_key)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("2026-01-01T00:00:00+00:00", "https://private.example", "Private",
             0.0, "Lower", "Unavailable", 0, "[]", "owner-guest"),
        )
        scan_id = cursor.lastrowid

    owner = app_module.app.test_client()
    with owner.session_transaction() as session:
        session["guest_key"] = "owner-guest"
    assert owner.get(f"/api/v1/scans/{scan_id}").status_code == 200

    other_guest = app_module.app.test_client()
    with other_guest.session_transaction() as session:
        session["guest_key"] = "other-guest"
    response = other_guest.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 403
    assert response.get_json() == {"error": "forbidden"}

    authenticated_guest = app_module.app.test_client()
    with authenticated_guest.session_transaction() as session:
        session["guest_key"] = "other-guest"
        session["user_id"] = 42
    assert authenticated_guest.get(f"/api/v1/scans/{scan_id}").status_code == 403
    assert authenticated_guest.get("/api/v1/scans").get_json()["items"] == []


def test_scan_detail_authorization_for_users_and_staff(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "scan-authorization.db")
    app_module.init_db()
    with app_module.db() as con:
        user_ids = {}
        for role in ("user", "user", "analyst"):
            cursor = con.execute(
                "INSERT INTO users(email,password_hash,role,created_at) VALUES (?,?,?,?)",
                (f"{role}-{len(user_ids)}@example.test", "unused", role, app_module.utc_now()),
            )
            user_ids[f"{role}-{len(user_ids)}"] = cursor.lastrowid
        cursor = con.execute(
            """INSERT INTO scans
               (created_at,url,label,confidence,threat,domain_age,risk_score,checks_json,user_id,owner_key)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("2026-01-01T00:00:00+00:00", "https://account.example", "Private",
             0.0, "Lower", "Unavailable", 0, "[]", user_ids["user-0"], None),
        )
        scan_id = cursor.lastrowid

    owner = app_module.app.test_client()
    with owner.session_transaction() as session:
        session["user_id"] = user_ids["user-0"]
    assert owner.get(f"/api/v1/scans/{scan_id}").status_code == 200
    assert owner.get("/api/v1/scans").get_json()["items"][0]["id"] == scan_id

    other_user = app_module.app.test_client()
    with other_user.session_transaction() as session:
        session["user_id"] = user_ids["user-1"]
    assert other_user.get(f"/api/v1/scans/{scan_id}").status_code == 403
    assert other_user.get("/api/v1/scans").get_json()["items"] == []
    assert other_user.get("/admin").status_code == 403
    assert other_user.get("/api/v1/reports").status_code == 403

    inactive_owner = app_module.app.test_client()
    with app_module.db() as con:
        con.execute("UPDATE users SET is_active=0 WHERE id=?", (user_ids["user-0"],))
    with inactive_owner.session_transaction() as session:
        session["user_id"] = user_ids["user-0"]
    assert inactive_owner.get(f"/api/v1/scans/{scan_id}").status_code == 403
    assert inactive_owner.get("/api/v1/scans").get_json()["items"] == []

    with app_module.db() as con:
        con.execute("UPDATE users SET is_active=1 WHERE id=?", (user_ids["user-0"],))
    analyst = app_module.app.test_client()
    with analyst.session_transaction() as session:
        session["user_id"] = user_ids["analyst-2"]
    assert analyst.get(f"/api/v1/scans/{scan_id}").status_code == 200
    assert analyst.get("/admin").status_code == 200
    assert analyst.get("/api/v1/reports").status_code == 200


def test_health_check_reports_database_status(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "health.db")
    app_module.init_db()
    response = app_module.app.test_client().get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
