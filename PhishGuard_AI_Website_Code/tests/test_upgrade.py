"""Regression checks for the PBL-1 prototype upgrade."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import app as app_module
import re
def csrf_token(client, path="/"):
    response = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"No CSRF token found on {path}"
    return match.group(1).decode()



def test_normalize_bare_domain():
    assert app_module.normalize_url("example.com") == "https://example.com"


def test_rejects_bad_scheme():
    try:
        app_module.normalize_url("javascript:alert(1)")
    except ValueError:
        pass
    else:
        raise AssertionError("Non-HTTP scheme should be rejected")


def test_risk_assessment_explains_http_and_at_symbol():
    url = "http://user@example.test/login-verify"
    features = app_module.extract_features(url)
    score, level, reasons = app_module.risk_assessment(url, features)
    assert 0 <= score <= 100
    assert level in {"Low", "Moderate", "High"}
    titles = {item["title"] for item in reasons}
    assert "No HTTPS" in titles
    assert "At-sign in URL" in titles


def test_scan_result_route(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "test_scans.db")
    app_module.init_db()
    monkeypatch.setattr(app_module, "domain_age", lambda url: "Unavailable (test)")
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))])
    client = app_module.app.test_client()
    response = client.post("/scan", data={"url": "http://account-verify.example.test/login", "csrf_token": csrf_token(client, "/scanner")})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "URL INDICATOR SCORE" in body
    assert "Findings that added risk points" in body
    assert "Inspection checklist" in body


def test_history_has_no_static_demo_rows(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "history.db")
    app_module.init_db()
    client = app_module.app.test_client()
    response = client.get("/history")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Demo record 001" not in body
    assert "No scan history yet" in body
