import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from app import app, normalize_url, extract_features

def test_normalize_url():
    assert normalize_url("example.com").startswith("https://")
    assert normalize_url("https://example.com").startswith("https://")

def test_features():
    f = extract_features("http://login-verify.example.com/path?a=1")
    assert f["HTTPS"] == "No"
    assert f["Hyphen Count"] >= 1
    assert "login" in f["Suspicious Words"]

def test_scanner_page():
    client = app.test_client()
    response = client.get("/scanner")
    assert response.status_code == 200


def test_non_resolving_domain_is_not_marked_legitimate(monkeypatch):
    import socket
    from app import predict

    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = predict("https://googlgijyughke.com")
    assert result["domain_status"] == "not_resolving"
    assert result["label"] == "Unverified / Domain Not Resolving"
    assert result["threat"] == "Unverified"


def test_resolving_domain_keeps_model_classification(monkeypatch):
    import socket
    from app import predict

    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = predict("https://example.com")
    assert result["domain_status"] == "resolves"
    assert result["label"] in {"Potential Phishing", "Potentially Legitimate"}
