from flask import Flask, render_template, request, redirect, url_for, flash
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
import sqlite3, pickle, re, math, socket

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = "phishguard-academic-demo-secret"

DB = BASE / "scan_history.db"
MODEL = BASE.parent / "models" / "final_random_forest.pkl"
VECTORIZER = BASE.parent / "models" / "final_tfidf_vectorizer.pkl"
DEMO_MODEL = BASE / "model.pkl"
DEMO_VECTORIZER = BASE / "vectorizer.pkl"

try:
    with open(MODEL, "rb") as f:
        model = pickle.load(f)
    with open(VECTORIZER, "rb") as f:
        vectorizer = pickle.load(f)
except Exception:
    try:
        with open(DEMO_MODEL, "rb") as f:
            model = pickle.load(f)
        with open(DEMO_VECTORIZER, "rb") as f:
            vectorizer = pickle.load(f)
    except Exception:
        model = None
        vectorizer = None

RECOMMENDATIONS = [
    "Do not enter passwords, OTPs or payment details on an unverified page.",
    "Verify the registered domain independently before trusting a sensitive website.",
    "Use the official application or manually entered official domain for banking and payments.",
    "Be cautious with urgency, rewards, account warnings and unexpected verification requests.",
]

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            url TEXT NOT NULL,
            label TEXT NOT NULL,
            confidence REAL NOT NULL,
            threat TEXT NOT NULL,
            domain_age TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()

def normalize_url(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Please enter a valid HTTP/HTTPS URL.")
    return value

def extract_features(url):
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    lower = url.lower()
    suspicious_words = [
        word for word in
        ["login","verify","verification","secure","update","account","password","reward","free","gift","urgent","confirm","bank"]
        if word in lower
    ]
    return {
        "URL Length": len(url),
        "HTTPS": "Yes" if p.scheme == "https" else "No",
        "Dot Count": url.count("."),
        "Hyphen Count": url.count("-"),
        "Subdomains": max(0, len(host.split(".")) - 2) if host else 0,
        "@ Symbol": "Yes" if "@" in url else "No",
        "IP Address": "Yes" if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "") else "No",
        "Suspicious Words": ", ".join(suspicious_words) if suspicious_words else "None",
        "Query Length": len(query),
        "Path Length": len(path),
        "Hostname": host or "Unavailable",
    }

def check_domain(url):
    """Check whether the submitted hostname resolves in DNS without fetching the site.

    This is deliberately a DNS-only check: the application must not make arbitrary
    HTTP requests to user-supplied URLs because that can create an SSRF risk.
    """
    host = urlparse(url).hostname
    if not host:
        return {"status": "invalid", "message": "Hostname unavailable.", "addresses": []}

    # Literal IPv4 addresses do not require DNS resolution.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return {"status": "ip", "message": "The URL uses an IP address instead of a domain name.", "addresses": [host]}

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in results if item[4]})
        if addresses:
            return {"status": "resolves", "message": "The hostname resolves in DNS.", "addresses": addresses}
        return {"status": "not_resolving", "message": "The hostname did not return a DNS address.", "addresses": []}
    except socket.gaierror as exc:
        # EAI_NONAME / EAI_NODATA means the hostname is not known or has no usable address.
        if getattr(exc, "errno", None) in {getattr(socket, "EAI_NONAME", -999), getattr(socket, "EAI_NODATA", -998)}:
            return {"status": "not_resolving", "message": "The hostname could not be resolved by DNS.", "addresses": []}
        return {"status": "unknown", "message": "DNS verification could not be completed from the current network.", "addresses": []}
    except Exception:
        return {"status": "unknown", "message": "DNS verification could not be completed from the current network.", "addresses": []}

def domain_age(url):
    # Optional WHOIS: keeps the prototype runnable even when python-whois/network access is unavailable.
    try:
        import whois
        host = urlparse(url).hostname
        if not host:
            return "Unavailable"
        info = whois.whois(host)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created is None:
            return "Unavailable"
        if getattr(created, "tzinfo", None) is None:
            created = created.replace(tzinfo=timezone.utc)
        days = max(0, (datetime.now(timezone.utc) - created).days)
        return f"{days // 365} years, {(days % 365) // 30} months"
    except Exception:
        return "Unavailable"

def predict(url):
    features = extract_features(url)
    domain_check = check_domain(url)

    if model is not None and vectorizer is not None:
        X = vectorizer.transform([url])
        pred = int(model.predict(X)[0])
        probs = model.predict_proba(X)[0]
        model_score = float(max(probs))
    else:
        # Safe fallback for a source-only install without model artifacts.
        score = 0
        score += 2 if features["HTTPS"] == "No" else 0
        score += 1 if features["Hyphen Count"] >= 2 else 0
        score += 2 if features["Suspicious Words"] != "None" else 0
        score += 2 if features["IP Address"] == "Yes" else 0
        pred = 1 if score >= 3 else 0
        model_score = min(0.55 + score * 0.07, 0.95)

    # Critical correction: a URL-text model cannot establish that a domain actually exists.
    # If DNS says the hostname does not resolve, do not display it as legitimate.
    if domain_check["status"] == "not_resolving":
        label = "Unverified / Domain Not Resolving"
        threat = "Unverified"
        message = (
            "The submitted hostname could not be resolved by DNS. The URL-text model alone cannot prove that "
            "a nonexistent or unreachable domain is legitimate, so this result is treated as unverified."
        )
    elif domain_check["status"] == "unknown":
        label = "Unable to Verify Domain"
        threat = "Unknown"
        message = (
            "The URL-text model produced a classification, but DNS verification could not be completed from the "
            "current network. Do not treat the model result as proof that the website is legitimate."
        )
    elif pred == 1:
        label = "Potential Phishing"
        threat = "Higher"
        message = "The URL contains patterns that the model associates more strongly with phishing examples."
    else:
        label = "Potentially Legitimate"
        threat = "Lower"
        message = (
            "The domain resolves in DNS and the URL appears more consistent with the legitimate examples used by "
            "the current model. This does not prove that the website is safe."
        )

    features["DNS Status"] = domain_check["status"].replace("_", " ").title()
    features["DNS Details"] = domain_check["message"]

    return {
        "url": url,
        "label": label,
        "confidence": model_score,
        "model_score": model_score,
        "threat": threat,
        "message": message,
        "features": features,
        "domain_status": domain_check["status"],
        "domain_message": domain_check["message"],
        "domain_addresses": domain_check["addresses"],
        "domain_age": domain_age(url),
        "recommendations": RECOMMENDATIONS,
    }

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        url = normalize_url(request.form.get("url"))
        result = predict(url)
        con = db()
        con.execute(
            "INSERT INTO scans(created_at,url,label,confidence,threat,domain_age) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), result["url"], result["label"],
             result["confidence"], result["threat"], result["domain_age"])
        )
        con.commit()
        con.close()
        return render_template("scan_result.html", result=result)
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("scanner"))

@app.route("/result")
def scan_result():
    return redirect(url_for("scanner"))

@app.route("/history")
def history():
    con = db()
    rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 200").fetchall()
    con.close()
    return render_template("history.html", scans=rows)

@app.route("/results")
def results_info():
    return render_template("results.html")

@app.route("/security")
def security():
    return render_template("security.html")

@app.route("/education")
def education():
    return render_template("education.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
