"""PhishGuard AI - explainable URL risk assessment prototype.

Important: the demo classifier was trained on a weak dataset. The transparent
heuristic score is an indicator summary, not a calibrated probability or verdict.
The application never opens the submitted destination URL.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone
from pathlib import Path
from ipaddress import ip_address
import json
import os
import pickle
import re
import sqlite3
import socket
import secrets
import time
from functools import wraps
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
if APP_ENV not in {"development", "production"}:
    raise RuntimeError("APP_ENV must be either 'development' or 'production'.")
FLASK_SECRET = os.environ.get("FLASK_SECRET")
TRUSTED_HOSTS = [
    host.strip() for host in os.environ.get("TRUSTED_HOSTS", "").split(",") if host.strip()
]


def validate_production_settings(app_env, secret, debug, trusted_hosts):
    if app_env != "production":
        return
    if not secret or len(secret.encode("utf-8")) < 32:
        raise RuntimeError("Production requires FLASK_SECRET to contain at least 32 bytes.")
    if debug == "1":
        raise RuntimeError("FLASK_DEBUG must not be enabled in production.")
    if not trusted_hosts:
        raise RuntimeError("Production requires TRUSTED_HOSTS to contain the public hostnames.")


if APP_ENV == "production":
    validate_production_settings(
        APP_ENV, FLASK_SECRET, os.environ.get("FLASK_DEBUG", "0"), TRUSTED_HOSTS
    )
elif not FLASK_SECRET:
    FLASK_SECRET = secrets.token_hex(32)
    app.logger.warning("FLASK_SECRET is unset; using an ephemeral development-only session secret.")

app.secret_key = FLASK_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_ENV == "production",
    MAX_CONTENT_LENGTH=64 * 1024,
)
if APP_ENV == "production":
    app.config["TRUSTED_HOSTS"] = TRUSTED_HOSTS
# Lightweight in-process rate limiter for this single-process academic MVP.
# Use a shared Redis-backed limiter when deploying multiple workers.
_RATE_BUCKETS = {}


def ensure_db_directory(db_path):
    if db_path is None:
        return None
    value = str(db_path).strip()
    if not value or value.lower() == ":memory:":
        return db_path
    path = Path(value).expanduser()
    if path.parent != Path(""):
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


DB = ensure_db_directory(os.environ.get("DB_PATH") or str(BASE / "scan_history.db"))
MODEL = BASE.parent / "models" / "final_random_forest.pkl"
VECTORIZER = BASE.parent / "models" / "final_tfidf_vectorizer.pkl"
DEMO_MODEL = BASE / "model.pkl"
DEMO_VECTORIZER = BASE / "vectorizer.pkl"

model = vectorizer = None
for model_path, vector_path in ((MODEL, VECTORIZER), (DEMO_MODEL, DEMO_VECTORIZER)):
    try:
        with open(model_path, "rb") as f:
            candidate_model = pickle.load(f)
        with open(vector_path, "rb") as f:
            candidate_vectorizer = pickle.load(f)
        model, vectorizer = candidate_model, candidate_vectorizer
        break
    except Exception as exc:
        app.logger.warning("Could not load model artifacts from %s: %s", model_path.parent, exc)

RECOMMENDATIONS = [
    "Do not enter passwords, OTPs or payment details on an unverified page.",
    "Verify the registered domain independently before trusting a sensitive website.",
    "For banking and payments, use the official app or type the official domain yourself.",
    "Be cautious with urgency, rewards, account warnings and unexpected verification requests.",
]
SUSPICIOUS_TERMS = ("login", "verify", "verification", "secure", "update", "account", "password",
                    "reward", "free", "gift", "urgent", "confirm", "bank", "wallet", "signin")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}


@contextmanager
def db():
    resolved_db = ensure_db_directory(DB)
    con = sqlite3.connect(resolved_db)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            url TEXT NOT NULL,
            label TEXT NOT NULL,
            confidence REAL NOT NULL,
            threat TEXT NOT NULL,
            domain_age TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            checks_json TEXT NOT NULL DEFAULT '[]'
        )""")
        # Migrate older databases safely without deleting scan history.
        cols = {row[1] for row in con.execute("PRAGMA table_info(scans)").fetchall()}
        if "risk_score" not in cols:
            con.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
        if "checks_json" not in cols:
            con.execute("ALTER TABLE scans ADD COLUMN checks_json TEXT NOT NULL DEFAULT '[]'")
        con.execute("CREATE TABLE IF NOT EXISTS lesson_progress (id INTEGER PRIMARY KEY AUTOINCREMENT, lesson_key TEXT NOT NULL UNIQUE, completed_at TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS quiz_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, score INTEGER NOT NULL, total INTEGER NOT NULL, answers_json TEXT NOT NULL, created_at TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS phishing_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Received for local review')")
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', mfa_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1)")
        con.execute("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, action TEXT NOT NULL, resource_id TEXT, ip_hash TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS report_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, analyst_id INTEGER, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, FOREIGN KEY(report_id) REFERENCES phishing_reports(id))")
        con.execute("CREATE TABLE IF NOT EXISTS lesson_completions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, lesson_key TEXT NOT NULL, completed_at TEXT NOT NULL, UNIQUE(user_id, lesson_key))")
        con.execute("CREATE TABLE IF NOT EXISTS user_quiz_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, score INTEGER NOT NULL, total INTEGER NOT NULL, answers_json TEXT NOT NULL, created_at TEXT NOT NULL, owner_key TEXT)")
        for table in ("scans", "lesson_completions", "user_quiz_attempts", "phishing_reports"):
            existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
            if "owner_key" not in existing:
                con.execute(f"ALTER TABLE {table} ADD COLUMN owner_key TEXT")
        # Backwards-compatible optional ownership fields.
        for table, column in (("scans", "user_id"), ("lesson_progress", "user_id"), ("quiz_attempts", "user_id"), ("phishing_reports", "reporter_id")):
            existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in existing:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER")


# Ensure tables exist for both CLI startup and WSGI/test-client use.
init_db()

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def audit(action, resource_id=None, metadata=None):
    actor = session.get("user_id")
    # Store a one-way digest, not a raw IP address.
    import hashlib
    ip_hash = hashlib.sha256((request.remote_addr or "unknown").encode()).hexdigest()[:24]
    with db() as con:
        con.execute("INSERT INTO audit_logs(actor_id,action,resource_id,ip_hash,metadata_json,created_at) VALUES (?,?,?,?,?,?)",
                    (actor, action, str(resource_id) if resource_id is not None else None, ip_hash,
                     json.dumps(metadata or {}, ensure_ascii=False), utc_now()))

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as con:
        return con.execute("SELECT id,email,role,is_active FROM users WHERE id=?", (user_id,)).fetchone()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user["is_active"]:
            flash("Please sign in to access that feature.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or not user["is_active"]:
                return redirect(url_for("login", next=request.path))
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

def rate_limit(bucket, limit=10, window=60):
    now = time.time()
    key = (bucket, request.remote_addr or "unknown")
    hits = [stamp for stamp in _RATE_BUCKETS.get(key, []) if now - stamp < window]
    if len(hits) >= limit:
        return False
    hits.append(now)
    _RATE_BUCKETS[key] = hits
    return True

@app.before_request
def request_guard():
    # CSRF token is required on state-changing form posts; JSON APIs should use a token too.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = session.get("csrf_token")
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or not secrets.compare_digest(token, submitted or ""):
            abort(400, description="CSRF token missing or invalid. Refresh the page and try again.")
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if "guest_key" not in session:
        session["guest_key"] = secrets.token_urlsafe(24)

@app.context_processor
def inject_user_context():
    return {"current_user": current_user(), "csrf_token": session.get("csrf_token")}

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self' https: data:; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
    return response

@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return "Request too large.", 413

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not rate_limit("register", 5, 3600):
            abort(429)
        email = (request.form.get("email") or "").strip().lower()[:254]
        password = request.form.get("password") or ""
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 12:
            flash("Use a password with at least 12 characters.", "error")
        else:
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)",
                                      (email, generate_password_hash(password), utc_now()))
                    user_id = cur.lastrowid
                session.clear(); session["user_id"] = user_id; session["csrf_token"] = secrets.token_urlsafe(32)
                audit("user.register", user_id)
                flash("Account created. You are signed in.", "success")
                return redirect(url_for("progress"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not rate_limit("login", 10, 300):
            abort(429)
        email = (request.form.get("email") or "").strip().lower()[:254]
        password = request.form.get("password") or ""
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not user["is_active"] or not check_password_hash(user["password_hash"], password):
            audit("auth.login_failed", metadata={"email_supplied": bool(email)})
            flash("Email or password is incorrect.", "error")
        else:
            session.clear(); session["user_id"] = user["id"]; session["csrf_token"] = secrets.token_urlsafe(32)
            audit("auth.login", user["id"])
            destination = request.args.get("next", "")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("progress")
            return redirect(destination)
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout():
    audit("auth.logout")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("home"))

@app.route("/admin")
@role_required("admin", "analyst")
def admin_dashboard():
    with db() as con:
        reports = con.execute("SELECT r.*, u.email AS reporter_email FROM phishing_reports r LEFT JOIN users u ON u.id=r.reporter_id ORDER BY r.id DESC LIMIT 200").fetchall()
        users_count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        scans_count = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        audit_rows = con.execute("SELECT a.*,u.email FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 30").fetchall()
    return render_template("admin.html", reports=reports, users_count=users_count, scans_count=scans_count, audit_rows=audit_rows)

@app.route("/admin/reports/<int:report_id>/status", methods=["POST"])
@role_required("admin", "analyst")
def update_report_status(report_id):
    allowed = {"new", "triage", "confirmed", "false_positive"}
    status = (request.form.get("status") or "").strip()
    note = (request.form.get("note") or "").strip()[:500]
    if status not in allowed:
        abort(400)
    with db() as con:
        report = con.execute("SELECT id FROM phishing_reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            abort(404)
        con.execute("UPDATE phishing_reports SET status=? WHERE id=?", (status, report_id))
        con.execute("INSERT INTO report_reviews(report_id,analyst_id,status,note,created_at) VALUES (?,?,?,?,?)",
                    (report_id, session.get("user_id"), status, note, utc_now()))
    audit("report.status_changed", report_id, {"status": status})
    flash("Report status updated.", "success")
    return redirect(url_for("admin_dashboard"))

def normalize_url(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Enter a website URL or domain to scan.")
    if len(value) > 2048:
        raise ValueError("URL is too long. Please enter a URL under 2,048 characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        has_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value)
        has_host_port = re.match(r"^[^:/?#]+:\d+(?:[/?#]|$)", value)
        if has_scheme and not has_host_port:
            raise ValueError("Enter a valid HTTP or HTTPS URL, such as example.com.")
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL, such as example.com.")
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL must not contain spaces.")
    try:
        _ = parsed.port  # Accessing this validates malformed ports.
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")
    return value


def is_ip(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(url):
    p = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    lower = unquote(url).lower()
    terms = [word for word in SUSPICIOUS_TERMS if word in lower]
    try:
        port = p.port
    except ValueError:
        port = None
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
    return {
        "URL Length": len(url), "HTTPS": "Yes" if p.scheme.lower() == "https" else "No",
        "Dot Count": url.count("."), "Hyphen Count": url.count("-"),
        "Subdomains": max(0, len(host.split(".")) - 2) if host else 0,
        "@ Symbol": "Yes" if "@" in url else "No", "IP Address": "Yes" if is_ip(host) else "No",
        "Suspicious Words": ", ".join(terms) if terms else "None", "Query Length": len(p.query),
        "Path Length": len(p.path), "Hostname": host or "Unavailable",
        "Punycode": "Yes" if "xn--" in ascii_host else "No",
        "Non-standard Port": "Yes" if port and port not in (80, 443) else "No",
        "URL Shortener": "Yes" if host in SHORTENERS else "No",
        "Encoded Characters": "Yes" if re.search(r"%[0-9a-fA-F]{2}", url) else "No",
    }


def build_checks(url, features, domain_check=None):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    checks = []
    def add(title, state, detail):
        checks.append({"title": title, "state": state, "detail": detail})
    add("HTTPS transport", "info" if p.scheme == "https" else "caution",
        "HTTPS is present, but encryption does not prove the site is legitimate." if p.scheme == "https" else
        "This URL uses HTTP without transport encryption. Legitimate sites can use HTTP, but sensitive information should not be sent over it.")
    add("Hostname format", "caution" if features["IP Address"] == "Yes" else "ok",
        "The hostname is a raw IP address; verify why the link uses it." if features["IP Address"] == "Yes" else
        "A domain name is present. This does not confirm ownership or reputation.")
    add("User-info / @ symbol", "caution" if features["@ Symbol"] == "Yes" else "ok",
        "An @ symbol can make the apparent destination confusing; inspect the hostname carefully." if features["@ Symbol"] == "Yes" else
        "No @ symbol was detected in the URL.")
    add("Domain depth", "caution" if features["Subdomains"] >= 3 else "ok",
        f"The hostname contains {features['Subdomains']} subdomain level(s); confirm the registered domain." if features["Subdomains"] >= 3 else
        f"The hostname has {features['Subdomains']} subdomain level(s). Subdomains are not inherently malicious.")
    add("Urgency / account terms", "caution" if features["Suspicious Words"] != "None" else "ok",
        "Detected terms: " + features["Suspicious Words"] + ". These words need context and are not proof of phishing." if features["Suspicious Words"] != "None" else
        "No configured urgency/account terms were detected.")
    add("URL length", "caution" if len(url) > 100 else "ok",
        f"The URL is {len(url)} characters long; long URLs can obscure the destination." if len(url) > 100 else
        f"The URL is {len(url)} characters long; length alone does not establish safety.")
    add("Internationalized hostname", "caution" if features["Punycode"] == "Yes" else "ok",
        "Punycode was detected. Inspect the normalized domain to guard against look-alike characters." if features["Punycode"] == "Yes" else
        "No punycode marker was detected in the hostname.")
    add("Port / redirect context", "caution" if features["Non-standard Port"] == "Yes" else "ok",
        "A non-standard port is present; check whether it is expected for this service." if features["Non-standard Port"] == "Yes" else
        "No non-standard port was detected. This check does not follow redirects.")
    add("URL shortener", "caution" if features["URL Shortener"] == "Yes" else "ok",
        "A known URL-shortening domain was detected; the final destination has not been expanded." if features["URL Shortener"] == "Yes" else
        "The hostname is not in the small built-in URL-shortener list.")
    domain_check = domain_check or check_domain(url)
    dns_state = "caution" if domain_check["status"] == "not_resolving" else ("info" if domain_check["status"] in {"unknown", "ip"} else "ok")
    add("DNS hostname resolution", dns_state, domain_check["message"] + (" Addresses: " + ", ".join(domain_check["addresses"]) if domain_check["addresses"] else ""))
    return checks


def risk_assessment(url, features):
    """Return a transparent rule-based indicator score, not a calibrated probability."""
    points, reasons = 0, []
    def flag(condition, pts, title, detail):
        nonlocal points
        if condition:
            points += pts
            reasons.append({"title": title, "detail": detail, "points": pts})
    flag(features["HTTPS"] == "No", 12, "No HTTPS", "The URL uses unencrypted HTTP.")
    flag(features["IP Address"] == "Yes", 22, "Raw IP hostname", "A raw IP address is used instead of a typical domain name.")
    flag(features["@ Symbol"] == "Yes", 18, "At-sign in URL", "The URL contains a character that can confuse destination reading.")
    flag(features["Suspicious Words"] != "None", min(18, 5 * len(features["Suspicious Words"].split(", "))), "Suspicious wording", "Terms found: " + features["Suspicious Words"] + ".")
    flag(features["Subdomains"] >= 3, 10, "Many subdomain levels", f"Found {features['Subdomains']} subdomain levels.")
    flag(len(url) > 100, 8, "Long URL", f"URL length is {len(url)} characters.")
    flag(features["Punycode"] == "Yes", 12, "Punycode hostname", "Internationalized hostname needs visual verification.")
    flag(features["Non-standard Port"] == "Yes", 8, "Non-standard port", "The URL uses a port other than 80 or 443.")
    flag(features["URL Shortener"] == "Yes", 10, "URL shortener", "The final destination is hidden by a known shortener.")
    score = min(points, 100)
    level = "High" if score >= 60 else "Moderate" if score >= 30 else "Low"
    return score, level, reasons


def check_domain(url):
    """Resolve the hostname only; never fetch the user-submitted webpage."""
    host = urlparse(url).hostname
    if not host:
        return {"status": "invalid", "message": "Hostname unavailable.", "addresses": []}
    if is_ip(host):
        return {"status": "ip", "message": "The URL uses a raw IP address rather than a domain name.", "addresses": [host]}
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in results if item[4]})
        if addresses:
            return {"status": "resolves", "message": "The hostname resolves in DNS.", "addresses": addresses}
        return {"status": "not_resolving", "message": "The hostname returned no DNS addresses.", "addresses": []}
    except socket.gaierror as exc:
        if getattr(exc, "errno", None) in {getattr(socket, "EAI_NONAME", -999), getattr(socket, "EAI_NODATA", -998)}:
            return {"status": "not_resolving", "message": "The hostname could not be resolved by DNS.", "addresses": []}
        return {"status": "unknown", "message": "DNS verification could not be completed on this network.", "addresses": []}
    except Exception:
        return {"status": "unknown", "message": "DNS verification could not be completed on this network.", "addresses": []}


def domain_age(url):
    # WHOIS is optional; the scanner does not request the target web page.
    try:
        import whois
        host = urlparse(url).hostname
        if not host or is_ip(host):
            return "Not available for this hostname"
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
        return "Unavailable (lookup failed or blocked)"


def predict(url):
    features = extract_features(url)
    domain_check = check_domain(url)
    features["DNS Status"] = domain_check["status"].replace("_", " ").title()
    features["DNS Details"] = domain_check["message"]
    score, risk_level, reasons = risk_assessment(url, features)
    checks = build_checks(url, features, domain_check)
    ml_label, ml_confidence = "Model unavailable", None
    if model is not None and vectorizer is not None:
        try:
            x = vectorizer.transform([url])
            pred = int(model.predict(x)[0])
            ml_label = "Potential Phishing" if pred == 1 else "Potentially Legitimate"
            probs = model.predict_proba(x)[0] if hasattr(model, "predict_proba") else None
            ml_confidence = float(max(probs)) if probs is not None else None
        except Exception as exc:
            app.logger.warning("Model inference failed: %s", exc)
    # Display an indicator-based assessment; don't let the weak demo model dominate it.
    if domain_check["status"] == "not_resolving":
        label, threat = "Unverified / Domain Not Resolving", "Unverified"
        message = "The hostname could not be resolved by DNS from this environment. This may mean the domain is invalid or the network lookup failed; it is not a definitive phishing verdict."
    elif domain_check["status"] == "unknown":
        label, threat = "Unable to Verify Domain", "Unknown"
        message = "DNS verification could not be completed. The URL checks remain indicative and do not establish that the site is safe."
    elif risk_level == "High":
        label, threat = "High-risk indicators found", "Higher"
        message = "Several URL-level warning signs were detected. Treat this link as suspicious and verify it independently."
    elif risk_level == "Moderate":
        label, threat = "Caution advised", "Moderate"
        message = "Some URL-level warning signs were detected. Check the domain and context before proceeding."
    else:
        label, threat = "No strong URL indicators found", "Lower"
        message = "The configured URL checks found few warning signs. This does not establish that the site is safe."
    return {
        "url": url, "label": label, "confidence": ml_confidence, "threat": threat,
        "message": message, "features": features, "domain_age": domain_age(url),
        "recommendations": RECOMMENDATIONS, "risk_score": score, "risk_level": risk_level,
        "reasons": reasons, "checks": checks, "model_label": ml_label,
        "domain_status": domain_check["status"], "domain_message": domain_check["message"],
        "domain_addresses": domain_check["addresses"],
        "model_status": "Available (experimental demo model)" if ml_confidence is not None else "Unavailable",
    }


@app.route("/")
def home():
    user = current_user()
    where = ""; params = []
    if not user or user["role"] not in {"admin", "analyst"}:
        if session.get("user_id"):
            where = " WHERE user_id=?"; params = [session.get("user_id")]
        else:
            where = " WHERE owner_key=?"; params = [session.get("guest_key")]
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans" + where, params).fetchone()[0]
        high = con.execute("SELECT COUNT(*) FROM scans" + where + (" AND" if where else " WHERE") + " risk_score >= 60", params).fetchone()[0]
        recent = con.execute("SELECT * FROM scans" + where + " ORDER BY id DESC LIMIT 5", params).fetchall()
    ml_available = model is not None and vectorizer is not None
    return render_template("index.html", total_scans=total, flagged_scans=high,
                           recent_scans=recent, ml_available=ml_available)

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        url = normalize_url(request.form.get("url"))
        result = predict(url)
        with db() as con:
            con.execute("""INSERT INTO scans(created_at,url,label,confidence,threat,domain_age,risk_score,checks_json,user_id,owner_key)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), result["url"], result["label"],
                 float(result["confidence"] or 0.0), result["threat"], result["domain_age"], result["risk_score"],
                 json.dumps(result["checks"]), session.get("user_id"), session.get("guest_key")))
        audit("scan.created", metadata={"risk_score": result["risk_score"]})
        return render_template("scan_result.html", result=result)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("scanner"))

@app.route("/history")
def history():
    query = (request.args.get("q") or "").strip()[:200]
    user = current_user()
    where = ""; owner_params = []
    if not user or user["role"] not in {"admin", "analyst"}:
        if session.get("user_id"):
            where = " WHERE user_id=?"; owner_params = [session.get("user_id")]
        else:
            where = " WHERE owner_key=?"; owner_params = [session.get("guest_key")]
    with db() as con:
        if query:
            connector = " AND " if where else " WHERE "
            rows = con.execute("SELECT * FROM scans" + where + connector + "(url LIKE ? OR label LIKE ?) ORDER BY id DESC LIMIT 200",
                               tuple(owner_params + [f"%{query}%", f"%{query}%"])).fetchall()
        else:
            rows = con.execute("SELECT * FROM scans" + where + " ORDER BY id DESC LIMIT 200", tuple(owner_params)).fetchall()
        total = con.execute("SELECT COUNT(*) FROM scans" + where, tuple(owner_params)).fetchone()[0]
    return render_template("history.html", scans=rows, total_scans=total, query=query)

@app.route("/results")
def results_info(): return render_template("results.html")
@app.route("/security")
def security(): return render_template("security.html")
@app.route("/education")
def education():
    with db() as con:
        rows = con.execute("SELECT lesson_key FROM lesson_completions WHERE user_id IS ? AND owner_key IS ?", (session.get("user_id"), session.get("guest_key"))).fetchall()
    return render_template("education.html", lessons=LESSONS, completed_keys={row["lesson_key"] for row in rows})
@app.route("/faq")
def faq(): return render_template("faq.html")
@app.route("/about")
def about(): return render_template("about.html")


LESSONS = [
 {"key":"lookalike","title":"Look-alike domains","body":"Check the actual registered domain, not just familiar words near the start of a URL. Misspellings and extra words can imitate a known service.","tip":"Open the official app or type the official domain yourself."},
 {"key":"urgency","title":"Unexpected urgency","body":"Messages threatening account closure, demanding instant verification, or offering surprise rewards try to rush your decision.","tip":"Pause and verify the request through a separate trusted channel."},
 {"key":"hidden-links","title":"Hidden destinations","body":"Shortened links, redirects, and long paths can make a destination harder to judge. This prototype does not expand redirects or open the destination.","tip":"Ask the sender what the link is for and verify it independently."},
 {"key":"credentials","title":"Credential harvesting","body":"A convincing sign-in page can still be fake. Unexpected requests for passwords, OTPs, recovery codes, or payment information are serious warning signs.","tip":"Never share an OTP or recovery code from an unsolicited link."},
 {"key":"scanner-limits","title":"Scanner limitations","body":"A low indicator score is not proof of safety. Legitimate URLs can trigger rules, and sophisticated phishing links may look ordinary.","tip":"Use browser protections and trusted threat-reporting channels as well."},
]
QUIZ = [
 {"q":"A message says your account will close in 10 minutes unless you sign in. What is the safest first step?","options":["Click quickly to avoid losing access","Open the official app/site independently","Reply with your password"],"answer":1,"explanation":"Urgency is a common manipulation tactic. Verify through a separate trusted route."},
 {"q":"Does HTTPS prove a website is legitimate?","options":["Yes, always","No; it indicates an encrypted connection","Only on mobile"],"answer":1,"explanation":"Phishing sites can also use HTTPS. Check the domain and context."},
 {"q":"A URL scanner reports a low risk score. What does that mean?","options":["The site is guaranteed safe","The scanner found few configured warning indicators","You can safely enter an OTP"],"answer":1,"explanation":"The score is a rule-based indicator summary, not a safety guarantee."},
 {"q":"What should you do with an unexpected OTP request?","options":["Share it if the page has a logo","Do not share it; verify the request independently","Post it in a support chat"],"answer":1,"explanation":"Never share OTPs or recovery codes in response to unexpected requests."},
 {"q":"What is a good way to verify a bank link?","options":["Use the bank's official app or type its known domain","Trust any link with the word bank","Assume a shortened link is safe"],"answer":0,"explanation":"Use a known, independent route instead of trusting the message link."},
]
@app.route("/learn/<lesson_key>/complete", methods=["POST"])
def complete_lesson(lesson_key):
    if lesson_key not in {item["key"] for item in LESSONS}:
        flash("That lesson was not found.", "error"); return redirect(url_for("education"))
    with db() as con:
        exists = con.execute("SELECT id FROM lesson_completions WHERE user_id IS ? AND owner_key IS ? AND lesson_key=?", (session.get("user_id"), session.get("guest_key"), lesson_key)).fetchone()
        if not exists:
            con.execute("INSERT INTO lesson_completions(user_id,lesson_key,completed_at,owner_key) VALUES (?,?,?,?)", (session.get("user_id"), lesson_key, utc_now(), session.get("guest_key")))
    audit("training.lesson_completed", lesson_key)
    flash("Lesson marked complete.", "success"); return redirect(url_for("education"))

@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    score=None; review=[]
    if request.method == "POST":
        answers=[]; score=0
        for i,item in enumerate(QUIZ):
            try: chosen=int(request.form.get(f"q{i}"))
            except (TypeError,ValueError): chosen=-1
            correct=chosen==item["answer"]; score+=int(correct); answers.append(chosen)
            review.append({"question":item["q"],"correct":correct,"chosen":item["options"][chosen] if 0<=chosen<len(item["options"]) else "Not answered","answer":item["options"][item["answer"]],"explanation":item["explanation"]})
        with db() as con:
            con.execute("INSERT INTO user_quiz_attempts(user_id,score,total,answers_json,created_at,owner_key) VALUES (?,?,?,?,?,?)", (session.get("user_id"), score, len(QUIZ), json.dumps(answers), utc_now(), session.get("guest_key")))
        audit("training.quiz_attempt", metadata={"score": score, "total": len(QUIZ)})
    return render_template("quiz.html",questions=QUIZ,score=score,review=review)

@app.route("/progress")
def progress():
    with db() as con:
        completed=con.execute("SELECT lesson_key,completed_at FROM lesson_completions WHERE user_id IS ? AND owner_key IS ? ORDER BY completed_at DESC", (session.get("user_id"), session.get("guest_key"))).fetchall()
        attempts=con.execute("SELECT * FROM user_quiz_attempts WHERE user_id IS ? AND owner_key IS ? ORDER BY id DESC LIMIT 20", (session.get("user_id"), session.get("guest_key"))).fetchall()
        if session.get("user_id"):
            total_scans=con.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (session.get("user_id"),)).fetchone()[0]
            total_reports=con.execute("SELECT COUNT(*) FROM phishing_reports WHERE reporter_id=?", (session.get("user_id"),)).fetchone()[0]
        else:
            total_scans=con.execute("SELECT COUNT(*) FROM scans WHERE owner_key=?", (session.get("guest_key"),)).fetchone()[0]
            total_reports=con.execute("SELECT COUNT(*) FROM phishing_reports WHERE owner_key=?", (session.get("guest_key"),)).fetchone()[0]
    return render_template("progress.html",lessons=LESSONS,completed_keys={r["lesson_key"] for r in completed},completed=completed,attempts=attempts,total_scans=total_scans,total_reports=total_reports,latest=attempts[0] if attempts else None)

@app.route("/report-phishing", methods=["GET","POST"])
def report_phishing():
    if request.method=="POST":
        raw_url=(request.form.get("url") or "").strip(); details=(request.form.get("details") or "").strip()[:1000]
        try: reported_url=normalize_url(raw_url)
        except ValueError as exc:
            flash(str(exc),"error"); return render_template("report_phishing.html",submitted=False)
        # Local-only storage: never fetch or open the submitted URL.
        with db() as con:
            cur=con.execute("INSERT INTO phishing_reports(url,details,created_at,reporter_id,status,owner_key) VALUES (?,?,?,?,?,?)",(reported_url,details,utc_now(),session.get("user_id"),"new",session.get("guest_key"))); report_id=cur.lastrowid
        audit("report.submitted", report_id)
        return render_template("report_phishing.html",submitted=True,report_id=report_id)
    return render_template("report_phishing.html",submitted=False)

@app.route("/api/v1/auth/register", methods=["POST"])
def api_auth_register():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()[:254]
    password = payload.get("password") or ""
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 12:
        return jsonify({"error":"invalid_input", "message":"Provide a valid email and a password of at least 12 characters."}), 400
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)", (email, generate_password_hash(password), utc_now()))
        session.clear(); session["user_id"] = cur.lastrowid; session["csrf_token"] = secrets.token_urlsafe(32)
        audit("user.register", cur.lastrowid)
        return jsonify({"id":cur.lastrowid,"email":email,"role":"user"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error":"email_exists"}), 409

@app.route("/api/v1/auth/login", methods=["POST"])
def api_auth_login():
    if not rate_limit("api_login", 10, 300): return jsonify({"error":"rate_limit_exceeded"}), 429
    payload = request.get_json(silent=True) or {}; email = (payload.get("email") or "").strip().lower(); password = payload.get("password") or ""
    with db() as con: user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not user["is_active"] or not check_password_hash(user["password_hash"], password):
        audit("auth.api_login_failed")
        return jsonify({"error":"invalid_credentials"}), 401
    session.clear(); session["user_id"] = user["id"]; session["csrf_token"] = secrets.token_urlsafe(32)
    audit("auth.api_login", user["id"])
    return jsonify({"id":user["id"],"email":user["email"],"role":user["role"],"csrf_token":session["csrf_token"]})

@app.route("/api/v1/auth/refresh", methods=["POST"])
def api_auth_refresh():
    user = current_user()
    if not user: return jsonify({"error":"unauthenticated"}), 401
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"authenticated":True,"csrf_token":session["csrf_token"]})

@app.route("/api/v1/auth/logout", methods=["POST"])
def api_auth_logout():
    if not current_user(): return jsonify({"authenticated":False}), 200
    audit("auth.api_logout"); session.clear()
    return jsonify({"authenticated":False})

EMAIL_SCENARIOS = [
    {"id":"delivery","subject":"Delivery address problem","sender":"parcel-update@example.invalid","body":"Your parcel is on hold. Confirm your address immediately using the button below.","answer":"phishing","signals":["Unexpected urgency", "Generic sender domain", "Requests action through an unverified link"],"explanation":"Unexpected delivery notices that demand immediate action should be verified using the courier's official app or website."},
    {"id":"routine","subject":"Your monthly statement is ready","sender":"statements@bank.example.invalid","body":"Your monthly statement is available in the bank's official mobile app. You do not need to reply to this message.","answer":"safer","signals":["No request for a password or OTP", "Directs user to the official app"],"explanation":"This example has fewer common warning signs, but sender details can be spoofed. Verify important messages independently."},
    {"id":"account","subject":"Account access expires today","sender":"security-check@example.invalid","body":"Your account will be disabled in 15 minutes. Send your password and OTP to keep access.","answer":"phishing","signals":["Threatening urgency", "Requests password and OTP", "Untrusted sender"],"explanation":"Never share passwords or OTPs in response to a message. Visit the service independently to check account status."},
]

@app.route("/email-simulation", methods=["GET", "POST"])
def email_simulation():
    scenario = None; feedback = None
    if request.method == "POST":
        sid = request.form.get("scenario_id", "")
        answer = request.form.get("answer", "")
        scenario = next((x for x in EMAIL_SCENARIOS if x["id"] == sid), None)
        if scenario:
            feedback = {"correct": answer == scenario["answer"], "chosen": answer, "scenario": scenario}
    scenario = scenario or EMAIL_SCENARIOS[0]
    return render_template("email_simulation.html", scenario=scenario, feedback=feedback, scenarios=EMAIL_SCENARIOS)

@app.route("/api/v1/csrf", methods=["GET"])
def api_csrf_token():
    return jsonify({"csrf_token": session.get("csrf_token")})

@app.route("/api/v1/training/modules", methods=["GET"])
def api_training_modules():
    return jsonify({"items":[{"id":x["key"],"title":x["title"],"body":x["body"],"tip":x["tip"]} for x in LESSONS]})

@app.route("/api/v1/scans", methods=["GET", "POST"])
def api_create_scan():
    if request.method == "GET":
        status = (request.args.get("status") or "").strip()
        verdict = (request.args.get("verdict") or "").strip()
        query = "SELECT * FROM scans WHERE 1=1"; params = []
        user = current_user()
        if user and user["is_active"] and user["role"] in {"admin", "analyst"}:
            pass
        elif user and user["is_active"]:
            query += " AND user_id=?"; params.append(user["id"])
        elif not user:
            query += " AND user_id IS NULL AND owner_key=?"; params.append(session.get("guest_key"))
        else:
            query += " AND 1=0"
        if status:
            query += " AND lower(label) LIKE ?"; params.append("%" + status.lower() + "%")
        if verdict:
            query += " AND lower(label) LIKE ?"; params.append("%" + verdict.lower() + "%")
        query += " ORDER BY id DESC LIMIT 200"
        with db() as con: rows = con.execute(query, params).fetchall()
        return jsonify({"items":[{"id":r["id"],"url":r["url"],"label":r["label"],"risk_score":r["risk_score"],"threat":r["threat"],"created_at":r["created_at"]} for r in rows]})
    if not rate_limit("api_scan", 20, 60):
        return jsonify({"error":"rate_limit_exceeded"}), 429
    payload = request.get_json(silent=True) or {}
    try:
        url = normalize_url(payload.get("url"))
    except ValueError as exc:
        return jsonify({"error":"invalid_url", "message":str(exc)}), 400
    result = predict(url)
    with db() as con:
        cur = con.execute("INSERT INTO scans(created_at,url,label,confidence,threat,domain_age,risk_score,checks_json,user_id,owner_key) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (utc_now(), result["url"], result["label"], float(result["confidence"] or 0.0), result["threat"], result["domain_age"], result["risk_score"], json.dumps(result["checks"]), session.get("user_id"), session.get("guest_key")))
        scan_id = cur.lastrowid
    audit("scan.created", scan_id)
    return jsonify({"id":scan_id,"status":"completed","url":result["url"],"label":result["label"],"risk_score":result["risk_score"],"risk_level":result["risk_level"],"reasons":result["reasons"],"checks":result["checks"],"model_label":result["model_label"],"model_confidence_uncalibrated":result["confidence"],"message":result["message"]}), 201

@app.route("/api/v1/scans/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    with db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error":"not_found"}), 404
    user = current_user()
    if user and user["is_active"] and user["role"] in {"admin", "analyst"}:
        pass
    elif row["user_id"] is not None:
        if not user or not user["is_active"] or row["user_id"] != user["id"]:
            return jsonify({"error":"forbidden"}), 403
    elif not row["owner_key"] or row["owner_key"] != session.get("guest_key"):
        return jsonify({"error":"forbidden"}), 403
    return jsonify({"id":row["id"],"url":row["url"],"label":row["label"],"risk_score":row["risk_score"],"threat":row["threat"],"created_at":row["created_at"],"checks":json.loads(row["checks_json"] or "[]")})

@app.route("/healthz", methods=["GET"])
def healthz():
    try:
        with db() as con:
            con.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        app.logger.exception("Database health check failed")
        return jsonify({"status": "unhealthy"}), 503
    return jsonify({"status": "ok"}), 200

@app.route("/api/v1/reports", methods=["POST", "GET"])
def api_reports():
    if request.method == "POST":
        if not rate_limit("api_report", 10, 3600): return jsonify({"error":"rate_limit_exceeded"}), 429
        payload = request.get_json(silent=True) or {}
        try: url = normalize_url(payload.get("url"))
        except ValueError as exc: return jsonify({"error":"invalid_url", "message":str(exc)}), 400
        details = str(payload.get("details") or "").strip()[:1000]
        with db() as con:
            cur = con.execute("INSERT INTO phishing_reports(url,details,created_at,reporter_id,status,owner_key) VALUES (?,?,?,?,?,?)", (url,details,utc_now(),session.get("user_id"),"new",session.get("guest_key")))
            report_id = cur.lastrowid
        audit("report.submitted", report_id)
        return jsonify({"id":report_id,"status":"new","message":"Saved locally; not forwarded externally."}), 201
    user = current_user()
    if not user or user["role"] not in {"admin", "analyst"}: return jsonify({"error":"forbidden"}), 403
    with db() as con: rows = con.execute("SELECT id,url,details,status,created_at FROM phishing_reports ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify({"items":[dict(r) for r in rows]})

@app.route("/api/v1/reports/<int:report_id>/status", methods=["PATCH"])
@role_required("admin", "analyst")
def api_report_status(report_id):
    payload = request.get_json(silent=True) or {}; status = payload.get("status"); note = str(payload.get("note") or "")[:500]
    if status not in {"new", "triage", "confirmed", "false_positive"}: return jsonify({"error":"invalid_status"}), 400
    with db() as con:
        row = con.execute("SELECT id FROM phishing_reports WHERE id=?", (report_id,)).fetchone()
        if not row: return jsonify({"error":"not_found"}), 404
        con.execute("UPDATE phishing_reports SET status=? WHERE id=?", (status, report_id))
        con.execute("INSERT INTO report_reviews(report_id,analyst_id,status,note,created_at) VALUES (?,?,?,?,?)", (report_id, session.get("user_id"), status, note, utc_now()))
    audit("report.status_changed", report_id, {"status":status})
    return jsonify({"id":report_id,"status":status})

def bootstrap_admin_from_env():
    email = os.environ.get("PHISHGUARD_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("PHISHGUARD_ADMIN_PASSWORD", "")
    if not email or len(password) < 12:
        return
    with db() as con:
        existing = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            con.execute("UPDATE users SET role='admin' WHERE id=?", (existing["id"],))
        else:
            con.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES (?,?,?,?)", (email, generate_password_hash(password), "admin", utc_now()))

if __name__ == "__main__":
    init_db()
    bootstrap_admin_from_env()
    if APP_ENV == "production":
        raise RuntimeError("Do not use Flask's development server in production; start with Waitress.")
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
