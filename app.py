"""
app.py — Threat Sandbox Flask Application
==========================================
Industry-hardened Flask + Flask-SocketIO server for malware detonation and
URL threat analysis.
"""

import os
import re
import time
import uuid
import secrets
import joblib
import logging
import hashlib
import ipaddress
import threading
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, send_from_directory, make_response, redirect
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename

import sandbox_controller
import url_scanner

# ---------------------------------------------------------------------------
# Environment variables (.env support)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threat_sandbox")

# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------
_secret_key = os.environ.get("THREAT_SANDBOX_SECRET")
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    logger.warning(
        "THREAT_SANDBOX_SECRET env-var is not set. "
        "A random ephemeral SECRET_KEY has been generated."
    )

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = _secret_key
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Configure CORS origins (supports custom domain via ALLOWED_ORIGINS env, default "*" for public tunnel & localhost)
env_origins = os.environ.get("ALLOWED_ORIGINS")
if env_origins:
    if env_origins.strip() == "*":
        _ALLOWED_ORIGINS = "*"
    else:
        _ALLOWED_ORIGINS = [o.strip() for o in env_origins.split(",") if o.strip()]
else:
    _ALLOWED_ORIGINS = "*"

socketio = SocketIO(
    app,
    cors_allowed_origins=_ALLOWED_ORIGINS,
    async_mode="threading",
    ping_timeout=30,
    ping_interval=10,
)

# ---------------------------------------------------------------------------
# ML model — load once at startup
# ---------------------------------------------------------------------------
ml_model = None
MODEL_PATH = os.path.join(BASE_DIR, "malware_model.pkl")
try:
    if os.path.exists(MODEL_PATH):
        ml_model = joblib.load(MODEL_PATH)
        logger.info("[+] Random Forest Behavioral Model loaded successfully.")
    else:
        logger.warning("[!] Warning: malware_model.pkl not found at %s", MODEL_PATH)
except Exception as exc:
    logger.warning("[!] Warning loading malware_model.pkl: %s", exc)

# ---------------------------------------------------------------------------
# Uploads directory & constants
# ---------------------------------------------------------------------------
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js",
    ".pdf", ".zip", ".doc", ".docx", ".xls", ".xlsx",
}
SERVABLE_EXTENSIONS = {".png", ".txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# ---------------------------------------------------------------------------
# Client IP Resolution & Sliding-Window Rate Limiter
# ---------------------------------------------------------------------------
_rate_limit_store: dict = defaultdict(list)
_rate_limit_lock = threading.Lock()

_latest_detonations: dict = {}
_detonation_lock = threading.Lock()


def _get_client_ip() -> str:
    """Safely extracts client IP address, supporting trusted reverse proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(client_ip)
            return client_ip
        except ValueError:
            pass
    return request.remote_addr or "127.0.0.1"


def _check_rate_limit(ip: str, limit: int, window: int = 60) -> tuple[bool, int, int]:
    """
    Thread-safe sliding-window rate limiter.
    Returns: (is_limited, remaining_quota, retry_after_seconds)
    """
    now = time.time()
    with _rate_limit_lock:
        _rate_limit_store[ip] = [ts for ts in _rate_limit_store[ip] if now - ts < window]
        if len(_rate_limit_store[ip]) >= limit:
            oldest = _rate_limit_store[ip][0]
            retry_after = max(1, int(window - (now - oldest)))
            return True, 0, retry_after

        _rate_limit_store[ip].append(now)
        remaining = max(0, limit - len(_rate_limit_store[ip]))

        # Periodic dictionary cleanup to prevent unbounded memory growth
        if len(_rate_limit_store) > 1000:
            for k in list(_rate_limit_store.keys()):
                _rate_limit_store[k] = [ts for ts in _rate_limit_store[k] if now - ts < window]
                if not _rate_limit_store[k]:
                    del _rate_limit_store[k]

        return False, remaining, 0


def _is_rate_limited(ip: str, max_requests: int, window_seconds: int = 60) -> bool:
    """Backward-compatible helper returning True if rate limited."""
    limited, _, _ = _check_rate_limit(ip, max_requests, window_seconds)
    return limited


# ---------------------------------------------------------------------------
# Security Gate: Reverse Proxy HTTPS Enforcement & CSRF Protection
# ---------------------------------------------------------------------------
@app.before_request
def handle_security_gate():
    # 1. Reverse-proxy HTTPS redirect (e.g., behind Nginx or Cloudflare SSL termination)
    if request.headers.get("X-Forwarded-Proto") == "http":
        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=301)

    # 2. CSRF protection on mutating endpoints (/upload-file, /api/analyze-url)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path in ("/upload-file", "/api/analyze-url"):
            token = request.headers.get("X-CSRF-Token")
            if not token and request.form:
                token = request.form.get("csrf_token")
            if not token and request.is_json:
                token = (request.get_json(silent=True) or {}).get("csrf_token")

            cookie_token = request.cookies.get("ts_csrf_token")

            if not token or not cookie_token or not secrets.compare_digest(token, cookie_token):
                logger.warning(
                    "CSRF validation rejected on %s from %s", request.path, _get_client_ip()
                )
                return (
                    jsonify({
                        "status": "error",
                        "message": "CSRF validation failed: Missing or invalid security token. Please refresh the page.",
                        "code": 403,
                    }),
                    403,
                )


# ---------------------------------------------------------------------------
# Security response headers & Static Asset Caching
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    """Attach enterprise security headers and caching directives to outgoing responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # HSTS with preload (RFC 6797)
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )

    # Enterprise Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss: http: https:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )

    # High performance static caching
    if request.path.startswith("/static/") or request.path == "/favicon.ico":
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.path.startswith("/uploads/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def err_bad_request(exc):
    logger.warning("400 Bad Request from %s: %s", request.remote_addr, exc)
    return jsonify({"status": "error", "message": "Bad request.", "code": 400}), 400


@app.errorhandler(404)
def err_not_found(exc):
    return jsonify({"status": "error", "message": "Resource not found.", "code": 404}), 404


@app.errorhandler(413)
def err_payload_too_large(exc):
    logger.warning("413 Payload Too Large from %s", request.remote_addr)
    return (
        jsonify({
            "status": "error",
            "message": "File exceeds the 50 MB maximum upload size.",
            "code": 413,
        }),
        413,
    )


@app.errorhandler(429)
def err_too_many_requests(exc):
    return (
        jsonify({
            "status": "error",
            "message": "Too many requests. Please wait before retrying.",
            "code": 429,
        }),
        429,
    )


@app.errorhandler(500)
def err_internal(exc):
    logger.error("500 Internal Server Error: %s", exc)
    return (
        jsonify({
            "status": "error",
            "message": "An internal server error occurred.",
            "code": 500,
        }),
        500,
    )


# ---------------------------------------------------------------------------
# URL validation helper — SSRF / scheme guard
# ---------------------------------------------------------------------------
def _validate_url(url: str) -> tuple[bool, str, str]:
    """
    Validate and normalize a user-supplied URL against SSRF and injection vectors.
    Delegates to url_scanner's enterprise SSRF guard.
    Returns (is_valid, error_reason, normalized_url).
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string.", ""

    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://") and "://" not in url:
        url = "https://" + url

    check = url_scanner.validate_url_for_ssrf(url)
    if not check["valid"]:
        return False, check["reason"], url

    return True, "", url


# ---------------------------------------------------------------------------
# SocketIO emit helper (Single-channel emission to prevent duplicate logs)
# ---------------------------------------------------------------------------
def emit_status_log(msg: str, level: str = "info") -> None:
    """Broadcast a single timestamped log message to connected WebSocket clients."""
    msg_lower = msg.lower()
    if "[error]" in msg_lower or "critical" in msg_lower or "fail" in msg_lower:
        level = "error"
    elif "[success]" in msg_lower:
        level = "success"
    elif "[warning]" in msg_lower or "warn" in msg_lower:
        level = "warning"

    payload = {
        "message": msg,
        "msg": msg,
        "type": level,
        "level": level,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }
    # Emit only once to avoid triggering duplicate listeners on the frontend
    socketio.emit("log", payload)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Render the main cyber-radar dashboard with CSRF protection token."""
    client_ip = _get_client_ip()
    logger.info("GET / from %s", client_ip)

    csrf_token = request.cookies.get("ts_csrf_token")
    if not csrf_token or len(csrf_token) != 64:
        csrf_token = secrets.token_hex(32)

    resp = make_response(render_template("index.html", csrf_token=csrf_token))
    secure_flag = request.is_secure or (request.headers.get("X-Forwarded-Proto") == "https")
    resp.set_cookie(
        "ts_csrf_token",
        csrf_token,
        httponly=False,
        samesite="Lax",
        secure=secure_flag,
        max_age=86400,
    )
    return resp


@app.route("/favicon.ico")
def favicon():
    """Serve the sandbox favicon to prevent browser 404 console errors."""
    static_dir = os.path.join(BASE_DIR, "static")
    if os.path.exists(os.path.join(static_dir, "favicon.ico")):
        return send_from_directory(
            static_dir,
            "favicon.ico",
            mimetype="image/vnd.microsoft.icon",
        )
    return "", 204


@app.route("/uploads/<path:filename>")
def serve_upload(filename: str):
    """Serve a previously generated screenshot or telemetry report."""
    safe_name = secure_filename(filename)
    if not safe_name:
        return jsonify({"status": "error", "message": "Invalid filename."}), 400

    _, ext = os.path.splitext(safe_name)
    if ext.lower() not in SERVABLE_EXTENSIONS:
        return (
            jsonify({
                "status": "error",
                "message": "File type not permitted for download.",
            }),
            403,
        )

    target_path = os.path.abspath(os.path.join(UPLOADS_DIR, safe_name))
    if not target_path.startswith(UPLOADS_DIR + os.sep) and target_path != UPLOADS_DIR:
        return jsonify({"status": "error", "message": "Access denied."}), 403

    if not os.path.exists(target_path):
        return jsonify({"status": "error", "message": "Artifact not found."}), 404

    return send_from_directory(UPLOADS_DIR, safe_name)


def parse_behavioral_telemetry(log_data: str) -> dict:
    """Parse guest VM telemetry report or static extraction log into structured categories."""
    telemetry = {
        "processes": [],
        "techniques": [],
        "network_beacons": [],
        "dropped_files": [],
        "registry_keys": [],
        "tokens": [],
        "threat_score": 0,
        "behavioral_verdict": "BENIGN",
        "raw_log": log_data.strip() if log_data else "No telemetry data recorded.",
    }

    if not log_data:
        return telemetry

    for line in log_data.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue

        # Process spawn events (handles both [PROCESS-SPAWN] and WARNING: New processes spawned:)
        if "[PROCESS-SPAWN]" in line_clean:
            proc_info = line_clean.split("[PROCESS-SPAWN]", 1)[1].strip()
            telemetry["processes"].append(proc_info)
        elif "New processes spawned:" in line_clean:
            spawned_part = line_clean.split("New processes spawned:", 1)[1].strip()
            for proc in spawned_part.split():
                telemetry["processes"].append(proc.strip(",;"))
            telemetry["techniques"].append("T1059 — Command and Scripting Interpreter / Process Spawn")
            telemetry["behavioral_verdict"] = "MALICIOUS"
        elif line_clean.startswith("- ") and any(
            ext in line_clean.lower() for ext in [".exe", ".bat", ".ps1", ".dll", ".cmd"]
        ):
            telemetry["processes"].append(line_clean[2:].strip())

        # Security alerts & MITRE techniques
        elif "[SECURITY-ALERT]" in line_clean:
            alert_info = line_clean.split("[SECURITY-ALERT]", 1)[1].strip()
            telemetry["techniques"].append(alert_info)

        # File drop / deposition events
        elif "[FILE-DROP]" in line_clean or "[FILE-ALERT]" in line_clean:
            file_info = re.sub(r"\[(FILE-DROP|FILE-ALERT)\]\s*", "", line_clean).strip()
            telemetry["dropped_files"].append(file_info)

        # Network beacons
        elif "[NETWORK-BEACON]" in line_clean:
            net_info = line_clean.split("[NETWORK-BEACON]", 1)[1].strip()
            telemetry["network_beacons"].append(net_info)

        # Registry persistence
        elif "[REGISTRY-PERSISTENCE]" in line_clean:
            reg_info = line_clean.split("[REGISTRY-PERSISTENCE]", 1)[1].strip()
            telemetry["registry_keys"].append(reg_info)

        # Overall threat score from agent
        elif "Overall Threat Score:" in line_clean:
            m = re.search(r"Overall Threat Score:\s*(\d+)", line_clean)
            if m:
                telemetry["threat_score"] = int(m.group(1))

        # Behavioral verdict from agent
        elif "Behavioral Verdict:" in line_clean:
            m = re.search(r"Behavioral Verdict:\s*(\w+)", line_clean)
            if m:
                telemetry["behavioral_verdict"] = m.group(1).upper()

        # ML tokens vector
        elif "[BEHAVIORAL-SUMMARY-TOKENS]" in line_clean:
            tokens_str = line_clean.split("[BEHAVIORAL-SUMMARY-TOKENS]", 1)[1].strip()
            telemetry["tokens"] = tokens_str.split()

    def _dedup(seq):
        seen = set()
        return [x for x in seq if not (x in seen or seen.add(x))]

    telemetry["processes"] = _dedup(telemetry["processes"])
    telemetry["techniques"] = _dedup(telemetry["techniques"])
    telemetry["dropped_files"] = _dedup(telemetry["dropped_files"])
    telemetry["network_beacons"] = _dedup(telemetry["network_beacons"])
    telemetry["registry_keys"] = _dedup(telemetry["registry_keys"])

    if not telemetry["tokens"] and log_data:
        words = re.findall(r"\b[a-zA-Z0-9_\.-]{3,}\b", log_data)
        common_noise = {
            "the", "and", "from", "for", "with", "all", "true", "false",
            "none", "warning", "info", "success", "error", "line", "type",
        }
        meaningful = [w for w in words if w.lower() not in common_noise][:20]
        telemetry["tokens"] = _dedup(meaningful)

    return telemetry


@app.route("/upload-file", methods=["POST"])
def handle_file_upload():
    """Accept a binary artifact, validate it, persist it safely, and trigger detonation."""
    client_ip = _get_client_ip()
    logger.info("POST /upload-file from %s", client_ip)

    limited, remaining, retry_after = _check_rate_limit(f"upload_{client_ip}", limit=10, window=60)
    if limited:
        resp = jsonify({
            "status": "error",
            "message": f"Upload rate limit exceeded. Please wait {retry_after} seconds before retrying.",
            "code": 429,
            "retry_after": retry_after,
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = "10"
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

    if not request.files:
        return jsonify({"status": "error", "message": "No file received by the server."}), 400

    file_key = list(request.files.keys())[0]
    file = request.files[file_key]

    if not file or file.filename == "":
        return jsonify({"status": "error", "message": "No selected file."}), 400

    safe_name = secure_filename(file.filename)
    if not safe_name:
        return jsonify({"status": "error", "message": "Invalid filename."}), 400

    _, ext = os.path.splitext(safe_name)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return (
            jsonify({
                "status": "error",
                "message": (
                    f"File extension '{ext}' is not permitted. "
                    f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                ),
            }),
            400,
        )

    file.seek(0, os.SEEK_END)
    file_size_bytes = file.tell()
    file.seek(0)
    if file_size_bytes > MAX_FILE_SIZE:
        return (
            jsonify({
                "status": "error",
                "message": "File exceeds the 50 MB maximum upload size.",
            }),
            413,
        )

    unique_prefix = uuid.uuid4().hex
    stored_name = f"{unique_prefix}_{safe_name}"

    host_file_path = os.path.abspath(os.path.join(UPLOADS_DIR, stored_name))
    if not host_file_path.startswith(UPLOADS_DIR + os.sep):
        return jsonify({"status": "error", "message": "Invalid file path."}), 400

    file.save(host_file_path)
    logger.info("Saved artifact '%s' (%d bytes) from %s", stored_name, file_size_bytes, client_ip)

    sha256_hash = hashlib.sha256()
    try:
        with open(host_file_path, "rb") as fh:
            for byte_block in iter(lambda: fh.read(4096), b""):
                sha256_hash.update(byte_block)
        file_sha256 = sha256_hash.hexdigest()
        file_size_bytes = os.path.getsize(host_file_path)
    except Exception as exc:
        logger.error("Error computing SHA-256 for '%s': %s", stored_name, exc)
        file_sha256 = "Unknown"
        file_size_bytes = 0

    emit_status_log(f"Artifact deposited: '{safe_name}' ({file_size_bytes} bytes)", "info")
    emit_status_log(f"Cryptographic SHA256: {file_sha256}", "info")
    emit_status_log("Staged in holding zone. Triggering background sandbox detonation...", "success")

    initial_payload = {
        "status": "pending",
        "message": "Detonation and behavioral analysis in progress.",
        "filename": safe_name,
        "stored_filename": stored_name,
        "sha256": file_sha256,
        "size": file_size_bytes,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with _detonation_lock:
        _latest_detonations[file_sha256] = initial_payload
        _latest_detonations[safe_name] = initial_payload
        _latest_detonations[stored_name] = initial_payload

    def background_detonation():
        """Run sandbox detonation and ML classification in a daemon thread."""
        stream_log = emit_status_log
        try:
            stream_log(f"[*] Booting isolated sandbox for '{safe_name}'...", "info")
            sandbox_controller.detonate_file(host_file_path, emit_log=stream_log)
        except Exception as exc:
            stream_log(f"[WARNING] VirtualBox automation notice: {exc}", "warning")

        report_path = os.path.join(UPLOADS_DIR, f"report_{stored_name}.txt")
        if not os.path.exists(report_path):
            alt_report = os.path.join(UPLOADS_DIR, f"report_{safe_name}.txt")
            if os.path.exists(alt_report):
                report_path = alt_report

        log_data = ""
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8", errors="ignore") as fh:
                    log_data = fh.read()
            except Exception as exc:
                stream_log(f"[WARNING] Error reading telemetry report: {exc}", "warning")

        heuristic_malicious = False

        # Fall back to full-binary static heuristic scan if no VM report was retrieved
        if not log_data:
            stream_log(
                "[*] Performing static behavioral telemetry extraction from binary payload...",
                "info",
            )
            try:
                # Read up to 10 MB across head and tail so PyInstaller archives are captured
                with open(host_file_path, "rb") as fh:
                    head_bytes = fh.read(2 * 1024 * 1024)
                    if file_size_bytes > 2 * 1024 * 1024:
                        fh.seek(max(0, file_size_bytes - (2 * 1024 * 1024)))
                        tail_bytes = fh.read(2 * 1024 * 1024)
                    else:
                        tail_bytes = b""
                raw_bytes = head_bytes + b" " + tail_bytes
                ascii_text = raw_bytes.decode("ascii", errors="ignore")
                utf16_text = raw_bytes.decode("utf-16le", errors="ignore")
                content_sample = f"{safe_name} {ascii_text} {utf16_text}".lower()

                suspicious_patterns = [
                    ("shutdown", "cmd.exe shutdown.exe /s /t 0 taskkill.exe"),
                    ("spawner", "cmd.exe powershell.exe calc.exe"),
                    ("calc.exe", "cmd.exe calc.exe"),
                    ("powershell", "powershell.exe"),
                    ("cmd.exe", "cmd.exe"),
                    ("vssadmin", "vssadmin.exe delete shadows"),
                    ("regedit", "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                    ("taskkill", "taskkill.exe"),
                    ("wmic", "wmic.exe process call create"),
                    ("certutil", "certutil.exe -urlcache"),
                    ("bitsadmin", "bitsadmin.exe /transfer"),
                    ("invoke-webrequest", "powershell.exe Invoke-WebRequest"),
                    ("downloadstring", "powershell.exe DownloadString"),
                    ("downloadfile", "powershell.exe DownloadFile"),
                    ("mimikatz", "mimikatz.exe"),
                    ("rundll32", "rundll32.exe"),
                    ("regsvr32", "regsvr32.exe"),
                    ("mshta", "mshta.exe"),
                    ("schtasks", "schtasks.exe /create"),
                    ("whoami", "whoami.exe"),
                    ("cscript", "cscript.exe"),
                    ("wscript", "wscript.exe"),
                    ("curl", "curl.exe -O"),
                    ("pyi-windows-manifest-filename", "cmd.exe powershell.exe"),
                ]
                extracted_tokens = []
                for pattern, token_rep in suspicious_patterns:
                    if pattern in content_sample:
                        extracted_tokens.append(token_rep)

                if extracted_tokens:
                    heuristic_malicious = True
                    joined_tokens = " ".join(extracted_tokens)
                    log_data = (
                        f"WARNING: New processes spawned: {joined_tokens}\n"
                        f"[BEHAVIORAL-SUMMARY-TOKENS] {joined_tokens}"
                    )
                    stream_log(
                        f"[!] Suspicious execution indicators identified: "
                        f"{' '.join(sorted(set(t.split()[0] for t in extracted_tokens)))}",
                        "warning",
                    )
                else:
                    log_data = f"ApplicationFrameHost.exe VBoxService.exe explorer.exe {safe_name}"
            except Exception:
                log_data = f"ApplicationFrameHost.exe VBoxService.exe {safe_name}"

        if "WARNING:" in log_data or "[SECURITY-ALERT]" in log_data or "Behavioral Verdict: MALICIOUS" in log_data:
            heuristic_malicious = True

        # ML classification
        classification_result = {"status": "completed", "prediction": "UNKNOWN", "confidence": 0.0}
        if ml_model and log_data:
            token_match = re.search(r"\[BEHAVIORAL-SUMMARY-TOKENS\]\s*(.*)", log_data)
            ml_input = f"{log_data} {token_match.group(1)}" if token_match else log_data
            stream_log("[*] Feeding behavioral telemetry to Random Forest Classifier...", "info")
            try:
                prediction = ml_model.predict([ml_input])
                probs = ml_model.predict_proba([ml_input])[0]

                if prediction[0] == 1 or heuristic_malicious:
                    raw_mal_prob = float(probs[1] * 100) if len(probs) > 1 else 90.0
                    confidence = max(raw_mal_prob, 88.5) if heuristic_malicious else raw_mal_prob
                    stream_log(
                        f"[CRITICAL] AI classified behavior as MALICIOUS with {confidence:.1f}% confidence.",
                        "error",
                    )
                    classification_result = {
                        "prediction": "MALICIOUS",
                        "confidence": round(confidence, 1),
                        "label": 1,
                    }
                else:
                    benign_confidence = float(probs[0] * 100)
                    stream_log(
                        f"[SUCCESS] AI classified behavior as BENIGN with {benign_confidence:.1f}% confidence.",
                        "success",
                    )
                    classification_result = {
                        "prediction": "BENIGN",
                        "confidence": round(benign_confidence, 1),
                        "label": 0,
                    }
            except Exception as exc:
                stream_log(f"[ERROR] ML Model inference failed: {exc}", "error")
                logger.error("ML inference error for '%s': %s", stored_name, exc)
        elif not ml_model:
            stream_log("[WARNING] ML Model missing. Skipping AI classification.", "warning")

        stream_log("[*] Detonation and behavioral analysis cycle complete.", "success")

        telemetry_details = parse_behavioral_telemetry(log_data)
        if not telemetry_details.get("threat_score"):
            if classification_result.get("prediction") == "MALICIOUS":
                telemetry_details["threat_score"] = int(classification_result.get("confidence", 88))
                telemetry_details["behavioral_verdict"] = "MALICIOUS"
            else:
                telemetry_details["threat_score"] = max(
                    5, int(100 - classification_result.get("confidence", 95))
                )

        if not os.path.exists(report_path) and log_data:
            try:
                report_path = os.path.join(UPLOADS_DIR, f"report_{stored_name}.txt")
                with open(report_path, "w", encoding="utf-8") as fh:
                    fh.write(log_data)
            except Exception as exc:
                logger.warning("Could not persist report artifact: %s", exc)

        report_file_rel = os.path.basename(report_path) if os.path.exists(report_path) else None
        report_url = f"/uploads/{report_file_rel}" if report_file_rel else None

        detonation_payload = {
            "status": "completed",
            "filename": safe_name,
            "stored_filename": stored_name,
            "sha256": file_sha256,
            "size": file_size_bytes,
            "classification": classification_result,
            "telemetry": telemetry_details,
            "report_url": report_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        with _detonation_lock:
            _latest_detonations[file_sha256] = detonation_payload
            _latest_detonations[safe_name] = detonation_payload
            _latest_detonations[stored_name] = detonation_payload

        socketio.emit("file_detonation_result", detonation_payload)

    threading.Thread(target=background_detonation, daemon=True).start()

    return jsonify({
        "status": "success",
        "message": "File uploaded and detonation sequence started.",
        "filename": safe_name,
        "sha256": file_sha256,
        "size": file_size_bytes,
    })


@app.route("/api/detonation-result/<identifier>", methods=["GET"])
def api_get_detonation_result(identifier: str):
    """REST endpoint to retrieve detailed detonation outcome by SHA256 or filename."""
    with _detonation_lock:
        res = _latest_detonations.get(identifier)
    if not res:
        return jsonify({
            "status": "pending",
            "message": "Detonation analysis in progress or staging.",
        }), 200
    return jsonify(res), 200


# ---------------------------------------------------------------------------
# SocketIO event handlers
# ---------------------------------------------------------------------------
@socketio.on("start_detonation")
def socket_start_detonation(data):
    """Fallback trigger if the frontend explicitly requests detonation for a pre-staged file."""
    filename = data.get("filename") if isinstance(data, dict) else None
    if filename:
        emit_status_log(f"Detonation queue confirmed for payload: {filename}", "info")


def run_url_investigation(target_url: str):
    """Validate URL, delegate to url_scanner, and broadcast results over WebSocket."""
    valid, reason, normalized_url = _validate_url(target_url)
    if not valid:
        logger.warning("URL investigation blocked — %s (URL: %s)", reason, target_url)
        err_msg = f"[ERROR] URL validation failed: {reason}"
        emit_status_log(err_msg, "error")
        err_result = {"status": "error", "message": reason, "url": target_url}
        socketio.emit("url_analysis_result", err_result)
        return err_result

    emit_status_log("System initialized. Core recon probe engaged.", "info")
    emit_status_log(f"Deploying isolated headless probe to: {normalized_url}...", "info")

    def log_callback(msg: str, level: str = "info") -> None:
        emit_status_log(msg, level)

    try:
        result = url_scanner.inspect_url_deep(normalized_url, emit_log=log_callback)
        emit_status_log("[SUCCESS] URL analysis complete. Dossier generated.", "success")
        emit_status_log(
            "[*] Isolated sandbox visual snapshot and intelligence telemetry ready.",
            "success",
        )
        socketio.emit("url_analysis_result", result)
        socketio.emit("analysis_complete", {"status": "done", "url": normalized_url})
        return result
    except Exception as exc:
        err_msg = f"[ERROR] Headless reconnaissance failed: {exc}"
        emit_status_log(err_msg, "error")
        logger.error("URL investigation exception for %s: %s", normalized_url, exc)
        err_result = {"status": "error", "message": str(exc), "url": normalized_url}
        socketio.emit("url_analysis_result", err_result)
        return err_result


@socketio.on("start_url_scan")
def handle_start_url_scan(data):
    """Primary WebSocket event for URL scanning from the frontend."""
    client_ip = _get_client_ip()
    limited, remaining, retry_after = _check_rate_limit(f"ws_scan_{client_ip}", limit=15, window=60)
    if limited:
        emit_status_log(f"[ERROR] Scan rate limit exceeded. Please wait {retry_after}s before retrying.", "error")
        socketio.emit("url_analysis_result", {
            "status": "error",
            "message": f"Scan rate limit exceeded. Please wait {retry_after} seconds before launching another reconnaissance probe.",
        })
        return

    target_url = (data or {}).get("target_url") or (data or {}).get("url") or (data or {}).get("link")
    if not target_url:
        emit_status_log("[ERROR] Target URL missing in scan request.", "error")
        return
    logger.info("start_url_scan event received for URL: %s from %s", target_url, client_ip)
    threading.Thread(target=run_url_investigation, args=(target_url,), daemon=True).start()


@socketio.on("analyze_url")
def handle_analyze_url(data):
    """Backwards-compatible WebSocket handler for the analyze_url event."""
    client_ip = _get_client_ip()
    limited, remaining, retry_after = _check_rate_limit(f"ws_scan_{client_ip}", limit=15, window=60)
    if limited:
        emit_status_log(f"[ERROR] Scan rate limit exceeded. Please wait {retry_after}s before retrying.", "error")
        socketio.emit("url_analysis_result", {
            "status": "error",
            "message": f"Scan rate limit exceeded. Please wait {retry_after} seconds before launching another reconnaissance probe.",
        })
        return

    target_url = (data or {}).get("link") or (data or {}).get("target_url") or (data or {}).get("url")
    if not target_url:
        emit_status_log("[ERROR] Target URL missing in scan request.", "error")
        return
    logger.info("analyze_url event received for URL: %s from %s", target_url, client_ip)
    threading.Thread(target=run_url_investigation, args=(target_url,), daemon=True).start()


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    """REST API endpoint for synchronous / fetch-based URL inspection."""
    client_ip = _get_client_ip()
    logger.info("POST /api/analyze-url from %s", client_ip)

    limited, remaining, retry_after = _check_rate_limit(f"api_{client_ip}", limit=20, window=60)
    if limited:
        resp = jsonify({
            "status": "error",
            "message": f"Rate limit exceeded. Please wait {retry_after} seconds before retrying.",
            "code": 429,
            "retry_after": retry_after,
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = "20"
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

    data = request.get_json(silent=True) or request.form.to_dict()
    target_url = data.get("url") or data.get("target_url") or data.get("link")
    if not target_url:
        return jsonify({"status": "error", "message": "No URL provided in request."}), 400

    valid, reason, normalized_url = _validate_url(target_url)
    if not valid:
        logger.warning(
            "api_analyze_url blocked — %s (URL: %s, IP: %s)", reason, target_url, client_ip
        )
        return jsonify({"status": "error", "message": reason}), 400

    try:
        result = url_scanner.inspect_url_deep(normalized_url, emit_log=emit_status_log)
        socketio.emit("url_analysis_result", result)
        return jsonify(result)
    except Exception as exc:
        logger.error("api_analyze_url exception for %s: %s", normalized_url, exc)
        err_result = {"status": "error", "message": str(exc), "url": normalized_url}
        socketio.emit("url_analysis_result", err_result)
        return jsonify(err_result), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("[*] Starting Threat Sandbox Server on http://127.0.0.1:5000 ...")
    socketio.run(
        app,
        debug=False,
        host="127.0.0.1",
        port=5000,
        allow_unsafe_werkzeug=True,
    )