# CHANGELOG — UNIFIED THREAT SANDBOX

All notable changes to this project are documented in this file.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.5.0] — 2026-10-16 — Industry Security Hardening Edition

### 🔒 Security — `app.py`
- **Secret Key Hardening**: `SECRET_KEY` now reads from `THREAT_SANDBOX_SECRET` environment variable; falls back to a runtime-generated `secrets.token_hex(32)` — eliminates hardcoded secret
- **File Upload Whitelist**: Strict extension allowlist (`.exe`, `.dll`, `.bat`, `.ps1`, `.pdf`, `.zip`, `.doc`, `.xls`, etc.) — rejects all other file types with 400
- **`secure_filename` Sanitization**: Applies `werkzeug.utils.secure_filename` to all upload filenames before saving
- **UUID-Prefixed Filenames**: All uploaded files are renamed to `<uuid4>_<original>` to prevent filename collision and path guessing attacks
- **Max File Size**: Enforced 50 MB hard limit via `MAX_CONTENT_LENGTH` and manual check; returns 413 with JSON error on violation
- **Path Traversal Prevention**: Validates that the resolved save path is strictly inside the `uploads/` directory using `os.path.abspath` comparison
- **SSRF Protection**: URL analysis endpoints validate that the target URL does not point to private/loopback IP ranges (127.x, 10.x, 192.168.x, 172.16–31.x) or dangerous schemes (`file://`, `javascript:`, `data:`, `ftp://`)
- **Security Response Headers**: `@app.after_request` hook adds `X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `Content-Security-Policy`, and `Strict-Transport-Security` to every response
- **Rate Limiting**: In-memory per-IP rate limiter (no external library) — `/upload-file`: 10 req/min, `/api/analyze-url`: 20 req/min; returns 429 on breach
- **SocketIO CORS**: Restricted from `"*"` to only `["http://127.0.0.1:5000", "http://localhost:5000"]`
- **Upload Serve Route**: `/uploads/<filename>` now only serves `.png` and `.txt` files; all others return 403; path traversal blocked via `abspath` check
- **Request Logging**: Python `logging` module added at INFO level; all requests, upload events, and errors are logged to console with timestamps
- **Error Handlers**: Proper JSON-returning error handlers for 400, 404, 413, 429, 500 HTTP status codes

### 🔒 Security — `sandbox_controller.py`
- **Credential Externalization**: `GUEST_PASS` now reads from `VBOX_GUEST_PASS` environment variable; hardcoded fallback kept for backward compatibility with a startup warning log

### 🔒 Security — `url_scanner.py`
- **SSRF Guard Function**: Added `_is_ssrf_target()` to reject private/loopback IPs and forbidden URL schemes before Playwright launch
- **URL Length Enforcement**: Rejects URLs longer than 2048 characters with descriptive error
- **Scheme Whitelist**: Strictly allows only `http://` and `https://`; all other schemes rejected
- **Private IP Detection**: Regex and socket-based detection of RFC 1918 private address space to prevent SSRF against the host system

### 📄 Documentation
- Created `FUTURE_ENHANCEMENTS.txt` — 20-item hierarchical enhancement registry with priority tiers, complexity ratings, implementation notes, and status tracking
- Created `CHANGELOG.md` — this file; tracks all project changes by version
- Updated `ACADEMIC_PROJECT_REPORT.md` — Section 7 expanded with new security hardening details; Section 9.2 synced with `FUTURE_ENHANCEMENTS.txt`
- Updated `PROJECT_MASTER_PROMPT.md` — added v2.5 security architecture context, environment variable configuration, and new enhancement commands

### 📦 Dependencies — `requirement.txt`
- Pinned all packages to specific versions for reproducible builds
- Added `python-dotenv>=1.0.0` for `.env` file support in development

---

## [2.4.0] — 2026-10-13 — Recon Engine Stability Update

### Changed
- `url_scanner.py`: Fixed `security_details()` Playwright API call signature (added `callable()` check)
- `app.py`: Added `analyze_url` SocketIO event as backward-compatible alias for `start_url_scan`
- `app.py`: Added `/api/analyze-url` REST endpoint as HTTP-based alternative to WebSocket

### Fixed
- Duplicate screenshot saving now correctly updates both timestamped and `url_capture_latest.png` files
- Navigation timeout increased from 15s to 20s for slow target sites

---

## [2.3.0] — 2026-10-11 — Academic Report & Documentation Milestone

### Added
- `ACADEMIC_PROJECT_REPORT.md` — Full 509-line academic project report with architecture diagrams, mathematical models, and test case results
- `PROJECT_MASTER_PROMPT.md` — Contextual master prompt for AI-assisted presentation and defense preparation

### Changed
- `url_scanner.py`: DOM analysis expanded with credit card input detection (`autocomplete="cc-number"`)
- `url_scanner.py`: Redirect chain tracking added for multi-hop phishing detection

---

## [2.2.0] — 2026-10-07 — Headless Browser Reconnaissance

### Added
- Full Playwright Chromium headless integration in `url_scanner.py`
- Browser Permissions Matrix (`navigator.permissions.query()`) for 10 hardware/sensor APIs
- HTTP `Permissions-Policy` header parser
- SSL/TLS certificate chain analysis via Playwright `security_details()` and socket fallback
- DOM attack surface inspection (forms, password inputs, external scripts, outbound links)
- Visual viewport screenshot capture (`uploads/url_capture_*.png`)

---

## [2.1.0] — 2026-10-03 — Machine Learning Integration

### Added
- `train_model.py` — TF-IDF + Random Forest training pipeline
- `malware_model.pkl` — Trained serialized scikit-learn model
- `dataset.csv` — Behavioral process execution telemetry training dataset
- ML inference in `app.py` `background_detonation()` function

---

## [2.0.0] — 2026-10-03 — Initial Project Release

### Added
- `app.py` — Flask + Flask-SocketIO web application gateway
- `sandbox_controller.py` — Oracle VirtualBox hypervisor automation via `VBoxManage`
- `templates/index.html` — Glassmorphic SOC dashboard with 3-second cyber HUD
- SHA-256 file hashing on upload
- Real-time WebSocket log streaming terminal
- Web Audio API cyber sound synthesizer
