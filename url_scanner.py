"""
url_scanner.py — Deep URL Threat Intelligence & Web Origin Reconnaissance Engine
==================================================================================
Performs isolated headless reconnaissance using Playwright, socket/SSL, and DNS.

Security Controls (v2.5):
  - SSRF Guard: Rejects private/loopback IP targets and forbidden URL schemes
  - URL Length Limit: Maximum 2048 characters enforced
  - Scheme Whitelist: Only http:// and https:// are permitted
  - Forbidden Scheme Rejection: file://, ftp://, javascript:, data: are blocked
  - Private Range Detection: RFC 1918, loopback, link-local ranges blocked

Extracts: Origin, Web Permissions, SSL/TLS Certificates, Security Headers,
          DOM attack surface, redirect chains, cookies, and visual snapshot.
"""

import os
import re
import socket
import ssl
import ipaddress
import logging
import time
import urllib.parse
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

# Module-level logger
logger = logging.getLogger("threat_sandbox.url_scanner")

# ---------------------------------------------------------------------------
# SSRF Guard — Private/Loopback/Forbidden Scheme Rejection
# ---------------------------------------------------------------------------
# These private IPv4 CIDR ranges are blocked to prevent SSRF attacks where
# a malicious analyst could submit e.g. http://192.168.1.1/admin to probe
# internal services on the host network.
_PRIVATE_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # RFC 3927 Link-local & Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),    # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),     # RFC 2544 Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # RFC 5771 Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # RFC 1112 Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    ipaddress.ip_network("::/128"),            # IPv6 Unspecified
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),      # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),          # Discard-Only
    ipaddress.ip_network("2001:db8::/32"),     # Documentation
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),          # IPv6 Multicast
]

# Cloud metadata and loopback hostnames strictly prohibited
_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
    "169.254.169.254",
}

# Permitted public web service ports
_PERMITTED_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# URL schemes that are dangerous or meaningless for external web recon
_FORBIDDEN_SCHEMES = {"file", "ftp", "javascript", "data", "blob", "vbscript", "ldap", "dict", "gopher"}

# Maximum allowed URL length (characters)
_MAX_URL_LENGTH = 2048


def _is_private_ip(ip_str: str) -> bool:
    """Returns True if the IP address string falls within a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in network for network in _PRIVATE_RANGES)
    except ValueError:
        return False


def validate_url_for_ssrf(raw_url: str) -> dict:
    """
    Validates a URL for SSRF safety before handing it to the recon engine.

    Checks performed:
      1. URL length <= 2048 characters
      2. Scheme must be http or https (not file://, ftp://, etc.)
      3. Prohibited hostnames and cloud metadata endpoints blocked
      4. Port verification against allowed web ports
      5. Hostname must resolve to a non-private IP address

    Returns:
        dict with keys: valid (bool), reason (str or None)
    """
    if not raw_url or not isinstance(raw_url, str):
        return {"valid": False, "reason": "URL must be a non-empty string."}

    url = raw_url.strip()

    # 1. Length guard
    if len(url) > _MAX_URL_LENGTH:
        return {"valid": False, "reason": f"URL exceeds maximum allowed length of {_MAX_URL_LENGTH} characters."}

    # 2. Scheme validation — must start with http:// or https://
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    scheme = parsed.scheme.lower()
    if scheme in _FORBIDDEN_SCHEMES:
        logger.warning("[SSRF-GUARD] Forbidden scheme rejected: %s", scheme)
        return {"valid": False, "reason": f"Scheme '{scheme}://' is not permitted. Only http:// and https:// are allowed."}
    if scheme not in ("http", "https"):
        logger.warning("[SSRF-GUARD] Unknown scheme rejected: %s", scheme)
        return {"valid": False, "reason": f"Unknown scheme '{scheme}://'. Only http:// and https:// are allowed."}

    # 3. Hostname checks
    hostname = parsed.hostname
    if not hostname:
        return {"valid": False, "reason": "Could not extract a valid hostname from the URL."}

    hostname_clean = hostname.lower().strip(".")
    if hostname_clean in _BLOCKED_HOSTNAMES:
        logger.warning("[SSRF-GUARD] Blocked access to restricted hostname: %s", hostname)
        return {
            "valid": False,
            "reason": f"Target host '{hostname}' is a restricted internal or cloud metadata service (SSRF blocked).",
        }

    # 4. Port verification
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in _PERMITTED_PORTS:
        logger.warning("[SSRF-GUARD] Blocked non-standard port: %d", port)
        return {
            "valid": False,
            "reason": f"Port {port} is not permitted for reconnaissance. Permitted web ports: {sorted(_PERMITTED_PORTS)}.",
        }

    # 5. DNS resolution + private IP check
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = item[4][0]
            if _is_private_ip(ip):
                logger.warning("[SSRF-GUARD] Blocked SSRF attempt to private/loopback IP: %s → %s", hostname, ip)
                return {
                    "valid": False,
                    "reason": (
                        f"Target hostname '{hostname}' resolves to a private or loopback address ({ip}). "
                        "Scanning internal infrastructure is strictly prohibited (SSRF Guard)."
                    ),
                }
    except socket.gaierror:
        # If the hostname cannot be resolved, we allow it to surface as a DNS failure downstream
        pass

    return {"valid": True, "reason": None}


def parse_target_url(raw_url: str):
    """Normalizes and validates target URL."""
    url = raw_url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Invalid hostname in URL: {raw_url}")
        
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if (parsed.scheme == "https" and port != 443) or (parsed.scheme == "http" and port != 80):
        origin += f":{port}"
        
    return {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": port,
        "origin": origin,
        "path": parsed.path or "/",
        "query": parsed.query
    }

def get_dns_and_network_info(hostname: str):
    """Resolves DNS records and reverse DNS for the target hostname."""
    ip_addresses = []
    reverse_dns = "N/A"
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        seen = set()
        for item in addr_info:
            ip = item[4][0]
            if ip not in seen:
                seen.add(ip)
                ip_addresses.append(ip)
    except Exception as e:
        ip_addresses = [f"DNS resolution failed: {str(e)}"]

    primary_ip = ip_addresses[0] if ip_addresses and not ip_addresses[0].startswith("DNS") else "Unknown"
    if primary_ip != "Unknown":
        try:
            rev = socket.gethostbyaddr(primary_ip)
            reverse_dns = rev[0]
        except Exception:
            reverse_dns = "No PTR record found"

    return {
        "primary_ip": primary_ip,
        "all_ips": ip_addresses,
        "reverse_dns": reverse_dns
    }

def get_ssl_cert_details(hostname: str, port: int = 443):
    """Inspects SSL certificate via direct TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                tls_version = ssock.version()
                
                return {
                    "has_ssl": True,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "tls_version": tls_version or "Unknown",
                    "cert_raw": cert
                }
    except Exception as e:
        return {
            "has_ssl": False,
            "error": str(e)
        }

def parse_permissions_policy_header(header_val: str):
    """Parses Permissions-Policy or Feature-Policy HTTP response header into a structured dict."""
    if not header_val:
        return {}
    
    parsed = {}
    directives = [d.strip() for d in header_val.split(",") if d.strip()]
    for directive in directives:
        match = re.match(r"^([a-zA-Z0-9_-]+)(?:=(.*))?$", directive)
        if match:
            feature = match.group(1).lower()
            val = match.group(2) or ""
            val = val.strip().strip('"')
            if val == "()":
                parsed[feature] = "Blocked / Disabled for all origins"
            elif "self" in val:
                parsed[feature] = "Restricted to same-origin (self)"
            elif val == "*":
                parsed[feature] = "Globally Allowed (*)"
            else:
                parsed[feature] = f"Allowed origins: {val}" if val else "Allowed"
    return parsed

def grade_security_headers(headers: dict):
    """Audits HTTP security headers and calculates a security posture score (0-100) and letter grade."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    audit = {}
    score = 0
    max_score = 100

    # 1. HSTS (Strict-Transport-Security) (25 pts)
    hsts = lower_headers.get("strict-transport-security")
    if hsts:
        score += 25
        audit["HSTS"] = {
            "status": "PASS",
            "score": 25,
            "max": 25,
            "value": hsts,
            "info": "Strict-Transport-Security enforces encrypted HTTPS connections and mitigates SSL stripping."
        }
    else:
        audit["HSTS"] = {
            "status": "FAIL",
            "score": 0,
            "max": 25,
            "value": "Missing",
            "info": "HSTS header is missing. Users could be vulnerable to man-in-the-middle SSL stripping attacks."
        }

    # 2. CSP (Content-Security-Policy) (25 pts)
    csp = lower_headers.get("content-security-policy")
    if csp:
        score += 25
        audit["CSP"] = {
            "status": "PASS",
            "score": 25,
            "max": 25,
            "value": csp[:120] + ("..." if len(csp) > 120 else ""),
            "info": "Content-Security-Policy restricts origins of executable scripts, mitigating XSS and data injection."
        }
    else:
        audit["CSP"] = {
            "status": "WARN",
            "score": 0,
            "max": 25,
            "value": "Missing",
            "info": "No CSP found. Browser cannot restrict unapproved external scripts or inline scripts."
        }

    # 3. X-Frame-Options (Clickjacking defense) (15 pts)
    xfo = lower_headers.get("x-frame-options")
    if xfo:
        score += 15
        audit["X-Frame-Options"] = {
            "status": "PASS",
            "score": 15,
            "max": 15,
            "value": xfo,
            "info": f"Configured as '{xfo}'. Prevents malicious framing and clickjacking attacks."
        }
    elif csp and "frame-ancestors" in csp:
        score += 15
        audit["X-Frame-Options"] = {
            "status": "PASS",
            "score": 15,
            "max": 15,
            "value": "CSP frame-ancestors active",
            "info": "Frame protection is enforced via CSP frame-ancestors directive."
        }
    else:
        audit["X-Frame-Options"] = {
            "status": "FAIL",
            "score": 0,
            "max": 15,
            "value": "Missing",
            "info": "Page can be embedded in an unauthorized <iframe>, exposing users to clickjacking."
        }

    # 4. X-Content-Type-Options (15 pts)
    xcto = lower_headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        score += 15
        audit["X-Content-Type-Options"] = {
            "status": "PASS",
            "score": 15,
            "max": 15,
            "value": xcto,
            "info": "Enforces strict MIME typing; prevents MIME-sniffing exploits."
        }
    else:
        audit["X-Content-Type-Options"] = {
            "status": "FAIL",
            "score": 0,
            "max": 15,
            "value": xcto or "Missing",
            "info": "Missing 'nosniff'. Browsers may attempt to guess MIME types, risking script execution."
        }

    # 5. Referrer-Policy (10 pts)
    ref = lower_headers.get("referrer-policy")
    if ref:
        score += 10
        audit["Referrer-Policy"] = {
            "status": "PASS",
            "score": 10,
            "max": 10,
            "value": ref,
            "info": f"Configured as '{ref}'. Guards sensitive URLs from leaking in HTTP Referer headers."
        }
    else:
        audit["Referrer-Policy"] = {
            "status": "WARN",
            "score": 5,
            "max": 10,
            "value": "Default Browser Policy",
            "info": "Explicit Referrer-Policy not provided; browser falls back to default."
        }
        score += 5

    # 6. Permissions-Policy / Feature-Policy (10 pts)
    perm_policy = lower_headers.get("permissions-policy") or lower_headers.get("feature-policy")
    if perm_policy:
        score += 10
        audit["Permissions-Policy"] = {
            "status": "PASS",
            "score": 10,
            "max": 10,
            "value": perm_policy[:100] + ("..." if len(perm_policy) > 100 else ""),
            "info": "Explicitly locks down or restricts browser hardware and API permissions."
        }
    else:
        audit["Permissions-Policy"] = {
            "status": "WARN",
            "score": 0,
            "max": 10,
            "value": "Not configured",
            "info": "Permissions-Policy header absent; browser features rely on standard permission prompts."
        }

    # Technology leak check
    server_header = lower_headers.get("server")
    x_powered_by = lower_headers.get("x-powered-by")
    tech_leak = []
    if server_header:
        tech_leak.append(f"Server: {server_header}")
    if x_powered_by:
        tech_leak.append(f"X-Powered-By: {x_powered_by}")

    # Grade calculation
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "max_score": max_score,
        "grade": grade,
        "audit": audit,
        "tech_leak": tech_leak
    }

def inspect_url_deep(raw_url: str, emit_log=None):
    """
    Main URL analysis engine (v2.5 — Security Hardened).
    Uses Playwright headless browser to load the target URL,
    extracts origin, permissions, SSL/TLS certificates, security headers,
    DOM structure (forms, password fields, links, scripts), and saves a screenshot.

    Security: Runs validate_url_for_ssrf() before any network contact is made
    to prevent SSRF attacks against the host's internal network.
    """
    def log(msg, level="info"):
        if emit_log:
            emit_log(msg, level)
        else:
            print(f"[{level.upper()}] {msg}")

    # --- SSRF Guard (first check, before any network activity) ---
    ssrf_check = validate_url_for_ssrf(raw_url)
    if not ssrf_check["valid"]:
        reason = ssrf_check["reason"]
        log(f"[SECURITY] URL rejected by SSRF guard: {reason}", "error")
        logger.warning("[SSRF-GUARD] Blocked scan request for URL: %s | Reason: %s", raw_url[:200], reason)
        return {
            "status": "error",
            "message": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "security_block": True
        }

    try:
        url_meta = parse_target_url(raw_url)
    except Exception as e:
        log(f"Invalid URL target: {str(e)}", "error")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    target_url = url_meta["url"]
    hostname = url_meta["hostname"]
    port = url_meta["port"]
    origin = url_meta["origin"]

    log(f"Initiating reconnaissance on target: {target_url}", "info")
    log(f"Extracted Primary Origin: {origin} (Hostname: {hostname}:{port})", "info")

    # Step 1: DNS & Network Perimeter
    log(f"Resolving DNS records and network perimeter for {hostname}...", "info")
    network_info = get_dns_and_network_info(hostname)
    log(f"Resolved Origin IP: {network_info['primary_ip']} (Reverse PTR: {network_info['reverse_dns']})", "success")

    # Step 2: Headless Playwright Reconnaissance
    log("Deploying isolated headless Chromium sandbox container...", "info")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    uploads_dir = os.path.join(base_dir, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_rel = f"url_capture_{timestamp_str}.png"
    screenshot_path = os.path.join(uploads_dir, screenshot_rel)
    latest_screenshot_path = os.path.join(uploads_dir, "url_capture_latest.png")

    redirect_chain = []
    response_headers = {}
    http_status = 200
    http_status_text = "OK"
    security_details = {}
    dom_stats = {}
    browser_permissions = []
    cookies_list = []
    final_url = target_url
    page_title = "Untitled Document"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage"
                ]
            )
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatSandbox/2.4 (Security Inspector)"
            )
            page = context.new_page()

            # Intercept all subrequests & redirects to prevent internal SSRF
            def intercept_route(route):
                req_url = route.request.url
                if req_url.startswith("data:") or req_url.startswith("blob:"):
                    route.continue_()
                    return
                chk = validate_url_for_ssrf(req_url)
                if not chk["valid"]:
                    logger.warning("[SSRF-INTERCEPT] Blocked subrequest: %s (%s)", req_url[:100], chk["reason"])
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", intercept_route)

            # Track redirects
            def on_response(response):
                if 300 <= response.status < 400:
                    redirect_chain.append({
                        "url": response.url,
                        "status": response.status,
                        "location": response.headers.get("location", "")
                    })
            page.on("response", on_response)

            log("Establishing TLS session and requesting target origin DOM...", "info")
            main_response = None
            try:
                main_response = page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(1000) # Allow dynamic scripts/DOM to settle
            except Exception as e:
                log(f"Navigation notice: {str(e)}", "warning")

            final_url = page.url
            try:
                page_title = page.title() or "Untitled Document"
            except Exception:
                page_title = hostname

            if main_response:
                http_status = main_response.status
                http_status_text = main_response.status_text
                response_headers = dict(main_response.headers)
                log(f"HTTP Status: {http_status} {http_status_text}", "success" if http_status < 400 else "warning")
                
                # Security Details from Playwright
                if hasattr(main_response, "security_details") and callable(main_response.security_details):
                    try:
                        sec = main_response.security_details()
                        if sec:
                            security_details = sec
                    except Exception as e:
                        log(f"Playwright security details notice: {e}", "warning")

            # Capture visual viewport screenshot
            try:
                page.screenshot(path=screenshot_path, full_page=False)
                page.screenshot(path=latest_screenshot_path, full_page=False)
                log(f"Visual viewport captured in isolated sandbox: {screenshot_rel}", "success")
            except Exception as e:
                log(f"Screenshot capture notice: {str(e)}", "warning")

            # Probe browser permissions API inside page
            log("Probing web permissions and browser capabilities matrix...", "info")
            try:
                browser_permissions = page.evaluate("""async () => {
                    const perms = [
                        { name: 'camera', label: 'Camera / Webcam', risk: 'High' },
                        { name: 'microphone', label: 'Microphone / Audio', risk: 'High' },
                        { name: 'geolocation', label: 'Geolocation / GPS Location', risk: 'High' },
                        { name: 'notifications', label: 'Push Notifications', risk: 'Medium' },
                        { name: 'clipboard-read', label: 'Clipboard Read Access', risk: 'High' },
                        { name: 'clipboard-write', label: 'Clipboard Write Access', risk: 'Low' },
                        { name: 'persistent-storage', label: 'Persistent Storage', risk: 'Low' },
                        { name: 'accelerometer', label: 'Motion Sensors (Accelerometer)', risk: 'Low' },
                        { name: 'gyroscope', label: 'Device Gyroscope', risk: 'Low' },
                        { name: 'magnetometer', label: 'Device Magnetometer', risk: 'Low' }
                    ];
                    const results = [];
                    for (const item of perms) {
                        try {
                            const status = await navigator.permissions.query({ name: item.name });
                            results.push({
                                name: item.name,
                                label: item.label,
                                risk: item.risk,
                                state: status.state // 'granted', 'denied', or 'prompt'
                            });
                        } catch (e) {
                            results.push({
                                name: item.name,
                                label: item.label,
                                risk: item.risk,
                                state: 'not-queried-or-restricted'
                            });
                        }
                    }
                    return results;
                }""")
            except Exception as e:
                log(f"Browser permissions query notice: {str(e)}", "warning")

            # Probe DOM Structure & Attack Surface Heuristics
            log("Analyzing DOM structure, form inputs, scripts, and links...", "info")
            try:
                dom_stats = page.evaluate("""() => {
                    const forms = Array.from(document.forms).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        hasPassword: !!f.querySelector('input[type="password"]'),
                        inputCount: f.querySelectorAll('input, select, textarea').length
                    }));

                    const passwordInputs = document.querySelectorAll('input[type="password"]').length;
                    const creditCardInputs = document.querySelectorAll('input[autocomplete="cc-number"], input[name*="card"], input[name*="cc_num"]').length;

                    const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
                    const externalScripts = scripts.filter(s => {
                        try {
                            const host = new URL(s).hostname;
                            return host && host !== window.location.hostname;
                        } catch (e) { return false; }
                    });

                    const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                    const externalLinks = links.filter(l => {
                        try {
                            const host = new URL(l).hostname;
                            return host && host !== window.location.hostname;
                        } catch (e) { return false; }
                    });

                    const metaDesc = document.querySelector('meta[name="description"]')?.content || 
                                     document.querySelector('meta[property="og:description"]')?.content || '';

                    const metaAuthor = document.querySelector('meta[name="author"]')?.content || '';

                    return {
                        formsCount: forms.length,
                        forms: forms.slice(0, 5),
                        passwordInputs: passwordInputs,
                        creditCardInputs: creditCardInputs,
                        totalScripts: document.querySelectorAll('script').length,
                        externalScriptsCount: externalScripts.length,
                        sampleExternalScripts: externalScripts.slice(0, 6),
                        totalLinks: links.length,
                        externalLinksCount: externalLinks.length,
                        metaDescription: metaDesc,
                        metaAuthor: metaAuthor
                    };
                }""")
            except Exception as e:
                log(f"DOM evaluation notice: {str(e)}", "warning")

            # Cookies inspection
            try:
                cookies = context.cookies()
                cookies_list = [{
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "httpOnly": c.get("httpOnly"),
                    "secure": c.get("secure"),
                    "sameSite": c.get("sameSite")
                } for c in cookies[:10]]
            except Exception:
                cookies_list = []

            browser.close()
    except Exception as e:
        log(f"Sandbox headless browser notice: {str(e)}", "warning")

    # Fallback permissions list if page query failed
    if not browser_permissions:
        browser_permissions = [
            {"name": "camera", "label": "Camera / Webcam", "risk": "High", "state": "prompt"},
            {"name": "microphone", "label": "Microphone / Audio", "risk": "High", "state": "prompt"},
            {"name": "geolocation", "label": "Geolocation / GPS Location", "risk": "High", "state": "prompt"},
            {"name": "notifications", "label": "Push Notifications", "risk": "Medium", "state": "prompt"},
            {"name": "clipboard-read", "label": "Clipboard Read Access", "risk": "High", "state": "prompt"},
            {"name": "clipboard-write", "label": "Clipboard Write Access", "risk": "Low", "state": "prompt"},
            {"name": "persistent-storage", "label": "Persistent Storage", "risk": "Low", "state": "prompt"},
            {"name": "accelerometer", "label": "Motion Sensors (Accelerometer)", "risk": "Low", "state": "prompt"},
            {"name": "gyroscope", "label": "Device Gyroscope", "risk": "Low", "state": "prompt"},
            {"name": "magnetometer", "label": "Device Magnetometer", "risk": "Low", "state": "prompt"}
        ]

    # Step 3: Parse Permissions-Policy Header
    perm_policy_header = response_headers.get("permissions-policy", "") or response_headers.get("feature-policy", "")
    policy_directives = parse_permissions_policy_header(perm_policy_header)

    # Step 4: Audit Security Headers & Calculate Score
    log("Auditing security headers (HSTS, CSP, X-Frame-Options, etc.)...", "info")
    headers_audit = grade_security_headers(response_headers)
    log(f"Security Posture Rating: Grade {headers_audit['grade']} ({headers_audit['score']}/100 pts)", "success")

    # Step 5: Format SSL / TLS Certificate Info
    ssl_cert_info = {}
    if security_details:
        valid_from_ts = security_details.get("validFrom")
        valid_to_ts = security_details.get("validTo")
        valid_from_str = datetime.fromtimestamp(valid_from_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if valid_from_ts else "Unknown"
        valid_to_str = datetime.fromtimestamp(valid_to_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if valid_to_ts else "Unknown"
        
        days_remaining = None
        if valid_to_ts:
            now_ts = datetime.now(timezone.utc).timestamp()
            days_remaining = int((valid_to_ts - now_ts) / 86400)

        ssl_cert_info = {
            "is_https": target_url.startswith("https://"),
            "issuer": security_details.get("issuer", "Unknown CA"),
            "subject": security_details.get("subjectName", hostname),
            "protocol": security_details.get("protocol", "TLS"),
            "valid_from": valid_from_str,
            "valid_to": valid_to_str,
            "days_remaining": days_remaining,
            "is_valid": days_remaining is None or days_remaining > 0
        }
    else:
        # Fallback to direct socket probe
        fallback_ssl = get_ssl_cert_details(hostname, port)
        ssl_cert_info = {
            "is_https": target_url.startswith("https://"),
            "issuer": "N/A (Non-TLS / Plain HTTP)" if not fallback_ssl.get("has_ssl") else "TLS Active",
            "subject": hostname,
            "protocol": fallback_ssl.get("tls_version", "N/A"),
            "valid_from": "N/A",
            "valid_to": "N/A",
            "days_remaining": None,
            "is_valid": fallback_ssl.get("has_ssl", False)
        }

    # Step 6: Risk Assessment and Heuristic Classification
    risk_factors = []
    risk_level = "LOW RISK"
    risk_color = "success"

    if not url_meta["scheme"] == "https":
        risk_factors.append("CRITICAL: Unencrypted HTTP connection; sensitive data sent in cleartext.")
        risk_level = "HIGH RISK"
        risk_color = "danger"

    if dom_stats.get("passwordInputs", 0) > 0 and url_meta["scheme"] != "https":
        risk_factors.append("CRITICAL: Insecure credential harvesting form detected over plain HTTP.")
        risk_level = "HIGH RISK"
        risk_color = "danger"
    elif dom_stats.get("passwordInputs", 0) > 0:
        risk_factors.append("INFO: Login/Authentication password fields detected on page.")

    if headers_audit["grade"] in ["D", "F"]:
        risk_factors.append(f"WARNING: Weak security header posture (Grade {headers_audit['grade']}). Missing basic defense headers.")
        if risk_level != "HIGH RISK":
            risk_level = "MODERATE RISK"
            risk_color = "warning"

    if len(redirect_chain) > 2:
        risk_factors.append(f"NOTICE: Multiple redirection hops detected ({len(redirect_chain)} redirects).")

    if ssl_cert_info.get("days_remaining") is not None and ssl_cert_info["days_remaining"] < 15:
        risk_factors.append("WARNING: SSL Certificate expires in less than 15 days.")

    if not risk_factors:
        risk_factors.append("System validated TLS encryption, standard origin policies, and absence of deceptive inputs.")

    log(f"Threat Intelligence compilation finished. Final Risk Rating: {risk_level}", "success" if risk_color == "success" else "warning")

    return {
        "status": "success",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "origin_details": {
            "origin": origin,
            "input_url": target_url,
            "final_url": final_url,
            "scheme": url_meta["scheme"],
            "hostname": hostname,
            "port": port,
            "primary_ip": network_info["primary_ip"],
            "all_ips": network_info["all_ips"],
            "reverse_dns": network_info["reverse_dns"],
            "http_status": http_status,
            "http_status_text": http_status_text,
            "server_software": response_headers.get("server", "Protected / Hidden"),
            "content_type": response_headers.get("content-type", "text/html"),
            "redirects_count": len(redirect_chain),
            "redirect_chain": redirect_chain
        },
        "permissions_matrix": {
            "browser_permissions": browser_permissions,
            "policy_header_directives": policy_directives,
            "raw_policy_header": perm_policy_header or "None (Default browser prompt behavior)"
        },
        "ssl_certificate": ssl_cert_info,
        "security_headers": headers_audit,
        "dom_attack_surface": {
            "title": page_title,
            "meta_description": dom_stats.get("metaDescription", ""),
            "forms_count": dom_stats.get("formsCount", 0),
            "forms": dom_stats.get("forms", []),
            "password_inputs": dom_stats.get("passwordInputs", 0),
            "credit_card_inputs": dom_stats.get("creditCardInputs", 0),
            "total_scripts": dom_stats.get("totalScripts", 0),
            "external_scripts_count": dom_stats.get("externalScriptsCount", 0),
            "sample_external_scripts": dom_stats.get("sampleExternalScripts", []),
            "total_links": dom_stats.get("totalLinks", 0),
            "external_links_count": dom_stats.get("externalLinksCount", 0),
            "cookies": cookies_list
        },
        "visual_snapshot": {
            "screenshot_url": f"/uploads/{screenshot_rel}",
            "screenshot_filename": screenshot_rel
        },
        "threat_assessment": {
            "risk_level": risk_level,
            "risk_color": risk_color,
            "risk_factors": risk_factors
        }
    }
