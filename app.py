"""
app.py — DoubleCheck Intel Platform v2.1
Deployment-ready for Railway / Render / Local.

Fixes applied:
  1. File stored server-side (not cookie) — no 4KB cookie limit
  2. MAX_CONTENT_LENGTH = 100MB
  3. OSINT capped on cloud to avoid timeouts
  4. Gunicorn-compatible (no use_reloader)
  5. results/ uses /tmp on cloud (writable on all platforms)
  6. 413 handler for oversized uploads
"""

import os
import uuid
import json
import threading
import logging
import socket

from flask import Flask, render_template, request, session, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import io

load_dotenv()

app = Flask(__name__)

# ── Secret key (stable across restarts if set in env) ──
app.secret_key = os.getenv("SECRET_KEY", "doublecheck-intel-v2-default-key-change-me")

# ── Upload limit: 100 MB always ──
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ── Detect cloud platform ──
# DO NOT use PORT — Windows local machines also have PORT set
IS_CLOUD = any([
    os.getenv("RENDER"),
    os.getenv("RAILWAY_ENVIRONMENT"),
    os.getenv("HEROKU_APP_NAME"),
    os.getenv("VESSEL_ENV"),
    os.getenv("CLOUD_DEPLOY"),     # set this manually in your platform env vars
])

# ── Folders ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# uploads/ — temp file storage (use /tmp on cloud, local dir otherwise)
UPLOAD_FOLDER  = "/tmp/dc_uploads" if IS_CLOUD else os.path.join(BASE_DIR, "uploads")

# results/ — server-side session storage (use /tmp on cloud)
RESULTS_FOLDER = "/tmp/dc_results" if IS_CLOUD else os.path.join(BASE_DIR, "results")

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# ── API keys ──
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")

ALLOWED_EXTENSIONS = {".apk", ".exe", ".dll"}


# ══════════════════════════════════════════════════════════════
# SERVER-SIDE SESSION  (fixes 4KB cookie limit)
# ══════════════════════════════════════════════════════════════

def save_result(result: dict) -> str:
    """Save analysis result to a server-side JSON file. Returns result ID."""
    rid   = uuid.uuid4().hex
    path  = os.path.join(RESULTS_FOLDER, f"{rid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, default=str)
    return rid


def load_result(rid: str) -> dict:
    """Load analysis result from server-side file."""
    if not rid:
        return {}
    path = os.path.join(RESULTS_FOLDER, f"{rid}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def cleanup_old_results():
    """Delete result files older than 2 hours — run in background thread."""
    import time
    try:
        cutoff = time.time() - 7200
        for fname in os.listdir(RESULTS_FOLDER):
            fpath = os.path.join(RESULTS_FOLDER, fname)
            try:
                if os.path.getmtime(fpath) < cutoff:
                    os.remove(fpath)
            except Exception:
                pass
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
# FILE TYPE DETECTION
# ══════════════════════════════════════════════════════════════

def detect_file_type(filepath: str) -> str:
    """Detect by magic bytes — not by extension."""
    with open(filepath, "rb") as f:
        header = f.read(4)
    if header[:2] == b"PK":
        return "apk"
    if header[:2] == b"MZ":
        return "pe"
    return "unknown"


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html", is_cloud=IS_CLOUD)


@app.route("/analyze", methods=["POST"])
def analyze():
    # Validate
    if "file" not in request.files:
        return render_template("error.html", error="No file uploaded.")
    f = request.files["file"]
    if not f or not f.filename:
        return render_template("error.html", error="Empty file submitted.")

    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return render_template("error.html",
            error=f"Unsupported file type '{ext}'. Only APK, EXE, and DLL are supported.")

    # Save temp file
    safe_name = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
    temp_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(temp_path)

    # Size check (actual bytes on disk)
    actual_mb = os.path.getsize(temp_path) / (1024 * 1024)
    if actual_mb > 100:
        os.remove(temp_path)
        return render_template("error.html",
            error=f"File too large ({actual_mb:.1f} MB). Maximum is 100 MB.")

    result    = {}
    file_type = detect_file_type(temp_path)

    try:
        # ── APK ──
        if file_type == "apk":
            from engines.android import analyze_apk
            result = analyze_apk(temp_path)

            net         = result.get("network_indicators", {})
            public_ips  = net.get("hardcoded_ips", [])
            private_ips = net.get("private_ips", [])

            # Don't block page load — show IPs immediately
            # OSINT enrichment happens via /enrich endpoint (AJAX after page loads)
            result["enriched_ips"] = []
            result["private_ip_entries"] = [
                {"ip": ip, "label": "Private / Internal IP", "is_private": True}
                for ip in private_ips
            ]

        # ── Windows PE ──
        elif file_type == "pe":
            from engines.windows import analyze_windows
            result = analyze_windows(temp_path)
            result["enriched_ips"]       = []
            result["private_ip_entries"] = []
            vd = result.pop("verdict_data", {})
            result.update(vd)

        # ── Unknown ──
        else:
            os.remove(temp_path)
            return render_template("error.html",
                error="File format not recognized. Upload a valid APK, EXE, or DLL.")

    except MemoryError:
        return render_template("error.html",
            error="Not enough memory to analyze this file. Try a smaller APK (under 20 MB).")
    except Exception as e:
        result.setdefault("errors", []).append(str(e))
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

    # Verdict
    from verdict import safe_calculate_verdict
    result["verdict_info"] = safe_calculate_verdict(result)

    # Save server-side, store only ID in cookie
    rid = save_result(result)
    session["result_id"] = rid

    # Background cleanup
    threading.Thread(target=cleanup_old_results, daemon=True).start()

    return render_template("report.html", r=result)


@app.route("/enrich", methods=["POST"])
def enrich():
    """
    Called by JavaScript AFTER the page loads.
    Runs OSINT in background so page shows instantly.
    Returns enriched IP data as JSON.
    """
    import json as json_lib
    rid    = session.get("result_id", "")
    result = load_result(rid)
    if not result:
        return {"enriched_ips": []}, 200

    net        = result.get("network_indicators", {})
    public_ips = net.get("hardcoded_ips", [])

    if not public_ips:
        return {"enriched_ips": []}, 200

    from osint import enrich_ip_list
    ip_cap   = 5 if IS_CLOUD else 10
    osint_to = 3 if IS_CLOUD else 5

    enriched = enrich_ip_list(public_ips[:ip_cap], ABUSEIPDB_KEY, VT_KEY, timeout=osint_to)

    # Save enriched data back to result file
    result["enriched_ips"] = enriched
    save_result_to_id(rid, result)

    from flask import jsonify
    return jsonify({"enriched_ips": enriched})


def save_result_to_id(rid: str, result: dict):
    """Overwrite existing result file with updated data."""
    if not rid:
        return
    path = os.path.join(RESULTS_FOLDER, f"{rid}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            import json as _j
            _j.dump(result, f, ensure_ascii=False, default=str)
    except Exception:
        pass


@app.route("/export_pdf", methods=["POST"])
def export_pdf():
    rid    = session.get("result_id", "")
    result = load_result(rid)
    if not result:
        return redirect(url_for("index"))
    try:
        from pdf_export import generate_pdf
        pdf_bytes = generate_pdf(result)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="intel_report.pdf",
        )
    except Exception as e:
        return render_template("error.html", error=f"PDF generation failed: {e}")


# ── 413 handler ──
@app.errorhandler(413)
def file_too_large(e):
    return render_template("error.html",
        error="File too large. Maximum upload size is 100 MB."), 413


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Suppress werkzeug's default banner (which shows 127.0.0.1)
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    port = int(os.getenv("PORT", 5000))

    # Print only the LAN IP
    try:
        lan_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        lan_ip = "localhost"

    print(f"\n  DoubleCheck Intel Platform v2.1")
    print(f"  ─────────────────────────────────")
    print(f"  Open →  http://{lan_ip}:{port}")
    print(f"  Press CTRL+C to stop\n")

    app.run(
        debug=False,           # always off — avoids reloader printing 127 link
        host="0.0.0.0",
        port=port,
        use_reloader=False,    # must be False — reloader prints 127 link
    )
