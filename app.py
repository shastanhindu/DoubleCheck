"""
app.py — DoubleCheck Intel Platform v2.1
502 FIX: Analysis runs in background thread.
Page loads INSTANTLY. JavaScript polls /status until done.
Works on Render/Railway free tier (30s request limit bypassed).
"""

import os
import uuid
import json
import threading
import logging
import socket

from flask import Flask, render_template, request, session, send_file, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import io

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "doublecheck-intel-v2-key-2026")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# ── Cloud detection ──
IS_CLOUD = any([
    os.getenv("RENDER"),
    os.getenv("RAILWAY_ENVIRONMENT"),
    os.getenv("HEROKU_APP_NAME"),
    os.getenv("VESSEL_ENV"),
    os.getenv("CLOUD_DEPLOY"),
])

# ── Folders ──
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER  = "/tmp/dc_uploads" if IS_CLOUD else os.path.join(BASE_DIR, "uploads")
RESULTS_FOLDER = "/tmp/dc_results" if IS_CLOUD else os.path.join(BASE_DIR, "results")
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# ── API keys ──
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")

ALLOWED_EXTENSIONS = {".apk", ".exe", ".dll"}

# ── In-memory job tracker ──
# { job_id: "running" | "done" | "error" }
JOBS = {}
JOBS_LOCK = threading.Lock()


# ══════════════════════════════════════════════════════════════
# RESULT FILE HELPERS
# ══════════════════════════════════════════════════════════════

def save_result(rid: str, data: dict):
    path = os.path.join(RESULTS_FOLDER, f"{rid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, default=str)


def load_result(rid: str) -> dict:
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


def cleanup_old():
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
    with open(filepath, "rb") as f:
        header = f.read(4)
    if header[:2] == b"PK": return "apk"
    if header[:2] == b"MZ": return "pe"
    return "unknown"


# ══════════════════════════════════════════════════════════════
# BACKGROUND ANALYSIS WORKER
# ══════════════════════════════════════════════════════════════

def _run_analysis(job_id: str, filepath: str, file_type: str):
    """
    Runs in a background thread.
    Page is already shown to user — no 30s timeout applies here.
    """
    with JOBS_LOCK:
        JOBS[job_id] = "running"

    result = {}
    try:
        if file_type == "apk":
            from engines.android import analyze_apk
            result = analyze_apk(filepath)
            result["enriched_ips"]       = []
            result["private_ip_entries"] = [
                {"ip": ip, "label": "Private / Internal IP", "is_private": True}
                for ip in result.get("network_indicators", {}).get("private_ips", [])
            ]

        elif file_type == "pe":
            from engines.windows import analyze_windows
            result = analyze_windows(filepath)
            result["enriched_ips"]       = []
            result["private_ip_entries"] = []
            vd = result.pop("verdict_data", {})
            result.update(vd)

        # Verdict
        from verdict import safe_calculate_verdict
        result["verdict_info"] = safe_calculate_verdict(result)

        # Save result
        save_result(job_id, result)

        with JOBS_LOCK:
            JOBS[job_id] = "done"

    except MemoryError:
        err_result = {"error": "Not enough memory. Try a smaller file (under 15 MB)."}
        save_result(job_id, err_result)
        with JOBS_LOCK:
            JOBS[job_id] = "error"

    except Exception as e:
        err_result = {"error": str(e)}
        save_result(job_id, err_result)
        with JOBS_LOCK:
            JOBS[job_id] = "error"

    finally:
        # Delete temp file
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass

    # Cleanup old results
    threading.Thread(target=cleanup_old, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html", is_cloud=IS_CLOUD)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Receives file, saves it, starts background thread, returns INSTANTLY.
    No more 502 — response is sent before analysis even starts.
    """
    if "file" not in request.files:
        return render_template("error.html", error="No file uploaded.")

    f = request.files["file"]
    if not f or not f.filename:
        return render_template("error.html", error="Empty file submitted.")

    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return render_template("error.html",
            error=f"Unsupported file type '{ext}'. Only APK, EXE, and DLL are supported.")

    # Save file
    safe_name = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
    temp_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(temp_path)

    # Size check
    actual_mb = os.path.getsize(temp_path) / (1024 * 1024)
    if actual_mb > 100:
        os.remove(temp_path)
        return render_template("error.html",
            error=f"File too large ({actual_mb:.1f} MB). Maximum is 100 MB.")

    file_type = detect_file_type(temp_path)
    if file_type == "unknown":
        os.remove(temp_path)
        return render_template("error.html",
            error="File format not recognized. Upload a valid APK, EXE, or DLL.")

    # Create job ID
    job_id = uuid.uuid4().hex
    session["job_id"] = job_id

    # Start analysis in BACKGROUND — page returns immediately
    t = threading.Thread(
        target=_run_analysis,
        args=(job_id, temp_path, file_type),
        daemon=True
    )
    t.start()

    # Return loading page RIGHT AWAY — no waiting
    return render_template("loading.html", job_id=job_id)


@app.route("/status/<job_id>")
def status(job_id: str):
    """Polled by JavaScript every 2 seconds to check if analysis is done."""
    with JOBS_LOCK:
        state = JOBS.get(job_id, "unknown")

    # Also check result file (handles server restart edge case)
    if state == "unknown":
        result = load_result(job_id)
        if result:
            state = "error" if "error" in result and len(result) == 1 else "done"

    return jsonify({"status": state})


@app.route("/report/<job_id>")
def report(job_id: str):
    """Called by JS when status == done. Returns the full report page."""
    result = load_result(job_id)
    if not result:
        return render_template("error.html", error="Result not found. Please re-upload.")
    if "error" in result and len(result) == 1:
        return render_template("error.html", error=result["error"])

    session["job_id"] = job_id
    return render_template("report.html", r=result)


@app.route("/enrich", methods=["POST"])
def enrich():
    """OSINT enrichment — called by JS after report loads."""
    job_id = session.get("job_id", "")
    result = load_result(job_id)
    if not result:
        return jsonify({"enriched_ips": []})

    net        = result.get("network_indicators", {})
    public_ips = net.get("hardcoded_ips", [])
    if not public_ips:
        return jsonify({"enriched_ips": []})

    from osint import enrich_ip_list
    ip_cap   = 5 if IS_CLOUD else 10
    osint_to = 3 if IS_CLOUD else 5
    enriched = enrich_ip_list(public_ips[:ip_cap], ABUSEIPDB_KEY, VT_KEY, timeout=osint_to)

    # Save back
    result["enriched_ips"] = enriched
    save_result(job_id, result)

    return jsonify({"enriched_ips": enriched})


@app.route("/export_pdf", methods=["POST"])
def export_pdf():
    job_id = session.get("job_id", "")
    result = load_result(job_id)
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


@app.errorhandler(413)
def file_too_large(e):
    return render_template("error.html",
        error="File too large. Maximum upload size is 100 MB."), 413


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    port = int(os.getenv("PORT", 5000))

    try:
        lan_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        lan_ip = "localhost"

    print(f"\n  DoubleCheck Intel Platform v2.1")
    print(f"  ─────────────────────────────────")
    print(f"  Open →  http://{lan_ip}:{port}")
    print(f"  Press CTRL+C to stop\n")

    app.run(debug=False, host="0.0.0.0", port=port, use_reloader=False)
