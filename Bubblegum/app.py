import os
import uuid
import threading
import sqlite3
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, \
                  send_file, jsonify
from scanner import scan_apk

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
DB_PATH       = "history.db"
MAX_SIZE_MB   = 600  # supports TikTok-sized APKs

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# In-memory job store  {job_id: {status, progress, result, error}}
JOBS = {}
JOBS_LOCK = threading.Lock()


# ── Database setup ────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            app_name  TEXT,
            package   TEXT,
            version   TEXT,
            file_size REAL,
            risk_score INTEGER,
            risk_level TEXT,
            dangerous  INTEGER,
            suspicious INTEGER,
            secrets    INTEGER,
            trackers   INTEGER,
            report_name TEXT
        )
    """)
    con.commit()
    con.close()


def save_to_history(result, report_name):
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT INTO scans
        (timestamp, app_name, package, version, file_size,
         risk_score, risk_level, dangerous, suspicious, secrets, trackers, report_name)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        result["app_name"], result["package"], result["version"],
        result["file_size"], result["risk_score"], result["risk_level"],
        len(result["dangerous"]), len(result["suspicious"]),
        len(result["secrets"]), len(result["trackers"]),
        report_name,
    ))
    con.commit()
    con.close()


init_db()


# ── Background scan worker ────────────────────────────────────
def run_scan_job(job_id, apk_path):
    def progress(msg):
        with JOBS_LOCK:
            JOBS[job_id]["progress"] = msg

    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["progress"] = "Starting scan..."

    try:
        result = scan_apk(apk_path, progress_cb=progress)

        # Save report
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_pkg    = "".join(c for c in result["package"] if c.isalnum() or c in "._-")
        report_name = f"{safe_pkg}_{timestamp}.txt"
        report_path = os.path.join(REPORT_FOLDER, report_name)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("APKGuard Privacy Scan Report\n")
            f.write(f"Generated  : {datetime.now()}\n")
            f.write(f"App        : {result['app_name']} ({result['package']})\n")
            f.write(f"Version    : {result['version']}\n")
            f.write(f"File Size  : {result['file_size']}MB\n")
            f.write(f"Risk Score : {result['risk_score']} — {result['risk_level']}\n")
            f.write(f"DEX files  : {result['dex_count']}\n")
            f.write(f"Strings    : {result['string_count']:,}\n")
            f.write(f"Classes    : {result['class_count']:,}\n\n")
            f.write("═" * 50 + "\n")

            f.write("\nDANGEROUS PERMISSIONS:\n")
            for p in result["dangerous"]:
                f.write(f"  [!] {p['name']}\n      {p['desc']}\n      OWASP: {p['owasp']}\n")

            f.write("\nSUSPICIOUS PERMISSIONS:\n")
            for p in result["suspicious"]:
                f.write(f"  [~] {p['name']}\n      {p['desc']}\n")

            f.write("\nHARDCODED SECRETS:\n")
            for s in result["secrets"]:
                f.write(f"  [!] {s['type']}: {s['value']}\n")

            f.write("\nTRACKER SDKs:\n")
            for t in result["trackers"]:
                f.write(f"  [T] {t['package']}\n      {t['label']}\n")

            f.write("\nSUSPICIOUS URLs:\n")
            for u in result["urls"]:
                if u["suspicious"]:
                    f.write(f"  [U] {u['url']}\n")

            f.write("\nHARDCODED IPs:\n")
            for ip in result["ips"]:
                f.write(f"  [IP] {ip}\n")

            f.write("\nNORMAL PERMISSIONS:\n")
            for p in result["normal"]:
                f.write(f"  [ ] {p}\n")

        result["report_name"] = report_name
        save_to_history(result, report_name)

        with JOBS_LOCK:
            JOBS[job_id]["status"]   = "done"
            JOBS[job_id]["result"]   = result
            JOBS[job_id]["progress"] = "Scan complete."

    except Exception as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"]  = str(e)


# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "apk" not in request.files:
        return redirect(url_for("index"))

    file = request.files["apk"]

    if not file.filename.lower().endswith(".apk"):
        return render_template("index.html",
                               error="Please upload a valid .apk file.")

    # Size check
    file.seek(0, 2)
    size_mb = file.tell() / (1024 * 1024)
    file.seek(0)
    if size_mb > MAX_SIZE_MB:
        return render_template("index.html",
            error=f"File too large ({size_mb:.0f}MB). Maximum is {MAX_SIZE_MB}MB.")

    # Save file
    safe_name = "".join(c for c in file.filename if c.isalnum() or c in "._-")
    apk_path  = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(apk_path)

    # Create job
    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status"  : "queued",
            "progress": "Queued...",
            "result"  : None,
            "error"   : None,
            "filename": file.filename,
            "size_mb" : round(size_mb, 1),
        }

    # Start background thread
    t = threading.Thread(target=run_scan_job, args=(job_id, apk_path), daemon=True)
    t.start()

    return redirect(url_for("scanning", job_id=job_id))


@app.route("/scanning/<job_id>")
def scanning(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return redirect(url_for("index"))
    return render_template("scanning.html", job_id=job_id,
                           filename=job["filename"], size_mb=job["size_mb"])


@app.route("/status/<job_id>")
def status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"status": "not_found"})
    return jsonify({
        "status"  : job["status"],
        "progress": job["progress"],
        "error"   : job["error"],
    })


@app.route("/results/<job_id>")
def results(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return redirect(url_for("scanning", job_id=job_id))
    return render_template("results.html", r=job["result"])


@app.route("/history")
def history():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 50"
    ).fetchall()
    con.close()
    return render_template("history.html", scans=rows)


@app.route("/download/<filename>")
def download(filename):
    safe = "".join(c for c in filename if c.isalnum() or c in "._-")
    path = os.path.join(REPORT_FOLDER, safe)
    if not os.path.exists(path):
        return "Report not found", 404
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)