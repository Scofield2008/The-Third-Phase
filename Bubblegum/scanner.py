import os
import re
import zipfile
import threading
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from permission import DANGEROUS_PERMISSIONS, SUSPICIOUS_PERMISSIONS
from secret_patterns import scan_strings_for_secrets
from trackers import scan_classes_for_trackers

OWASP_MAP = {
    "READ_CONTACTS":              "M2: Insecure Data Storage",
    "WRITE_CONTACTS":             "M2: Insecure Data Storage",
    "READ_CALL_LOG":              "M2: Insecure Data Storage",
    "READ_SMS":                   "M2: Insecure Data Storage",
    "RECEIVE_SMS":                "M6: Insufficient Privacy Controls",
    "SEND_SMS":                   "M6: Insufficient Privacy Controls",
    "RECORD_AUDIO":               "M6: Insufficient Privacy Controls",
    "CAMERA":                     "M6: Insufficient Privacy Controls",
    "ACCESS_FINE_LOCATION":       "M6: Insufficient Privacy Controls",
    "ACCESS_COARSE_LOCATION":     "M6: Insufficient Privacy Controls",
    "ACCESS_BACKGROUND_LOCATION": "M6: Insufficient Privacy Controls",
    "READ_EXTERNAL_STORAGE":      "M2: Insecure Data Storage",
    "WRITE_EXTERNAL_STORAGE":     "M2: Insecure Data Storage",
    "READ_PHONE_STATE":           "M6: Insufficient Privacy Controls",
    "PROCESS_OUTGOING_CALLS":     "M6: Insufficient Privacy Controls",
    "INSTALL_PACKAGES":           "M8: Security Misconfiguration",
    "REQUEST_INSTALL_PACKAGES":   "M8: Security Misconfiguration",
    "GET_ACCOUNTS":               "M2: Insecure Data Storage",
    "USE_BIOMETRIC":              "M4: Insufficient Input/Output Validation",
    "SYSTEM_ALERT_WINDOW":        "M8: Security Misconfiguration",
    "RECEIVE_BOOT_COMPLETED":     "M8: Security Misconfiguration",
    "DISABLE_KEYGUARD":           "M8: Security Misconfiguration",
}

URL_PATTERN = re.compile(r'https?://[^\s\'"<>{}\[\]\\]{8,}')
IP_PATTERN  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

KNOWN_CDN = [
    "googleapis.com", "gstatic.com", "android.com", "google.com",
    "firebase.google", "crashlytics.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "fastly.net", "w3.org", "schema.org",
    "mozilla.org", "apache.org", "example.com", "localhost",
]

DEX_TIMEOUT = 45  # seconds per dex file


def _parse_dex_safe(dex_bytes, result_holder, label):
    """Parse a single dex file in a thread — times out if too slow."""
    try:
        dex = DalvikVMFormat(dex_bytes)
        result_holder[label] = dex
    except Exception:
        result_holder[label] = None


def load_dex_files(apk_path, progress_cb=None):
    """
    Extract and parse DEX files from APK using zipfile.
    Each dex is parsed in a thread with a timeout — so huge APKs
    (like TikTok) don't hang forever; we just skip dex files that
    exceed the timeout and keep going.
    """
    dex_list = []
    with zipfile.ZipFile(apk_path, 'r') as zf:
        dex_names = sorted([n for n in zf.namelist()
                            if re.match(r'classes\d*\.dex', n)])
        total = len(dex_names)
        for i, name in enumerate(dex_names):
            if progress_cb:
                progress_cb(f"Parsing {name} ({i+1}/{total})...")
            try:
                dex_bytes = zf.read(name)
                holder = {}
                t = threading.Thread(target=_parse_dex_safe,
                                     args=(dex_bytes, holder, name))
                t.start()
                t.join(timeout=DEX_TIMEOUT)
                if t.is_alive():
                    # Timed out — skip this dex
                    if progress_cb:
                        progress_cb(f"Skipped {name} (too large, timeout)")
                    continue
                if holder.get(name):
                    dex_list.append(holder[name])
            except Exception:
                continue
    return dex_list


def scan_apk(apk_path, progress_cb=None):
    """
    Full APK scan. progress_cb(message) is called at each stage
    so the UI can show real-time updates.
    """
    def prog(msg):
        if progress_cb:
            progress_cb(msg)

    result = {
        "app_name"   : "Unknown",
        "package"    : "unknown",
        "version"    : "?",
        "min_sdk"    : "?",
        "target_sdk" : "?",
        "file_size"  : round(os.path.getsize(apk_path) / (1024*1024), 1),
        "dangerous"  : [],
        "suspicious" : [],
        "normal"     : [],
        "secrets"    : [],
        "trackers"   : [],
        "urls"       : [],
        "ips"        : [],
        "risk_score" : 0,
        "risk_level" : "LOW",
        "dex_count"  : 0,
        "string_count": 0,
        "class_count" : 0,
    }

    # ── Step 1: Parse manifest (fast — APK class only) ───────
    prog("Parsing AndroidManifest.xml...")
    try:
        a = APK(apk_path)
        result["app_name"]   = a.get_app_name() or "Unknown"
        result["package"]    = a.get_package() or "unknown"
        result["version"]    = a.get_androidversion_name() or "?"
        result["min_sdk"]    = a.get_min_sdk_version() or "?"
        result["target_sdk"] = a.get_target_sdk_version() or "?"
    except Exception as e:
        result["error"] = str(e)
        return result

    # ── Step 2: Permissions ───────────────────────────────────
    prog("Analysing permissions...")
    try:
        for perm in a.get_permissions():
            short = perm.replace("android.permission.", "")
            owasp = OWASP_MAP.get(short, "")
            if perm in DANGEROUS_PERMISSIONS:
                result["dangerous"].append({
                    "name": short,
                    "desc": DANGEROUS_PERMISSIONS[perm],
                    "owasp": owasp,
                })
            elif perm in SUSPICIOUS_PERMISSIONS:
                result["suspicious"].append({
                    "name": short,
                    "desc": SUSPICIOUS_PERMISSIONS[perm],
                    "owasp": owasp,
                })
            else:
                result["normal"].append(perm)
    except Exception:
        pass

    # ── Step 3: Load DEX files ────────────────────────────────
    prog("Loading DEX bytecode (this takes longest for large APKs)...")
    dex_files = load_dex_files(apk_path, progress_cb=prog)
    result["dex_count"] = len(dex_files)

    # ── Step 4: Extract strings ───────────────────────────────
    prog("Extracting strings from bytecode...")
    all_strings = []
    for dex in dex_files:
        try:
            for s in dex.get_strings():
                all_strings.append(str(s))
        except Exception:
            continue
    result["string_count"] = len(all_strings)

    # ── Step 5: Secret scan ───────────────────────────────────
    prog(f"Scanning {len(all_strings):,} strings for secrets...")
    for label, val in scan_strings_for_secrets(all_strings):
        result["secrets"].append({"type": label, "value": val})

    # ── Step 6: URL/IP extraction ─────────────────────────────
    prog("Extracting network endpoints...")
    seen_urls = set()
    seen_ips  = set()
    for s in all_strings:
        for url in URL_PATTERN.findall(s):
            url_clean = url.rstrip('.,;)')
            if url_clean not in seen_urls:
                is_cdn = any(cdn in url_clean for cdn in KNOWN_CDN)
                seen_urls.add(url_clean)
                result["urls"].append({
                    "url": url_clean[:120],
                    "suspicious": not is_cdn,
                })
        for ip in IP_PATTERN.findall(s):
            if ip not in seen_ips and not ip.startswith(('127.', '0.0.', '255.')):
                seen_ips.add(ip)
                result["ips"].append(ip)

    # limit display to 40 urls
    result["urls"] = sorted(result["urls"], key=lambda x: x["suspicious"], reverse=True)[:40]
    result["ips"]  = result["ips"][:20]

    # ── Step 7: Tracker scan ──────────────────────────────────
    prog("Scanning class names for tracker SDKs...")
    all_classes = []
    for dex in dex_files:
        try:
            for cls in dex.get_classes():
                all_classes.append(cls.get_name())
        except Exception:
            continue
    result["class_count"] = len(all_classes)

    for sig, label in scan_classes_for_trackers(all_classes):
        result["trackers"].append({"package": sig, "label": label})

    # ── Step 8: Risk score ────────────────────────────────────
    prog("Calculating risk score...")
    sus_urls = len([u for u in result["urls"] if u["suspicious"]])
    score = (len(result["dangerous"])  * 3) + \
            (len(result["suspicious"]) * 1) + \
            (len(result["secrets"])    * 5) + \
            (len(result["trackers"])   * 2) + \
            (sus_urls                  * 1)

    result["risk_score"] = score
    result["risk_level"] = "HIGH" if score >= 15 else "MEDIUM" if score >= 6 else "LOW"

    prog("Done.")
    return result