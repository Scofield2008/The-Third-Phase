import re

SECRET_PATTERNS = [
    ("Google API Key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth Token",  re.compile(r"ya29\.[0-9A-Za-z\-_]+")),
    ("AWS Access Key ID",   re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token",        re.compile(r"ghp_[0-9a-zA-Z]{36}")),
    ("GitHub OAuth",        re.compile(r"gho_[0-9a-zA-Z]{36}")),
    ("Slack Token",         re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
    ("Stripe Live Key",     re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("Firebase URL",        re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("Private Key Block",   re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")),
    ("Bearer Token",        re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}")),
    ("SendGrid API Key",    re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}")),
    ("Twilio Account SID",  re.compile(r"AC[a-z0-9]{32}")),
    ("Mapbox Token",        re.compile(r"pk\.eyJ1Ijoi[A-Za-z0-9\-_]+")),
    ("Generic Secret",      re.compile(r"(?i)(secret|api_key|apikey|token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]")),
]

# Known false positive fragments — skip any match containing these
FP_BLOCKLIST = [
    "AppCompat", "FEATURE_", "android.", "layout_", "wrap_content",
    "match_parent", "xmlns", "http://schemas", "TextView", "Fragment",
    "Activity", "Service", "Receiver", "Provider", "Intent", "Bundle",
    "Context", "String", "Integer", "Boolean", ".class", "Ljava",
    "Landroid", "dalvik", "okhttp", "retrofit", "glide", "picasso",
]

MIN_SECRET_LENGTH = 16


def scan_strings_for_secrets(string_list):
    findings = []
    seen = set()

    for s in string_list:
        if not s or len(s) < MIN_SECRET_LENGTH:
            continue

        # Skip known false positive fragments
        if any(fp in s for fp in FP_BLOCKLIST):
            continue

        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(s)
            if match:
                val = match.group(0)
                key = (label, val[:40])
                if key not in seen:
                    seen.add(key)
                    findings.append((label, val[:80]))
    return findings