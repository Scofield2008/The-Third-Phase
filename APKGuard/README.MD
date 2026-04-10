# APKGuard — Android Privacy Scanner

> A static analysis tool for Android APK files. Detects dangerous permissions, hardcoded secrets, tracker SDKs, and suspicious network endpoints — all mapped to the OWASP Mobile Top 10.

---

## What It Does

APKGuard performs privacy-focused static analysis on Android APK files without executing the app. It cracks open the APK, reads the compiled bytecode, and flags anything that could compromise a user's privacy.

**Findings include:**

- **Dangerous Permissions** — Camera, microphone, GPS, SMS, contacts, and 15+ others
- **Suspicious Permissions** — Auto-start on boot, overlay windows, background services
- **Hardcoded Secrets** — Google API keys, AWS credentials, Stripe keys, GitHub tokens, Firebase URLs, and 25+ patterns
- **Tracker SDKs** — Facebook Ads, AppsFlyer, Firebase Analytics, TikTok SDK, and 40+ known trackers
- **Network Endpoints** — Hardcoded URLs and IP addresses extracted from bytecode
- **OWASP Mapping** — Every finding tagged to M2, M4, M6, or M8 of the OWASP Mobile Top 10

---

## Features

- Web dashboard — upload via browser, no command line needed
- Async scanning — large APKs (100MB–600MB) scan in the background with a live progress log
- Scan history — all past scans saved to SQLite with risk scores and downloadable reports
- Animated risk gauge — visual score from 0–50 with LOW / MEDIUM / HIGH classification
- Per-finding OWASP tags — every finding mapped to a standard
- Downloadable `.txt` report — full findings exported per scan

---

## Tech Stack

| Component | Tool |
|---|---|
| Language | Python 3.10+ |
| Web framework | Flask |
| APK parsing | androguard |
| Async scanning | Python `threading` |
| Scan history | SQLite (`sqlite3`) |
| Secret detection | `re` (regex patterns) |
| Tracker DB | Custom — based on Exodus Privacy |
| Frontend | HTML/CSS/JS (vanilla) |

---

## Project Structure

```
apkguard/
├── app.py                # Flask server, routes, async job manager
├── scanner.py            # Core scan engine
├── permission.py         # Dangerous + suspicious permission database
├── secret_patterns.py    # Regex patterns for secret detection
├── trackers.py           # 40+ tracker SDK fingerprints
├── templates/
│   ├── index.html        # Upload page
│   ├── scanning.html     # Live progress page
│   ├── results.html      # Results dashboard
│   └── history.html      # Scan history
├── static/
│   └── style.css         # Full design system
├── uploads/              # Temporary APK storage
├── reports/              # Generated .txt reports
├── history.db            # SQLite scan history (auto-created)
└── requirements.txt
```

---

## Installation

**Requirements:** Python 3.10+

```bash
# 1. Clone the repo
git clone https://github.com/Scofield2008/apkguard.git
cd apkguard

# 2. Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Usage

1. Visit `http://127.0.0.1:5000`
2. Upload any Android `.apk` file (up to 600MB)
3. Watch the live scan progress
4. Review findings on the results dashboard
5. Download the full `.txt` report
6. View past scans at `http://127.0.0.1:5000/history`

---

## Risk Scoring

Each finding type contributes to the overall risk score:

| Finding | Score |
|---|---|
| Dangerous permission | +3 per permission |
| Suspicious permission | +1 per permission |
| Hardcoded secret | +5 per secret |
| Tracker SDK | +2 per tracker |
| Suspicious URL | +1 per URL |

| Score Range | Risk Level |
|---|---|
| 0–5 | LOW |
| 6–14 | MEDIUM |
| 15+ | HIGH |

---

## Sample Results

Scanning **VLC for Android:**

```
App:     VLC (org.videolan.vlc) v1.7.5
Risk:    MEDIUM (Score: 9)

Dangerous:   WRITE_EXTERNAL_STORAGE → M2: Insecure Data Storage
Suspicious:  RECEIVE_BOOT_COMPLETED → M8: Security Misconfiguration
Trackers:    None
Secrets:     None
```

---

## OWASP Mobile Top 10 Coverage

| OWASP Risk | What APKGuard Checks |
|---|---|
| M2: Insecure Data Storage | Storage permissions, credential secrets |
| M4: Insufficient Input Validation | Biometric bypass permissions |
| M6: Insufficient Privacy Controls | Location, camera, mic, SMS permissions + trackers |
| M8: Security Misconfiguration | Auto-start, overlay, package install permissions + suspicious URLs |

---

## requirements.txt

```
androguard==3.3.5
flask
rich
```

---

## Roadmap

- [ ] PDF report export
- [ ] CVSS-style combined permission scoring (e.g. CAMERA + RECORD_AUDIO + INTERNET = higher risk)
- [ ] Batch scan — analyse a folder of APKs at once
- [ ] APK version diffing — compare two versions of the same app
- [ ] Docker container for one-command deployment
- [ ] Certificate analysis — debug vs release signing check

---

## Author

**Scofield Lori**  
Cybersecurity student, Veritas University Abuja  
SOC Analyst track | Static analysis | Threat detection

GitHub: [github.com/Scofield2008](https://github.com/Scofield2008)  
LinkedIn: [linkedin.com/in/scofield-lori-965a01258](https://linkedin.com/in/scofield-lori-965a01258)

---

## Disclaimer

APKGuard is a static analysis tool intended for security research, privacy auditing, and educational purposes. Only analyse APKs you own or have explicit permission to test.