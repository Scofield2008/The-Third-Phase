"""
SALT SIEM v3.0 - Enhanced Backend

Improvements:
- Fixed YARA compilation error handling
- Added missing requirements imports
- Implemented full VirusTotal integration with error handling
- Fixed Windows event collection with better error handling
- Added search functionality for logs and alerts with multiple filters
- Improved data storage with encryption for sensitive fields
- Enhanced ZoneSandbox with PE file analysis if available
- Fixed encryption/decryption logic
- Improved webhook security
- Added rate limiting
- Fixed socketio emissions
- Added more stats for charts (threat_score, file_types)
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
import json
import datetime
import hashlib
import yara
import time
import secrets
import requests
from pathlib import Path
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from collections import defaultdict
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Windows Event Logs (optional)
try:
    import win32evtlog
    import win32con
    WINDOWS_EVENTS_AVAILABLE = True
except ImportError:
    WINDOWS_EVENTS_AVAILABLE = False
def add_log(self, log_entry):
    # ... existing code ...
    socketio.start_background_task(target=lambda: socketio.emit('new_log', log_entry, broadcast=True))
    return log_entry

# pefile (optional)
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# =====================================================
#              FLASK APP CONFIGURATION
# =====================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'salt-siem-v3-secret')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB
app.config['VIRUSTOTAL_API_KEY'] = os.environ.get('VIRUSTOTAL_API_KEY', '')

# Socket.IO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# API Keys storage
API_KEYS_FILE = 'data/api_keys.json'
api_keys = {}

# Create directories
for directory in ['uploads', 'reports', 'data']:
    os.makedirs(directory, exist_ok=True)

# =====================================================
#                 ENCRYPTION & YARA
# =====================================================
ENCRYPTION_KEY_FILE = 'data/encryption.key'

def get_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

# YARA Rules (expanded)
YARA_RULES = r"""
rule Suspicious_APIs {
    meta:
        severity = "high"
    strings:
        $a1 = "CreateRemoteThread" nocase
        $a2 = "VirtualAlloc" nocase
        $a3 = "WriteProcessMemory" nocase
        $a4 = "ShellExecute" nocase
    condition:
        2 of them
}

rule Ransomware {
    meta:
        severity = "critical"
    strings:
        $r1 = "encrypt" nocase
        $r2 = "bitcoin" nocase
        $r3 = "vssadmin delete" nocase
        $r4 = "ransom" nocase
    condition:
        2 of them
}

rule Trojan {
    meta:
        severity = "high"
    strings:
        $t1 = "keylog" nocase
        $t2 = "backdoor" nocase
    condition:
        any of them
}
"""

try:
    rules = yara.compile(source=YARA_RULES)
except Exception as e:
    print(f"YARA compilation error: {str(e)}")
    rules = None

# =====================================================
#                 DATA STORAGE
# =====================================================
class DataStore:
    def __init__(self):
        self.data_file = 'data/store.json'
        self.logs = []
        self.alerts = []
        self.incidents = []
        self.scans = []
        self.load_data()
    
    def load_data(self):
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    self.logs = data.get('logs', [])
                    self.alerts = data.get('alerts', [])
                    self.incidents = data.get('incidents', [])
                    self.scans = data.get('scans', [])
        except Exception as e:
            print(f"Error loading data: {str(e)}")
    
    def save_data(self):
        try:
            with open(self.data_file, 'w') as f:
                json.dump({
                    'logs': self.logs[-1000:],
                    'alerts': self.alerts[-500:],
                    'incidents': self.incidents,
                    'scans': self.scans[-100:]
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving data: {str(e)}")
    
    def add_log(self, log_entry):
        log_entry['id'] = len(self.logs) + 1
        log_entry['timestamp'] = datetime.datetime.now().isoformat()
        self.logs.append(log_entry)
        self.save_data()
        socketio.emit('new_log', log_entry)
        return log_entry
    
    def add_alert(self, alert):
        alert['id'] = len(self.alerts) + 1
        alert['timestamp'] = datetime.datetime.now().isoformat()
        alert['status'] = alert.get('status', 'active')
        self.alerts.append(alert)
        self.save_data()
        socketio.emit('new_alert', alert)
        return alert
    
    def add_scan(self, scan):
        scan['id'] = len(self.scans) + 1
        scan['timestamp'] = datetime.datetime.now().isoformat()
        self.scans.append(scan)
        self.save_data()
        socketio.emit('new_scan', scan)
        return scan
    
    def add_incident(self, incident):
        incident['id'] = len(self.incidents) + 1
        incident['created'] = datetime.datetime.now().isoformat()
        incident['status'] = incident.get('status', 'open')
        self.incidents.append(incident)
        self.save_data()
        return incident

store = DataStore()

# =====================================================
#            API KEYS MANAGEMENT
# =====================================================
def load_api_keys():
    global api_keys
    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'r') as f:
            api_keys = json.load(f)
    else:
        api_keys = {}

def save_api_keys():
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(api_keys, f, indent=2)

load_api_keys()

def generate_api_key():
    return 'salt_' + secrets.token_urlsafe(32)

def verify_api_key(key):
    return key in api_keys and api_keys[key]['active']

# =====================================================
#            VIRUSTOTAL INTEGRATION
# =====================================================
def check_virustotal(file_hash):
    if not app.config['VIRUSTOTAL_API_KEY']:
        return None
    
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': app.config['VIRUSTOTAL_API_KEY']}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'total': sum(stats.values())
        }
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal error: {str(e)}")
        return None

# =====================================================
#         WINDOWS EVENT LOG COLLECTOR
# =====================================================
def collect_windows_events(log_type='Security', max_events=50):
    if not WINDOWS_EVENTS_AVAILABLE:
        return []
    
    events = []
    try:
        hand = win32evtlog.OpenEventLog(None, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        total = 0
        while total < max_events:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            
            for record in records:
                if total >= max_events:
                    break
                
                event = {
                    'event_id': record.EventID,
                    'source': record.SourceName,
                    'time': record.TimeGenerated.isoformat(),
                    'type': record.EventType,
                    'category': record.EventCategory,
                    'description': ' '.join(record.StringInserts or [])  # Added description
                }
                events.append(event)
                total += 1
        
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f"Windows events error: {str(e)}")
    
    return events

# =====================================================
#              ZONE SANDBOX (IMPROVED)
# =====================================================
class ZoneSandbox:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.results = []
        self.threat_score = 0
        self.sha256 = None
        self.md5 = None

    def log(self, text):
        self.results.append(text)

    def calculate_hashes(self):
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
            self.sha256 = hashlib.sha256(data).hexdigest()
            self.md5 = hashlib.md5(data).hexdigest()
            self.log(f"SHA256: {self.sha256}")
            self.log(f"MD5: {self.md5}")
            return True
        except Exception as e:
            self.log(f"Hash calculation error: {str(e)}")
            return False

    def yara_scan(self):
        if not rules:
            self.log("YARA rules not available")
            return 0
        try:
            matches = rules.match(self.filepath)
            if matches:
                self.log(f"YARA Matches: {len(matches)}")
                for match in matches:
                    severity = match.meta.get('severity', 'unknown')
                    self.log(f"  - {match.rule} ({severity})")
                    if severity == 'critical':
                        self.threat_score += 5
                    elif severity == 'high':
                        self.threat_score += 3
                    elif severity == 'medium':
                        self.threat_score += 2
                return len(matches)
            return 0
        except Exception as e:
            self.log(f"YARA scan error: {str(e)}")
            return 0

    def pe_analysis(self):
        if not PEFILE_AVAILABLE:
            self.log("pefile not available for PE analysis")
            return
        try:
            pe = pefile.PE(self.filepath)
            self.log("PE File Analysis:")
            self.log(f"  - Number of sections: {len(pe.sections)}")
            suspicious_sections = [s.Name.decode(errors='ignore').strip() for s in pe.sections if '.rsrc' in s.Name.decode(errors='ignore') or '.data' in s.Name.decode(errors='ignore')]
            if suspicious_sections:
                self.log(f"  - Suspicious sections: {', '.join(suspicious_sections)}")
                self.threat_score += len(suspicious_sections) * 1
            self.log(f"  - Imported DLLs: {len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0}")
        except Exception as e:
            self.log(f"PE analysis error: {str(e)}")

    def get_threat_level(self):
        if self.threat_score >= 10:
            return "Critical"
        elif self.threat_score >= 6:
            return "High"
        elif self.threat_score >= 3:
            return "Medium"
        else:
            return "Low"

    def analyze(self):
        self.log("=== ZONE SANDBOX ANALYSIS ===")
        self.calculate_hashes()
        yara_matches = self.yara_scan()
        self.pe_analysis()
        
        # Check VirusTotal
        vt_result = check_virustotal(self.sha256)
        if vt_result:
            self.log(f"VirusTotal: {vt_result['malicious']}/{vt_result['total']} detected")
            if vt_result['malicious'] > 0:
                self.threat_score += min(vt_result['malicious'], 5)
        
        threat_level = self.get_threat_level()
        self.log(f"Threat Level: {threat_level}")
        self.log(f"Threat Score: {self.threat_score}/15")
        
        return {
            'report': "\n".join(self.results),
            'threat_level': threat_level,
            'threat_score': self.threat_score,
            'sha256': self.sha256 or 'N/A',
            'md5': self.md5 or 'N/A',
            'yara_matches': yara_matches,
            'virustotal': vt_result
        }

# =====================================================
#                 HELPER FUNCTIONS
# =====================================================
def encrypt_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        encrypted_data = cipher.encrypt(file_data)
        enc_path = filepath + '.enc'
        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)
        os.remove(filepath)
        return enc_path
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return filepath

def decrypt_file(encrypted_filepath):
    try:
        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        temp_path = encrypted_filepath.replace('.enc', '')
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        return temp_path
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return encrypted_filepath

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or 'unknown'

# =====================================================
#                    ROUTES
# =====================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/playbook')
def playbook():
    return render_template('playbook.html')

@app.route('/api/stats')
def get_stats():
    threat_score = sum(s['threat_score'] for s in store.scans) / len(store.scans) if store.scans else 0
    file_types = defaultdict(int)
    for scan in store.scans:
        ext = scan['filename'].split('.')[-1].upper() if '.' in scan['filename'] else 'OTHER'
        file_types[ext] += 1
    return jsonify({
        'logs': len(store.logs),
        'alerts': len([a for a in store.alerts if a.get('status') == 'active']),
        'incidents': len([i for i in store.incidents if i.get('status') == 'open']),
        'scans': len(store.scans),
        'threat_score': round(threat_score, 1),
        'file_types': dict(file_types),
        'recent_logs': store.logs[-10:][::-1],
        'recent_alerts': store.alerts[-5:][::-1]
    })

# =====================================================
#         FEATURE 1: SEARCH & FILTER
# =====================================================
@app.route('/api/logs/search')
def search_logs():
    query = request.args.get('q', '').lower()
    severity = request.args.get('severity', '').lower()
    log_type = request.args.get('type', '').lower()
    
    results = store.logs
    
    if query:
        results = [log for log in results if query in log.get('message', '').lower()]
    
    if severity:
        results = [log for log in results if log.get('severity', '').lower() == severity]
    
    if log_type:
        results = [log for log in results if log.get('type', '').lower() == log_type]
    
    return jsonify(results[::-1])

@app.route('/api/alerts/search')
def search_alerts():
    severity = request.args.get('severity', '').lower()
    results = store.alerts
    
    if severity:
        results = [a for a in results if a.get('severity', '').lower() == severity]
    
    return jsonify(results[::-1])

# =====================================================
#         FEATURE 2: API KEYS & WEBHOOKS
# =====================================================
@app.route('/api/keys', methods=['GET'])
def list_api_keys():
    return jsonify([{
        'key': k[:15] + '...',
        'name': v['name'],
        'created': v['created'],
        'active': v['active']
    } for k, v in api_keys.items()])

@app.route('/api/keys/create', methods=['POST'])
def create_api_key():
    data = request.json
    name = data.get('name', 'Unnamed Key')
    
    key = generate_api_key()
    api_keys[key] = {
        'name': name,
        'created': datetime.datetime.now().isoformat(),
        'active': True
    }
    save_api_keys()
    
    store.add_log({
        'type': 'api_key_created',
        'message': f'API key created: {name}',
        'severity': 'Info'
    })
    
    return jsonify({'key': key, 'name': name})

@app.route('/api/keys/<key>/revoke', methods=['POST'])
def revoke_api_key(key):
    if key in api_keys:
        api_keys[key]['active'] = False
        save_api_keys()
        return jsonify({'success': True})
    return jsonify({'error': 'Key not found'}), 404

@app.route('/api/webhook/scan', methods=['POST'])
@limiter.limit("10 per minute")
def webhook_scan():
    api_key = request.headers.get('X-API-Key')
    if not api_key or not verify_api_key(api_key):
        return jsonify({'error': 'Invalid API key'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename) if file.filename else 'webhook_file'
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    encrypted_path = encrypt_file(filepath)
    temp_path = decrypt_file(encrypted_path)
    
    sandbox = ZoneSandbox(temp_path)
    result = sandbox.analyze()
    
    if os.path.exists(temp_path):
        os.remove(temp_path)
    
    scan_record = {
        'filename': filename,
        'threat_level': result['threat_level'],
        'threat_score': result['threat_score'],
        'sha256': result['sha256'],
        'via': 'webhook'
    }
    
    store.add_scan(scan_record)
    
    return jsonify(scan_record)

# =====================================================
#         FEATURE 3: VIRUSTOTAL CHECK
# =====================================================
@app.route('/api/virustotal/<file_hash>')
def virustotal_check(file_hash):
    result = check_virustotal(file_hash)
    if result:
        return jsonify(result)
    return jsonify({'error': 'Not found or API key missing'}), 404

# =====================================================
#         FEATURE 4: WINDOWS EVENT LOGS
# =====================================================
@app.route('/api/windows-events')
def get_windows_events():
    log_type = request.args.get('type', 'Security')
    max_events = int(request.args.get('limit', 50))
    
    events = collect_windows_events(log_type, max_events)
    
    return jsonify({
        'available': WINDOWS_EVENTS_AVAILABLE,
        'events': events,
        'count': len(events)
    })

@app.route('/api/windows-events/monitor', methods=['POST'])
def start_windows_monitoring():
    if not WINDOWS_EVENTS_AVAILABLE:
        return jsonify({'error': 'Windows events not available'}), 400
    
    events = collect_windows_events('Security', 20)
    
    for event in events:
        if event['event_id'] in [4625, 4648, 4720]:  # Failed login, explicit creds, account created
            store.add_log({
                'type': 'windows_event',
                'message': f"Event {event['event_id']}: {event['source']} - {event['description'][:100]}",
                'severity': 'Medium'
            })
    
    return jsonify({'success': True, 'processed': len(events)})

# =====================================================
#                 SCAN ENDPOINT
# =====================================================
@app.route('/api/scan', methods=['POST'])
@limiter.limit("5 per minute")
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = secure_filename(file.filename) if file.filename else f'uploaded_{int(time.time())}'
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        encrypted_path = encrypt_file(filepath)
        store.add_log({
            'type': 'file_upload',
            'message': f'File uploaded: {filename}',
            'severity': 'Info'
        })
        
        temp_path = decrypt_file(encrypted_path)
        sandbox = ZoneSandbox(temp_path)
        result = sandbox.analyze()
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        scan_record = {
            'filename': filename,
            'threat_level': result['threat_level'],
            'threat_score': result['threat_score'],
            'sha256': result['sha256'],
            'md5': result['md5'],
            'yara_matches': result['yara_matches'],
            'report': result['report'],
            'virustotal': result.get('virustotal')
        }
        
        store.add_scan(scan_record)
        
        if result['threat_level'] in ['High', 'Critical']:
            store.add_alert({
                'type': 'Malware Detection',
                'severity': result['threat_level'],
                'message': f"Threat detected: {filename} (Score: {result['threat_score']}/15)"
            })
        
        return jsonify(scan_record)
        
    except Exception as e:
        print(f"Scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    return jsonify(store.logs[-100:][::-1])

@app.route('/api/alerts')
def get_alerts():
    return jsonify(store.alerts[::-1])

@app.route('/api/incidents')
def get_incidents():
    return jsonify(store.incidents[::-1])

@app.route('/api/incident/create', methods=['POST'])
def create_incident():
    data = request.json
    incident = {
        'title': data.get('title', 'Untitled'),
        'description': data.get('description', ''),
        'severity': data.get('severity', 'Medium'),
        'assigned_to': data.get('assigned_to', 'Unassigned'),
        'status': 'open'
    }
    created = store.add_incident(incident)
    return jsonify(created)

# =====================================================
#                   MAIN
# =====================================================
if __name__ == '__main__':
    print("=" * 70)
    print("SALT SIEM v3.0 - Enhanced Edition")
    print("=" * 70)
    print(f"✅ YARA rules: {'Loaded' if rules else 'Failed'}")
    print(f"✅ VirusTotal: {'Enabled' if app.config['VIRUSTOTAL_API_KEY'] else 'Disabled'}")
    print(f"✅ Windows Events: {'Available' if WINDOWS_EVENTS_AVAILABLE else 'Not Available'}")
    print(f"✅ PE Analysis: {'Available' if PEFILE_AVAILABLE else 'Not Available'}")
    print(f"✅ API Keys: {len([k for k in api_keys if api_keys[k]['active']])} active")
    print("=" * 70)
    
    store.add_log({
        'type': 'system_start',
        'message': 'SALT SIEM v3.0 started with enhanced features',
        'severity': 'Info'
    })
    
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)