# app.py - COMPLETE FINAL VERSION
import os
import secrets
import datetime
import sqlite3
import threading
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import mimetypes

# Optional imports
try:
    import qrcode
    from io import BytesIO
    import base64
    QR_AVAILABLE = True
except:
    QR_AVAILABLE = False

try:
    from PIL import Image
    PREVIEW_AVAILABLE = True
except:
    PREVIEW_AVAILABLE = False

try:
    import subprocess
    CLAMAV_AVAILABLE = True
except:
    CLAMAV_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['DEBUG'] = True
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PREVIEW_FOLDER'] = 'previews'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PREVIEW_FOLDER'], exist_ok=True)

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://", default_limits=["1000 per day"])

db_lock = threading.Lock()

def get_db_connection():
    conn = sqlite3.connect('secureshare.db', timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    expiry DATETIME NOT NULL,
                    max_downloads INTEGER NOT NULL,
                    current_downloads INTEGER DEFAULT 0,
                    salt TEXT,
                    iv TEXT NOT NULL,
                    password_protected BOOLEAN DEFAULT 0,
                    rsa_public_key TEXT,
                    encrypted_aes_key TEXT,
                    rsa_private_key_hash TEXT,
                    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER DEFAULT 0,
                    mime_type TEXT,
                    virus_scan_status TEXT DEFAULT 'skipped',
                    has_preview BOOLEAN DEFAULT 0,
                    preview_path TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT,
                    action TEXT,
                    ip_address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_expiry ON files(expiry)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_id ON audit_logs(file_id)')
            conn.commit()
            print("✓ Database initialized")
        finally:
            conn.close()

init_database()

def log_audit(file_id, action, ip):
    try:
        with db_lock:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO audit_logs (file_id, action, ip_address) VALUES (?, ?, ?)', (file_id, action, ip))
                conn.commit()
            finally:
                conn.close()
    except:
        pass

def scan_with_clamav(file_path):
    if not CLAMAV_AVAILABLE:
        return True, "ClamAV not available"
    try:
        result = subprocess.run(['clamscan', '--no-summary', file_path], capture_output=True, text=True, timeout=30)
        return result.returncode == 0, "Clean" if result.returncode == 0 else "Infected"
    except:
        return True, "Scan unavailable"

def create_preview(file_path, mime_type):
    if not PREVIEW_AVAILABLE or not mime_type or not mime_type.startswith('image/'):
        return None
    try:
        img = Image.open(file_path)
        img.thumbnail((400, 400), Image.Resampling.LANCZOS)
        preview_path = os.path.join(app.config['PREVIEW_FOLDER'], os.path.basename(file_path) + '_preview.jpg')
        if img.mode in ('RGBA', 'LA', 'P'):
            bg = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            bg.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = bg
        img.save(preview_path, 'JPEG', quality=85)
        return preview_path
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<file_id>')
def download_page(file_id):
    return render_template('download.html', file_id=file_id)

@app.route('/api/upload', methods=['POST'])
@limiter.limit("100 per hour")
def upload_file():
    if 'encrypted' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    encrypted_file = request.files['encrypted']
    if not encrypted_file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    try:
        expiry_type = request.form.get('expiry_type', 'hours')
        if expiry_type == 'custom':
            expiry_str = request.form.get('custom_expiry', '')
            if not expiry_str:
                return jsonify({'success': False, 'error': 'Custom expiry required'}), 400
            expiry = datetime.datetime.fromisoformat(expiry_str.replace('Z', ''))
        else:
            hours = int(request.form.get('expiry_hours', 24))
            expiry = datetime.datetime.now() + datetime.timedelta(hours=hours)
        
        max_downloads = int(request.form.get('max_downloads', 1))
    except:
        return jsonify({'success': False, 'error': 'Invalid parameters'}), 400

    salt = request.form.get('salt', '')
    iv = request.form.get('iv', '')
    if not iv:
        return jsonify({'success': False, 'error': 'IV required'}), 400

    password_protected = request.form.get('password_protected', 'false') == 'true'
    rsa_public_key = request.form.get('rsa_public_key')
    encrypted_aes_key = request.form.get('encrypted_aes_key')
    rsa_private_key = request.form.get('rsa_private_key')

    file_id = secrets.token_urlsafe(32)
    filename = secure_filename(encrypted_file.filename) or 'file.enc'
    mime_type, _ = mimetypes.guess_type(filename.replace('.enc', ''))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{file_id}.enc')

    try:
        encrypted_file.save(file_path)
        file_size = os.path.getsize(file_path)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Save failed: {str(e)}'}), 500

    is_safe, scan_result = scan_with_clamav(file_path)
    if not is_safe:
        os.remove(file_path)
        return jsonify({'success': False, 'error': 'Virus detected'}), 400

    preview_path = create_preview(file_path, mime_type)
    rsa_hash = hashlib.sha256(rsa_private_key.encode()).hexdigest() if rsa_private_key else None

    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (
                    id, filename, expiry, max_downloads, salt, iv, password_protected,
                    rsa_public_key, encrypted_aes_key, rsa_private_key_hash,
                    file_size, mime_type, virus_scan_status, has_preview, preview_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_id, filename, expiry.isoformat(), max_downloads, salt, iv, password_protected,
                rsa_public_key, encrypted_aes_key, rsa_hash,
                file_size, mime_type, scan_result, bool(preview_path), preview_path
            ))
            conn.commit()
        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'success': False, 'error': f'Database error: {str(e)}'}), 500
        finally:
            conn.close()

    log_audit(file_id, 'upload', request.remote_addr)

    return jsonify({
        'success': True,
        'download_url': f"{request.host_url}download/{file_id}",
        'file_id': file_id,
        'expiry_time': expiry.isoformat(),
        'max_downloads': max_downloads,
        'virus_scan_status': scan_result,
        'rsa_private_key': rsa_private_key if rsa_private_key else None
    })

@app.route('/api/file/<file_id>/qr')
def get_qr(file_id):
    if not QR_AVAILABLE:
        return jsonify({'success': False, 'error': 'QR unavailable'}), 503
    
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM files WHERE id = ?', (file_id,))
            if not cursor.fetchone():
                return jsonify({'success': False, 'error': 'File not found'}), 404
        finally:
            conn.close()
    
    url = f"{request.host_url}download/{file_id}"
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return jsonify({
        'success': True,
        'qr_code': f'data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}',
        'download_url': url
    })

@app.route('/api/file/<file_id>/preview')
def get_preview(file_id):
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT preview_path, has_preview FROM files WHERE id = ?', (file_id,))
            data = cursor.fetchone()
        finally:
            conn.close()
    
    if not data or not data['has_preview'] or not data['preview_path']:
        return jsonify({'success': False, 'error': 'No preview'}), 404
    
    if not os.path.exists(data['preview_path']):
        return jsonify({'success': False, 'error': 'Preview missing'}), 404
    
    return send_file(data['preview_path'], mimetype='image/jpeg')

@app.route('/api/file/<file_id>/info')
def get_file_info(file_id):
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
            data = cursor.fetchone()
        finally:
            conn.close()

    if not data:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    expiry = datetime.datetime.fromisoformat(data['expiry'])
    if expiry < datetime.datetime.now():
        delete_file(file_id)
        return jsonify({'success': False, 'error': 'File expired'}), 410

    if data['current_downloads'] >= data['max_downloads']:
        delete_file(file_id)
        return jsonify({'success': False, 'error': 'Max downloads reached'}), 410

    return jsonify({
        'success': True,
        'filename': data['filename'],
        'password_protected': bool(data['password_protected']),
        'downloads_remaining': data['max_downloads'] - data['current_downloads'],
        'expiry_time': expiry.isoformat(),
        'file_size': data['file_size'],
        'uses_rsa': bool(data['rsa_public_key']),
        'mime_type': data['mime_type'],
        'virus_scan_status': data['virus_scan_status'],
        'has_preview': bool(data['has_preview']),
        'rsa_public_key': data['rsa_public_key']
    })

@app.route('/api/file/<file_id>')
def get_file(file_id):
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE files SET current_downloads = current_downloads + 1 WHERE id = ? AND current_downloads < max_downloads', (file_id,))
            
            if cursor.rowcount == 0:
                cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
                data = cursor.fetchone()
                conn.close()
                if not data:
                    return jsonify({'success': False, 'error': 'File not found'}), 404
                if data['current_downloads'] >= data['max_downloads']:
                    delete_file(file_id)
                    return jsonify({'success': False, 'error': 'Max downloads'}), 410
            
            conn.commit()
            cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
            data = cursor.fetchone()
        finally:
            conn.close()

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{file_id}.enc')
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
    except:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    log_audit(file_id, 'download', request.remote_addr)

    if data['current_downloads'] >= data['max_downloads']:
        delete_file(file_id)

    return jsonify({
        'success': True,
        'encrypted': encrypted_data.hex(),
        'salt': data['salt'] or '',
        'iv': data['iv'],
        'filename': data['filename'],
        'password_protected': bool(data['password_protected']),
        'rsa_public_key': data['rsa_public_key'],
        'encrypted_aes_key': data['encrypted_aes_key']
    })

def delete_file(file_id):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{file_id}.enc')
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except:
            pass
    
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT preview_path FROM files WHERE id = ?', (file_id,))
            data = cursor.fetchone()
            if data and data['preview_path'] and os.path.exists(data['preview_path']):
                try:
                    os.remove(data['preview_path'])
                except:
                    pass
            cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
            conn.commit()
        finally:
            conn.close()

def cleanup():
    try:
        now = datetime.datetime.now().isoformat()
        with db_lock:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM files WHERE expiry < ?', (now,))
                expired = cursor.fetchall()
            finally:
                conn.close()
        
        for row in expired:
            delete_file(row['id'])
        
        if expired:
            print(f'✓ Cleaned {len(expired)} files')
    except:
        pass

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({'success': False, 'error': 'File too large'}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'success': False, 'error': 'Server error'}), 500

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup, trigger="interval", minutes=15)
scheduler.start()

import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    print("\n" + "="*60)
    print("SecureShare Enhanced Edition")
    print("="*60)
    print(f"✓ QR Codes: {'Yes' if QR_AVAILABLE else 'No'}")
    print(f"✓ Previews: {'Yes' if PREVIEW_AVAILABLE else 'No'}")
    print(f"✓ Virus Scan: {'Yes' if CLAMAV_AVAILABLE else 'No'}")
    print(f"✓ URL: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)