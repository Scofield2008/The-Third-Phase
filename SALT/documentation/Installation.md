# SALT SIEM Installation Guide

Complete setup guide for SALT SIEM v3.0

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Start](#quick-start)
3. [Detailed Installation](#detailed-installation)
4. [Configuration](#configuration)
5. [Running SALT](#running-salt)
6. [Deployment](#deployment)
7. [Troubleshooting](#troubleshooting)
8. [Upgrading](#upgrading)

---

## System Requirements

### Minimum Requirements

- **OS:** Windows 10/11, macOS 10.15+, Linux (Ubuntu 20.04+)
- **Python:** 3.8 or higher
- **RAM:** 2GB minimum, 4GB recommended
- **Disk:** 1GB free space
- **Network:** Internet connection for dependencies

### Recommended Requirements

- **Python:** 3.10+
- **RAM:** 8GB
- **Disk:** 10GB free space (for logs and uploads)
- **CPU:** Multi-core processor

---

## Quick Start

### 5-Minute Installation

```bash
# 1. Clone or download SALT SIEM
git clone https://github.com/yourusername/salt-siem.git
cd salt-siem

# 2. Create virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run SALT
python app.py

# 5. Open browser
# Navigate to: http://localhost:5000
```

That's it! SALT is now running.

---

## Detailed Installation

### Step 1: System Preparation

#### Windows

```powershell
# Check Python version
python --version

# If Python not installed, download from python.org
# Make sure to check "Add Python to PATH" during installation
```

#### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11

# Verify installation
python3 --version
```

#### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install build tools (required for some dependencies)
sudo apt install build-essential python3-dev

# Verify installation
python3 --version
```

---

### Step 2: Download SALT SIEM

#### Option A: Git Clone

```bash
git clone https://github.com/yourusername/salt-siem.git
cd salt-siem
```

#### Option B: Download ZIP

1. Download from GitHub releases
2. Extract to desired location
3. Open terminal in extracted folder

---

### Step 3: Create Project Structure

```bash
# Create necessary directories
mkdir -p templates static/css static/js static/img modules data uploads reports docs

# Verify structure
ls -la
```

**Expected structure:**
```
salt-siem/
├── app.py
├── config.py
├── requirements.txt
├── Procfile
├── templates/
├── static/
├── modules/
├── data/
├── uploads/
├── reports/
└── docs/
```

---

### Step 4: Virtual Environment Setup

#### Why Use Virtual Environment?

- Isolates dependencies
- Prevents version conflicts
- Easy to remove/reinstall

#### Create and Activate

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate

# Your prompt should now show (venv)
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate

# Your prompt should now show (venv)
```

#### Verify Activation

```bash
which python
# Should point to venv/bin/python or venv\Scripts\python
```

---

### Step 5: Install Dependencies

#### Install from requirements.txt

```bash
pip install -r requirements.txt
```

#### Manual Installation (if needed)

```bash
pip install Flask==3.0.0
pip install Flask-SocketIO==5.3.5
pip install yara-python==4.5.0
pip install pefile==2023.2.7
pip install cryptography==41.0.7
pip install gunicorn==21.2.0
pip install watchdog==3.0.0
pip install psutil==5.9.6
pip install requests==2.31.0
```

#### Verify Installation

```bash
pip list
# Should show all installed packages
```

---

### Step 6: Configuration

#### Create config.py

```bash
# config.py should already exist
# Edit if needed for custom settings
```

#### Environment Variables (Optional)

**Windows:**
```powershell
set FLASK_ENV=development
set SECRET_KEY=your-secret-key-here
```

**macOS/Linux:**
```bash
export FLASK_ENV=development
export SECRET_KEY=your-secret-key-here
```

#### For Production

Create `.env` file:
```env
FLASK_ENV=production
SECRET_KEY=generate-strong-secret-key
PORT=5000
```

---

## Configuration

### Basic Configuration

Edit `config.py`:

```python
# Upload settings
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB

# Rate limiting
RATE_LIMIT_REQUESTS = 150  # requests per minute

# Features
ENABLE_NOTIFICATIONS = True
ENABLE_REAL_TIME_FEED = True
ENABLE_CHARTS = True
```

### Advanced Configuration

#### Custom Upload Folder

```python
UPLOAD_FOLDER = '/path/to/uploads'
REPORTS_FOLDER = '/path/to/reports'
```

#### Security Settings

```python
# Intrusion Detection
ENABLE_SQL_INJECTION_DETECTION = True
ENABLE_XSS_DETECTION = True
ENABLE_DOS_PROTECTION = True
```

---

## Running SALT

### Development Mode

```bash
# Standard run
python app.py

# With debug mode
python app.py --debug

# Custom port
PORT=8080 python app.py
```

### Production Mode

#### Using Gunicorn (Recommended)

```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

#### With Eventlet (for Socket.IO)

```bash
gunicorn --bind 0.0.0.0:5000 --worker-class eventlet --workers 1 app:app
```

### Background Service

#### Linux (systemd)

Create `/etc/systemd/system/salt-siem.service`:

```ini
[Unit]
Description=SALT SIEM Service
After=network.target

[Service]
User=your-username
WorkingDirectory=/path/to/salt-siem
Environment="PATH=/path/to/salt-siem/venv/bin"
ExecStart=/path/to/salt-siem/venv/bin/gunicorn --bind 0.0.0.0:5000 --worker-class eventlet --workers 1 app:app

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable salt-siem
sudo systemctl start salt-siem
sudo systemctl status salt-siem
```

#### Windows (NSSM)

```powershell
# Download NSSM from nssm.cc
nssm install SALT-SIEM "C:\path\to\venv\Scripts\python.exe" "C:\path\to\app.py"
nssm start SALT-SIEM
```

---

## Deployment

### Deploy to Render.com

#### Step 1: Prepare Repository

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/salt-siem.git
git push -u origin main
```

#### Step 2: Create Render Account

1. Go to [render.com](https://render.com)
2. Sign up / Log in
3. Connect GitHub account

#### Step 3: Create Web Service

1. Click "New +" → "Web Service"
2. Select your repository
3. Configure:
   - **Name:** salt-siem
   - **Environment:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --bind 0.0.0.0:$PORT --worker-class eventlet --workers 1 app:app`
4. Click "Create Web Service"

#### Step 4: Environment Variables

Add in Render dashboard:
```
FLASK_ENV=production
SECRET_KEY=your-secret-key
```

#### Step 5: Deploy

Render will automatically deploy. Wait 2-3 minutes.

**Your SALT SIEM will be live at:** `https://salt-siem-xxxx.onrender.com`

---

### Deploy to Heroku

```bash
# Install Heroku CLI
# Login
heroku login

# Create app
heroku create salt-siem

# Deploy
git push heroku main

# Open
heroku open
```

---

### Deploy with Docker

#### Create Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "eventlet", "--workers", "1", "app:app"]
```

#### Build and Run

```bash
# Build image
docker build -t salt-siem .

# Run container
docker run -d -p 5000:5000 --name salt-siem salt-siem

# View logs
docker logs -f salt-siem
```

---

## Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError: No module named 'yara'"

**Solution:**
```bash
pip install yara-python
```

If fails, try:
```bash
# Windows
pip install yara-python --no-binary :all:

# Linux
sudo apt install libyara-dev
pip install yara-python
```

---

#### Issue: "Address already in use"

**Solution:**
```bash
# Find process using port 5000
# Linux/Mac
lsof -i :5000

# Windows
netstat -ano | findstr :5000

# Kill process
# Linux/Mac
kill -9 <PID>

# Windows
taskkill /PID <PID> /F

# Or use different port
PORT=8080 python app.py
```

---

#### Issue: "pefile not available"

**Solution:**
```bash
pip install pefile
```

---

#### Issue: "Permission denied" on Linux

**Solution:**
```bash
# Give execute permission
chmod +x app.py

# Or run with sudo (not recommended)
sudo python app.py
```

---

#### Issue: "Invalid input detected" on all requests

**Solution:**
Check intrusion detection settings in `config.py`:
```python
# Disable temporarily to test
ENABLE_SQL_INJECTION_DETECTION = False
ENABLE_XSS_DETECTION = False
```

---

#### Issue: Socket.IO not working

**Solution:**
```bash
# Install eventlet
pip install eventlet

# Run with eventlet worker
gunicorn --worker-class eventlet app:app
```

---

### Debug Mode

Enable detailed error messages:

```python
# In app.py
app.run(debug=True)
```

Check logs:
```bash
# View recent logs
tail -f data/store.json

# Check system logs (Linux)
journalctl -u salt-siem -f
```

---

## Upgrading

### From v2.0 to v3.0

```bash
# Backup data
cp -r data data_backup

# Pull latest code
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart SALT
# Development
python app.py

# Production
sudo systemctl restart salt-siem
```

### Database Migration

v3.0 uses JSON storage. No migration needed.

---

## Post-Installation

### Step 1: Verify Installation

```bash
# Check health endpoint
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "SALT SIEM",
  "version": "3.0.0"
}
```

### Step 2: Test File Upload

```bash
# Create test file
echo "test" > test.txt

# Upload
curl -X POST http://localhost:5000/api/scan -F "file=@test.txt"
```

### Step 3: Access Dashboard

Open browser: `http://localhost:5000`

**You should see:**
- Dashboard with metrics (all showing 0)
- Sidebar with navigation
- Theme toggle working

---

## Security Checklist

Before production deployment:

- [ ] Change SECRET_KEY in config
- [ ] Enable HTTPS
- [ ] Implement authentication
- [ ] Configure firewall
- [ ] Set up backups
- [ ] Review intrusion detection settings
- [ ] Enable logging
- [ ] Set up monitoring
- [ ] Review YARA rules
- [ ] Test all features

---

## Performance Tuning

### For High Load

```python
# Increase workers
gunicorn --workers 4 --worker-class eventlet app:app

# Increase rate limits
RATE_LIMIT_REQUESTS = 300

# Enable caching (optional)
# Install redis
pip install redis
```

### For Low Resources

```python
# Reduce workers
gunicorn --workers 1 app:app

# Lower rate limits
RATE_LIMIT_REQUESTS = 50

# Disable features
ENABLE_CHARTS = False
```

---

## Backup and Restore

### Backup

```bash
# Backup data
tar -czf salt-backup-$(date +%Y%m%d).tar.gz data/ uploads/ reports/

# Or just data
cp data/store.json data/store.json.backup
```

### Restore

```bash
# Restore from backup
tar -xzf salt-backup-20250101.tar.gz

# Or just data
cp data/store.json.backup data/store.json
```

---

## Uninstall

```bash
# Deactivate virtual environment
deactivate

# Remove SALT directory
cd ..
rm -rf salt-siem

# Remove service (if installed)
sudo systemctl stop salt-siem
sudo systemctl disable salt-siem
sudo rm /etc/systemd/system/salt-siem.service
```

---

## Next Steps

After installation:

1. Read the [API Documentation](API.md)
2. Review the [SOC Playbook](/playbook)
3. Test file scanning
4. Configure custom YARA rules
5. Set up monitoring
6. Train your team

---

## Support

Need help?

- **Documentation:** `/docs`
- **API Docs:** [API.md](API.md)
- **GitHub Issues:** [Report a bug]
- **Community:** [Discord/Slack]

---

## License

SALT SIEM is released under the MIT License.

---

**Installation guide complete!**

Last updated: 2025-01-01