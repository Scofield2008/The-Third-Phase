# SALT SIEM API Documentation

Version: 3.0  
Base URL: `http://localhost:5000`

---

## Authentication

Currently, SALT SIEM does not require authentication. For production deployment, implement authentication middleware.

---

## API Endpoints

### Health Check

#### GET `/api/health`

Check if the SALT SIEM system is running.

**Response:**
```json
{
  "status": "healthy",
  "service": "SALT SIEM",
  "version": "3.0.0",
  "intrusion_detection": "enabled",
  "max_upload": "1GB",
  "timestamp": "2025-01-01T12:00:00.000Z"
}
```

---

### Statistics

#### GET `/api/stats`

Get dashboard statistics and recent activity.

**Response:**
```json
{
  "logs": 145,
  "alerts": 3,
  "incidents": 1,
  "scans": 28,
  "recent_logs": [
    {
      "id": 145,
      "timestamp": "2025-01-01T12:00:00.000Z",
      "type": "file_scan",
      "message": "Scanned test.exe - Threat: Low",
      "severity": "Info"
    }
  ],
  "recent_alerts": [...],
  "recent_scans": [...]
}
```

---

### File Scanning

#### POST `/api/scan`

Upload and scan a file with Zone Sandbox.

**Request:**
- Content-Type: `multipart/form-data`
- Body: Form data with `file` field

**cURL Example:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -F "file=@/path/to/suspicious.exe"
```

**Response:**
```json
{
  "id": 29,
  "filename": "suspicious.exe",
  "threat_level": "High",
  "threat_score": 8,
  "sha256": "a1b2c3d4...",
  "md5": "e5f6g7h8...",
  "sha1": "i9j0k1l2...",
  "yara_matches": 3,
  "report": "Full analysis report...",
  "encrypted": true,
  "source_ip": "127.0.0.1",
  "timestamp": "2025-01-01T12:00:00.000Z"
}
```

**Status Codes:**
- `200` - Scan successful
- `400` - No file provided / Invalid file
- `413` - File too large (>1GB)
- `500` - Server error

---

### Logs

#### GET `/api/logs`

Retrieve system logs.

**Query Parameters:**
- `limit` (optional) - Number of logs to return (default: 100)

**Example:**
```bash
GET /api/logs?limit=50
```

**Response:**
```json
[
  {
    "id": 145,
    "timestamp": "2025-01-01T12:00:00.000Z",
    "type": "file_scan",
    "message": "Scanned test.exe - Threat: Low",
    "severity": "Info"
  },
  {
    "id": 144,
    "timestamp": "2025-01-01T11:59:30.000Z",
    "type": "malware_detection",
    "message": "HIGH THREAT from 192.168.1.5: malware.exe - Critical (12/15)",
    "severity": "Critical"
  }
]
```

---

### Alerts

#### GET `/api/alerts`

Get all security alerts.

**Response:**
```json
[
  {
    "id": 3,
    "timestamp": "2025-01-01T12:00:00.000Z",
    "type": "Malware Detection",
    "severity": "Critical",
    "message": "Suspicious file from 192.168.1.5: ransomware.exe (Score: 13/15)",
    "status": "active",
    "scan_id": 25,
    "file_hash": "a1b2c3d4...",
    "source_ip": "192.168.1.5"
  }
]
```

#### POST `/api/alerts/:id/dismiss`

Dismiss an alert.

**Request:**
```bash
POST /api/alerts/3/dismiss
```

**Response:**
```json
{
  "id": 3,
  "status": "dismissed",
  "dismissed_at": "2025-01-01T12:05:00.000Z"
}
```

---

### Incidents

#### GET `/api/incidents`

Get all incidents.

**Response:**
```json
[
  {
    "id": 1,
    "title": "Ransomware detected on HR laptop",
    "description": "User opened email attachment, showing ransomware indicators",
    "severity": "Critical",
    "status": "open",
    "assigned_to": "Security Team",
    "created": "2025-01-01T10:00:00.000Z"
  }
]
```

#### POST `/api/incident/create`

Create a new incident.

**Request:**
```json
{
  "title": "Incident title",
  "description": "Detailed description",
  "severity": "High",
  "assigned_to": "John Doe"
}
```

**Response:**
```json
{
  "id": 2,
  "title": "Incident title",
  "description": "Detailed description",
  "severity": "High",
  "status": "open",
  "assigned_to": "John Doe",
  "created": "2025-01-01T12:10:00.000Z"
}
```

#### POST `/api/incident/:id/update`

Update an existing incident.

**Request:**
```json
{
  "status": "closed",
  "description": "Updated description"
}
```

**Response:**
```json
{
  "id": 2,
  "status": "closed",
  "updated": "2025-01-01T14:00:00.000Z"
}
```

---

### Security Testing

#### GET `/api/test-attack`

Endpoint for testing intrusion detection features.

**Response:**
```json
{
  "message": "Test different attacks:",
  "examples": {
    "sql_injection": "/api/test-attack?id=1' OR '1'='1",
    "xss": "/api/test-attack?msg=<script>alert(1)</script>",
    "dos": "Make 100+ requests in 1 minute",
    "scanner": "Use User-Agent: sqlmap/1.0"
  }
}
```

#### GET `/api/security-stats`

Get intrusion detection statistics.

**Response:**
```json
{
  "sql_injection_attempts": 5,
  "xss_attempts": 2,
  "tracked_ips": 12,
  "your_ip": "127.0.0.1",
  "your_requests": 45
}
```

---

## WebSocket Events

SALT SIEM uses Socket.IO for real-time updates.

### Client → Server

No client events currently implemented.

### Server → Client

#### `new_log`

Emitted when a new log entry is created.

```javascript
socket.on('new_log', (data) => {
  console.log(data);
  // { message: "File scanned", severity: "Info" }
});
```

#### `new_alert`

Emitted when a new alert is generated.

```javascript
socket.on('new_alert', (data) => {
  console.log(data);
  // { message: "Malware detected", severity: "Critical" }
});
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message description"
}
```

**Common HTTP Status Codes:**
- `400` - Bad Request (missing parameters, invalid input)
- `404` - Not Found
- `413` - Payload Too Large
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error

---

## Rate Limiting

**Limits:**
- 80-150 requests per minute: Warning logged
- 150+ requests per minute: Blocked with `429` status

**Response when rate limited:**
```json
{
  "error": "Rate limit exceeded"
}
```

---

## Intrusion Detection

SALT SIEM automatically detects and blocks:

1. **SQL Injection** - Patterns like `' OR 1=1`, `UNION SELECT`
2. **XSS Attacks** - Patterns like `<script>`, `javascript:`
3. **DoS Attacks** - More than 150 requests/minute
4. **Security Scanners** - User agents: sqlmap, nikto, nmap, etc.

**Response when attack detected:**
```json
{
  "error": "Invalid input detected"
}
```

An alert is automatically created and logged.

---

## Data Types

### Severity Levels

```
- "Critical" - Immediate action required
- "High" - Urgent attention needed
- "Medium" - Investigation required
- "Low" - Informational
- "Info" - General logging
```

### Log Types

```
- "system_start" - System initialization
- "file_upload" - File uploaded
- "file_scan" - File scanned
- "malware_detection" - High threat detected
- "suspicious_filename" - Suspicious file name
- "sql_injection" - SQL injection attempt
- "xss_attempt" - XSS attack attempt
- "dos_attack" - DoS attack detected
- "high_traffic" - High request rate
- "scanning_tool" - Security scanner detected
- "scan_error" - Error during scanning
- "404_error" - Page not found
- "500_error" - Server error
- "file_too_large" - Upload too large
- "incident_created" - Incident created
- "incident_updated" - Incident updated
- "alert_dismissed" - Alert dismissed
```

---

## Examples

### Python Example

```python
import requests

# Scan a file
with open('suspicious.exe', 'rb') as f:
    response = requests.post(
        'http://localhost:5000/api/scan',
        files={'file': f}
    )
    result = response.json()
    print(f"Threat Level: {result['threat_level']}")
    print(f"Threat Score: {result['threat_score']}/15")

# Get statistics
stats = requests.get('http://localhost:5000/api/stats').json()
print(f"Total Logs: {stats['logs']}")
print(f"Active Alerts: {stats['alerts']}")

# Create incident
incident = requests.post(
    'http://localhost:5000/api/incident/create',
    json={
        'title': 'Security Incident',
        'description': 'Details here',
        'severity': 'High',
        'assigned_to': 'SOC Team'
    }
).json()
print(f"Incident ID: {incident['id']}")
```

### JavaScript Example

```javascript
// Scan a file
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('/api/scan', {
  method: 'POST',
  body: formData
})
.then(res => res.json())
.then(data => {
  console.log('Threat Level:', data.threat_level);
  console.log('Threat Score:', data.threat_score);
});

// WebSocket connection
const socket = io();

socket.on('new_log', (data) => {
  console.log('New log:', data.message);
});

socket.on('new_alert', (data) => {
  console.log('Alert:', data.message);
});
```

### cURL Examples

```bash
# Health check
curl http://localhost:5000/api/health

# Get stats
curl http://localhost:5000/api/stats

# Scan file
curl -X POST http://localhost:5000/api/scan \
  -F "file=@suspicious.exe"

# Get logs (last 50)
curl "http://localhost:5000/api/logs?limit=50"

# Create incident
curl -X POST http://localhost:5000/api/incident/create \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Incident",
    "description": "Testing API",
    "severity": "Low"
  }'

# Test SQL injection (will be blocked)
curl "http://localhost:5000/api/stats?id=1' OR '1'='1"
```

---

## Best Practices

1. **File Scanning:**
   - Always check `threat_score` and `yara_matches`
   - Store SHA256 hashes for future reference
   - Review full report for detailed analysis

2. **Error Handling:**
   - Always check HTTP status codes
   - Implement retry logic for 429 errors
   - Log all errors for debugging

3. **Rate Limiting:**
   - Keep requests under 80/minute for normal operation
   - Implement exponential backoff if rate limited

4. **Security:**
   - Always use HTTPS in production
   - Validate all input before sending to API
   - Implement authentication for production use

---

## Changelog

### v3.0.0 (2025-01-01)
- Added intrusion detection system
- Added real-time WebSocket updates
- Added file encryption
- Increased upload limit to 1GB
- Added security testing endpoints

### v2.0.0 (2024-12-15)
- Initial API release
- Basic file scanning
- Log and alert management

---

## Support

For issues or questions:
- GitHub Issues: [Your Repo]
- Documentation: `/docs`
- Playbook: `/playbook`

---

**End of API Documentation**