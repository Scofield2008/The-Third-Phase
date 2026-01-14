/**
 * SALT SIEM v3.0 - Main JavaScript
 * Core functionality and utilities
 */

// Initialize Socket.IO connection
const socket = io();

// Global state
const AppState = {
    currentPage: 'dashboard',
    theme: localStorage.getItem('theme') || 'dark',
    isLoading: false,
    stats: {
        logs: 0,
        alerts: 0,
        incidents: 0,
        scans: 0,
        threat_score: 0,
        file_types: {}
    }
};

// Initialize app on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadInitialData();
});

/**
 * Initialize application
 */
function initializeApp() {
    // Set saved theme
    document.documentElement.setAttribute('data-theme', AppState.theme);
    document.getElementById('theme-icon').textContent = AppState.theme === 'dark' ? '◐' : '◑';
    
    // Log initialization
    console.log('SALT SIEM v3.0 initialized');
    addToFeed('System initialized - SALT SIEM v3.0 started', 'low');
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Socket.IO events
    socket.on('connect', () => {
        console.log('Connected to server');
        addToFeed('Connected to server', 'low');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        addToFeed('Disconnected from server', 'high');
    });

    socket.on('new_log', (data) => {
        handleNewLog(data);
    });

    socket.on('new_alert', (data) => {
        handleNewAlert(data);
    });

    socket.on('new_scan', (data) => {
        handleNewScan(data);
    });

    // Page visibility change
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            loadStats();
        }
    });
}

/**
 * Load initial data
 */
function loadInitialData() {
    loadStats();
    
    // Auto-refresh every 5 seconds
    setInterval(() => {
        if (!document.hidden) {
            loadStats();
        }
    }, 5000);
}

/**
 * Load statistics
 */
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to fetch stats');
        
        const data = await response.json();
        
        // Update metrics
        updateMetric('metric-logs', data.logs);
        updateMetric('metric-alerts', data.alerts);
        updateMetric('metric-incidents', data.incidents);
        updateMetric('metric-scans', data.scans);
        
        // Update state
        AppState.stats = data;
        
        // Update charts if on analytics
        if (AppState.currentPage === 'analytics') {
            updateCharts(data);
        }
        
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

/**
 * Page navigation
 */
function switchPage(page) {
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    event.currentTarget.classList.add('active');

    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(page).classList.add('active');

    AppState.currentPage = page;

    // Load page-specific data
    switch(page) {
        case 'dashboard':
            loadStats();
            break;
        case 'logs':
            refreshLogs();
            break;
        case 'alerts':
            refreshAlerts();
            break;
        case 'incidents':
            refreshIncidents();
            break;
        case 'analytics':
            initCharts();
            updateCharts(AppState.stats);
            break;
        case 'api':
            listApiKeys();
            break;
        case 'windows-events':
            // Optional: auto fetch
            fetchWindowsEvents();
            break;
    }
}

/**
 * Theme toggle
 */
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    document.getElementById('theme-icon').textContent = newTheme === 'dark' ? '◐' : '◑';
    localStorage.setItem('theme', newTheme);
    AppState.theme = newTheme;
    
    // Reinitialize charts if on analytics page
    if (AppState.currentPage === 'analytics') {
        setTimeout(initCharts, 100);
    }
}

/**
 * Update metric with animation
 */
function updateMetric(elementId, value) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const currentValue = parseInt(element.textContent) || 0;
    const targetValue = parseInt(value) || 0;
    
    if (currentValue !== targetValue) {
        animateValue(element, currentValue, targetValue, 300);
    }
}

/**
 * Animate value change
 */
function animateValue(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 16);
}

/**
 * Activity feed management
 */
function addToFeed(message, severity = 'low') {
    const feed = document.getElementById('live-feed');
    if (!feed) return;
    
    const item = document.createElement('div');
    item.className = `feed-item ${severity.toLowerCase()}`;
    item.innerHTML = `
        <div class="feed-time">${new Date().toLocaleTimeString()}</div>
        <div class="feed-message">${escapeHtml(message)}</div>
    `;
    
    item.style.opacity = '0';
    feed.insertBefore(item, feed.firstChild);
    setTimeout(() => item.style.opacity = '1', 10);
    
    while (feed.children.length > 20) {
        feed.removeChild(feed.lastChild);
    }
}

function clearFeed() {
    const feed = document.getElementById('live-feed');
    if (feed) feed.innerHTML = '';
}

/**
 * Socket event handlers
 */
function handleNewLog(data) {
    addToFeed(data.message, data.severity);
    loadStats();
}

function handleNewAlert(data) {
    addToFeed(`Alert: ${data.message}`, data.severity);
    loadStats();
}

function handleNewScan(data) {
    addToFeed(`Scan completed: ${data.filename} - ${data.threat_level}`, data.threat_level.toLowerCase());
    loadStats();
}

/**
 * Logs management
 */
async function refreshLogs(url = '/api/logs') {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch logs');
        
        const logs = await response.json();
        const tbody = document.querySelector('#logs-table tbody');
        
        if (!tbody) return;
        
        tbody.innerHTML = logs.length === 0 ? '<tr><td colspan="4" style="text-align:center; padding:40px; color:var(--text-dim);">No logs found</td></tr>' : '';
        
        logs.forEach(log => {
            const time = new Date(log.timestamp).toLocaleString();
            const sev = (log.severity || 'Info').toLowerCase();
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${time}</td>
                <td><span class="badge badge-${sev}">${log.type}</span></td>
                <td>${escapeHtml(log.message)}</td>
                <td><span class="badge badge-${sev}">${log.severity || 'Info'}</span></td>
            `;
            tbody.appendChild(row);
        });
        
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

async function performLogSearch() {
    const query = document.getElementById('log-search-query').value;
    const severity = document.getElementById('log-search-severity').value;
    let url = '/api/logs/search?';
    if (query) url += `q=${encodeURIComponent(query)}&`;
    if (severity) url += `severity=${severity}&`;
    await refreshLogs(url);
}

/**
 * Alerts management
 */
async function refreshAlerts(url = '/api/alerts') {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch alerts');
        
        const alerts = await response.json();
        const container = document.getElementById('alerts-container');
        
        if (!container) return;
        
        container.innerHTML = alerts.length === 0 ? '<div class="card"><p style="text-align:center; padding:40px; color:var(--text-dim);">No active alerts</p></div>' : '';
        
        alerts.forEach(alert => {
            const sev = alert.severity.toLowerCase();
            const time = new Date(alert.timestamp).toLocaleString();
            
            const card = document.createElement('div');
            card.className = 'card';
            card.style.marginBottom = '12px';
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:start;">
                    <div>
                        <span class="badge badge-${sev}">${alert.severity}</span>
                        <strong style="margin-left:8px;">${escapeHtml(alert.type)}</strong>
                        <div style="margin-top:8px; font-size:13px; color:var(--text-dim);">${time}</div>
                    </div>
                </div>
                <div style="margin-top:12px; color:var(--text-main);">${escapeHtml(alert.message)}</div>
            `;
            container.appendChild(card);
        });
        
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function performAlertSearch() {
    const severity = document.getElementById('alert-search-severity').value;
    let url = '/api/alerts/search?';
    if (severity) url += `severity=${severity}`;
    await refreshAlerts(url);
}

/**
 * Incidents management
 */
async function refreshIncidents() {
    try {
        const response = await fetch('/api/incidents');
        if (!response.ok) throw new Error('Failed to fetch incidents');
        
        const incidents = await response.json();
        const container = document.getElementById('incidents-container');
        
        if (!container) return;
        
        container.innerHTML = incidents.length === 0 ? '<div class="card"><p style="text-align:center; padding:40px; color:var(--text-dim);">No incidents</p></div>' : '';
        
        incidents.forEach(inc => {
            const sev = inc.severity.toLowerCase();
            const time = new Date(inc.created).toLocaleString();
            
            const card = document.createElement('div');
            card.className = 'card';
            card.style.marginBottom = '12px';
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:start;">
                    <div>
                        <strong>${escapeHtml(inc.title)}</strong>
                        <div style="margin-top:4px;">
                            <span class="badge badge-${sev}">${inc.severity}</span>
                            <span class="badge" style="margin-left:8px; background:var(--bg-hover);">${inc.status.toUpperCase()}</span>
                        </div>
                    </div>
                </div>
                <div style="margin-top:12px; font-size:13px; color:var(--text-dim);">${escapeHtml(inc.description)}</div>
                <div style="margin-top:8px; font-size:12px; color:var(--text-dim);">
                    Assigned: ${escapeHtml(inc.assigned_to)} • Created: ${time}
                </div>
            `;
            container.appendChild(card);
        });
        
    } catch (error) {
        console.error('Error loading incidents:', error);
    }
}

function createIncident() {
    const title = prompt('Incident Title:');
    if (!title) return;
    
    const description = prompt('Description:');
    const severity = prompt('Severity (Low/Medium/High/Critical):', 'Medium');
    const assigned = prompt('Assigned to:', 'Security Team');
    
    fetch('/api/incident/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            title,
            description,
            severity,
            assigned_to: assigned
        })
    })
    .then(response => response.json())
    .then(() => {
        refreshIncidents();
        addToFeed(`Incident created: ${title}`, 'medium');
    })
    .catch(error => console.error('Error creating incident:', error));
}

/**
 * API Keys management
 */
async function listApiKeys() {
    try {
        const response = await fetch('/api/keys');
        if (!response.ok) throw new Error('Failed to fetch API keys');
        
        const keys = await response.json();
        const container = document.getElementById('api-keys-list');
        
        container.innerHTML = '';
        
        if (keys.length === 0) {
            container.innerHTML = '<p style="text-align:center; padding:40px; color:var(--text-dim);">No API keys</p>';
            return;
        }
        
        const table = document.createElement('table');
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Key Preview</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody></tbody>
        `;
        
        keys.forEach(key => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(key.name)}</td>
                <td>${key.key}</td>
                <td>${new Date(key.created).toLocaleString()}</td>
                <td><span class="badge ${key.active ? 'badge-success' : 'badge-danger'}">${key.active ? 'Active' : 'Revoked'}</span></td>
                <td>${key.active ? '<button class="btn" onclick="revokeApiKey(\'' + key.key + '\')">Revoke</button>' : ''}</td>
            `;
            table.querySelector('tbody').appendChild(row);
        });
        
        container.appendChild(table);
        
    } catch (error) {
        console.error('Error loading API keys:', error);
    }
}

function createApiKey() {
    const name = prompt('Key Name:');
    if (!name) return;
    
    fetch('/api/keys/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    })
    .then(response => response.json())
    .then(data => {
        alert(`New Key: ${data.key}`);
        listApiKeys();
    })
    .catch(error => console.error('Error creating key:', error));
}

function revokeApiKey(keyPreview) {
    // Note: keyPreview is partial, but for simplicity assume full key is passed or adjust
    if (confirm('Revoke this key?')) {
        fetch(`/api/keys/${keyPreview}/revoke`, { method: 'POST' })
            .then(() => listApiKeys())
            .catch(error => console.error('Error revoking key:', error));
    }
}

/**
 * Windows Events
 */
async function fetchWindowsEvents() {
    try {
        const response = await fetch('/api/windows-events?type=Security&limit=50');
        if (!response.ok) throw new Error('Failed to fetch windows events');
        
        const data = await response.json();
        const results = document.getElementById('win-events-results');
        
        results.innerHTML = '';
        
        if (!data.available) {
            results.innerHTML = '<p style="color:var(--text-dim);">Windows events not available on this system.</p>';
            return;
        }
        
        if (data.count === 0) {
            results.innerHTML = '<p style="color:var(--text-dim);">No events found.</p>';
            return;
        }
        
        data.events.forEach(event => {
            const item = document.createElement('div');
            item.className = 'feed-item';
            item.innerHTML = `
                <div class="feed-time">${event.time}</div>
                <div class="feed-message">Event ${event.event_id}: ${escapeHtml(event.source)} - ${escapeHtml(event.description.slice(0, 100))}</div>
            `;
            results.appendChild(item);
        });
        
    } catch (error) {
        console.error('Error fetching windows events:', error);
    }
}

/**
 * File Upload Handler
 */
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');

if (uploadZone && fileInput) {
    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });
    fileInput.addEventListener('change', (e) => handleFiles(e.target.files));
}

async function handleFiles(files) {
    const queue = document.getElementById('file-queue');
    for (let file of files) {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.innerHTML = `
            <div style="font-size:20px;">📄</div>
            <div class="file-info">
                <div class="file-name">${escapeHtml(file.name)}</div>
                <div class="file-size">${formatFileSize(file.size)}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:0%"></div>
                </div>
            </div>
        `;
        queue.appendChild(item);
        
        const formData = new FormData();
        formData.append('file', file);
        
        const progressBar = item.querySelector('.progress-fill');
        progressBar.style.width = '30%';
        
        try {
            const response = await fetch('/api/scan', { method: 'POST', body: formData });
            progressBar.style.width = '100%';
            
            if (!response.ok) throw new Error('Scan failed');
            
            const data = await response.json();
            
            setTimeout(() => {
                const sev = data.threat_level.toLowerCase();
                const results = document.getElementById('scan-results');
                results.innerHTML += `
                    <div class="card" style="margin-top:16px;">
                        <div class="card-header">
                            <h3 class="card-title">Scan Results: ${escapeHtml(data.filename)}</h3>
                            <span class="badge badge-${sev}">${data.threat_level}</span>
                        </div>
                        <table style="margin-bottom:16px;">
                            <tr><td style="width:120px; font-weight:500;">SHA256</td><td style="font-family:monospace; font-size:11px;">${data.sha256}</td></tr>
                            <tr><td style="font-weight:500;">MD5</td><td style="font-family:monospace; font-size:11px;">${data.md5}</td></tr>
                            <tr><td style="font-weight:500;">Threat Score</td><td>${data.threat_score}/15</td></tr>
                            <tr><td style="font-weight:500;">YARA Matches</td><td>${data.yara_matches}</td></tr>
                        </table>
                        <div style="background:var(--bg-main); padding:16px; border-radius:6px; font-family:monospace; font-size:12px; max-height:400px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.report)}</div>
                    </div>
                `;
                item.remove();
            }, 1000);
        } catch (error) {
            console.error('Scan error:', error);
            item.remove();
        }
    }
}

/**
 * Utility: Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Utility: Format file size
 */
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}