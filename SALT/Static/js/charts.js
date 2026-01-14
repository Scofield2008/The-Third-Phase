// SALT SIEM - Charts Module
// Handles all Chart.js visualizations

let threatChart, trendChart, fileTypeChart, detectionChart, categoryChart;

// Initialize all charts
function initCharts() {
    initThreatChart();
    initTrendChart();
    initFileTypeChart();
    initDetectionChart();
    initCategoryChart();
}

// Threat Gauge (Doughnut) - Renamed to avoid conflict
function initThreatChart() {
    const ctx = document.getElementById('threat-gauge');
    if (!ctx) return;
    
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 15],
                backgroundColor: ['#58a6ff', '#30363d'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    });
}

// Update threat gauge
function updateThreatChart(score) {
    if (!threatChart) return;
    threatChart.data.datasets[0].data = [score, 15 - score];
    threatChart.data.datasets[0].backgroundColor = [
        score >= 10 ? '#f85149' : score >= 6 ? '#d29922' : '#58a6ff',
        '#30363d'
    ];
    threatChart.update();
    document.getElementById('threat-score').textContent = `${score}/15`;
}

// Threat Trends (Line Chart)
function initTrendChart() {
    const ctx = document.getElementById('trend-chart');
    if (!ctx) return;
    
    trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            datasets: [{
                label: 'Threats Detected',
                data: [2, 5, 3, 7, 4, 6],  // Mock data, replace with real
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88, 166, 255, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { color: '#8b949e' }
                },
                x: { 
                    grid: { display: false },
                    ticks: { color: '#8b949e' }
                }
            }
        }
    });
}

// File Type Distribution (Pie Chart)
function initFileTypeChart() {
    const ctx = document.getElementById('filetype-chart');
    if (!ctx) return;
    
    fileTypeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['EXE', 'PDF', 'ZIP', 'DOC', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#8b949e']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'bottom',
                    labels: { color: '#8b949e', padding: 10 }
                }
            }
        }
    });
}

// Detection Rate (Bar Chart)
function initDetectionChart() {
    const ctx = document.getElementById('detection-chart');
    if (!ctx) return;
    
    detectionChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Scans',
                data: [12, 19, 3, 5, 2, 3, 7],
                backgroundColor: '#58a6ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { color: '#8b949e' }
                },
                x: { 
                    grid: { display: false },
                    ticks: { color: '#8b949e' }
                }
            }
        }
    });
}

// Threat Categories (Doughnut)
function initCategoryChart() {
    const ctx = document.getElementById('category-chart');
    if (!ctx) return;
    
    categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malware', 'Ransomware', 'Trojan', 'Keylogger', 'Other'],
            datasets: [{
                data: [12, 19, 3, 5, 2],
                backgroundColor: ['#f85149', '#d29922', '#a371f7', '#58a6ff', '#8b949e']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'bottom',
                    labels: { color: '#8b949e', padding: 10 }
                }
            }
        }
    });
}

// Update charts with real data
function updateCharts(stats) {
    updateThreatChart(stats.threat_score || 0);
    
    if (fileTypeChart && stats.file_types) {
        const labels = Object.keys(stats.file_types);
        const data = Object.values(stats.file_types);
        fileTypeChart.data.labels = labels.length ? labels : ['No Data'];
        fileTypeChart.data.datasets[0].data = data.length ? data : [1];
        fileTypeChart.update();
    }
    
    // Update other charts with mock or add real data endpoints if needed
}

// Initialize on load if on analytics
if (document.getElementById('analytics')) {
    initCharts();
}