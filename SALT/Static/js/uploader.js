/**
 * SALT SIEM v3.0 - File Upload Handler
 * Multi-file upload with progress tracking
 */

(function() {
    'use strict';

    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const fileQueue = document.getElementById('file-queue');
    const scanResults = document.getElementById('scan-results');

    // Upload state
    const uploadState = {
        activeUploads: 0,
        completedUploads: 0,
        failedUploads: 0
    };

    /**
     * Initialize upload functionality
     */
    function initUploader() {
        if (!uploadZone || !fileInput) return;

        // Click to browse
        uploadZone.addEventListener('click', () => fileInput.click());

        // Drag and drop
        uploadZone.addEventListener('dragover', handleDragOver);
        uploadZone.addEventListener('dragleave', handleDragLeave);
        uploadZone.addEventListener('drop', handleDrop);

        // File input change
        fileInput.addEventListener('change', handleFileSelect);
    }

    /**
     * Drag over handler
     */
    function handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        uploadZone.classList.add('dragover');
    }

    /**
     * Drag leave handler
     */
    function handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        uploadZone.classList.remove('dragover');
    }

    /**
     * Drop handler
     */
    function handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        uploadZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFiles(files);
        }
    }

    /**
     * File select handler
     */
    function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            handleFiles(files);
        }
        // Reset input
        fileInput.value = '';
    }

    /**
     * Handle multiple files
     */
    async function handleFiles(files) {
        if (!files || files.length === 0) return;

        // Log activity
        if (window.SALT && window.SALT.addToFeed) {
            window.SALT.addToFeed(`Uploading ${files.length} file(s)`, 'low');
        }

        // Process each file
        for (let file of files) {
            await uploadFile(file);
        }
    }

    /**
     * Upload single file
     */
    async function uploadFile(file) {
        uploadState.activeUploads++;

        // Create queue item
        const queueItem = createQueueItem(file);
        fileQueue.appendChild(queueItem);

        // Get progress elements
        const progressFill = queueItem.querySelector('.progress-fill');
        const statusText = queueItem.querySelector('.file-status');

        try {
            // Prepare form data
            const formData = new FormData();
            formData.append('file', file);

            // Update progress
            progressFill.style.width = '10%';
            statusText.textContent = 'Uploading...';

            // Upload file
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData
            });

            progressFill.style.width = '50%';
            statusText.textContent = 'Analyzing...';

            if (!response.ok) {
                throw new Error(`Upload failed: ${response.statusText}`);
            }

            const data = await response.json();

            // Complete
            progressFill.style.width = '100%';
            statusText.textContent = 'Complete';
            uploadState.completedUploads++;

            // Show results after brief delay
            setTimeout(() => {
                displayScanResults(data);
                queueItem.remove();
            }, 1000);

            // Log to feed
            if (window.SALT && window.SALT.addToFeed) {
                window.SALT.addToFeed(
                    `Scan complete: ${file.name} - ${data.threat_level}`,
                    data.threat_level.toLowerCase()
                );
            }

        } catch (error) {
            console.error('Upload error:', error);
            uploadState.failedUploads++;
            
            // Show error
            progressFill.style.width = '100%';
            progressFill.style.background = 'var(--danger)';
            statusText.textContent = 'Failed';
            statusText.style.color = 'var(--danger)';

            // Remove after delay
            setTimeout(() => queueItem.remove(), 3000);

            // Log error
            if (window.SALT && window.SALT.addToFeed) {
                window.SALT.addToFeed(
                    `Upload failed: ${file.name} - ${error.message}`,
                    'high'
                );
            }
        } finally {
            uploadState.activeUploads--;
        }
    }

    /**
     * Create queue item element
     */
    function createQueueItem(file) {
        const item = document.createElement('div');
        item.className = 'file-item';
        
        const fileSize = window.SALT ? window.SALT.formatFileSize(file.size) : `${(file.size / 1024).toFixed(1)} KB`;
        
        item.innerHTML = `
            <div style="font-size:20px;">📄</div>
            <div class="file-info">
                <div class="file-name">${escapeHtml(file.name)}</div>
                <div class="file-size">${fileSize} • <span class="file-status">Queued</span></div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:0%"></div>
                </div>
            </div>
        `;
        
        return item;
    }

    /**
     * Display scan results
     */
    function displayScanResults(data) {
        if (!scanResults) return;

        const sev = data.threat_level.toLowerCase();
        
        const resultCard = document.createElement('div');
        resultCard.className = 'card';
        resultCard.style.marginTop = '16px';
        resultCard.innerHTML = `
            <div class="card-header">
                <h3 class="card-title">Scan Results: ${escapeHtml(data.filename)}</h3>
                <span class="badge badge-${sev}">${data.threat_level}</span>
            </div>
            <table style="margin-bottom:16px;">
                <tr>
                    <td style="width:120px; font-weight:500;">SHA256</td>
                    <td style="font-family:monospace; font-size:11px;">${data.sha256}</td>
                </tr>
                <tr>
                    <td style="font-weight:500;">MD5</td>
                    <td style="font-family:monospace; font-size:11px;">${data.md5}</td>
                </tr>
                <tr>
                    <td style="font-weight:500;">Threat Score</td>
                    <td>${data.threat_score}/15</td>
                </tr>
                <tr>
                    <td style="font-weight:500;">YARA Matches</td>
                    <td>${data.yara_matches}</td>
                </tr>
            </table>
            <details style="margin-top:16px;">
                <summary style="cursor:pointer; font-weight:500; margin-bottom:8px;">View Full Report</summary>
                <div style="background:var(--bg-main); padding:16px; border-radius:6px; font-family:monospace; font-size:12px; max-height:400px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.report)}</div>
            </details>
        `;
        
        // Replace previous results
        scanResults.innerHTML = '';
        scanResults.appendChild(resultCard);

        // Scroll to results
        resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    /**
     * Escape HTML
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initUploader);
    } else {
        initUploader();
    }

    // Export
    window.SALTUploader = {
        uploadFile,
        handleFiles,
        uploadState
    };

})();