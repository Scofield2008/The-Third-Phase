/**
 * SALT SIEM - Live Activity Feed
 * Real-time event feed with Socket.IO
 */

class LiveFeed {
    constructor(feedElementId, options = {}) {
        this.feedElement = document.getElementById(feedElementId);
        this.maxItems = options.maxItems || 20;
        this.autoScroll = options.autoScroll !== false;
        this.soundEnabled = options.soundEnabled || false;
        this.socket = io();
        
        this.init();
    }

    init() {
        // Socket.IO listeners
        this.socket.on('new_log', (data) => this.handleNewLog(data));
        this.socket.on('new_alert', (data) => this.handleNewAlert(data));
        this.socket.on('new_scan', (data) => this.handleNewScan(data));
        
        // Connection status
        this.socket.on('connect', () => this.updateConnectionStatus(true));
        this.socket.on('disconnect', () => this.updateConnectionStatus(false));
    }

    handleNewLog(data) {
        this.addItem(data.message, data.severity || 'low');
        
        // Play sound for high/critical
        if (this.soundEnabled && ['high', 'critical'].includes(data.severity?.toLowerCase())) {
            this.playNotificationSound();
        }
    }

    handleNewAlert(data) {
        this.addItem(`🚨 ${data.message}`, data.severity || 'high');
        this.playNotificationSound();
    }

    handleNewScan(data) {
        const message = `File scanned: ${data.filename} - Threat: ${data.threat_level}`;
        this.addItem(message, data.threat_level?.toLowerCase() || 'low');
    }

    addItem(message, severity = 'low') {
        if (!this.feedElement) return;

        const item = document.createElement('div');
        item.className = `feed-item ${severity.toLowerCase()}`;
        item.style.opacity = '0';
        item.innerHTML = `
            <div class="feed-time">${this.getTimeString()}</div>
            <div class="feed-message">${this.escapeHtml(message)}</div>
        `;

        // Insert at the top
        this.feedElement.insertBefore(item, this.feedElement.firstChild);

        // Animate in
        requestAnimationFrame(() => {
            item.style.transition = 'opacity 0.3s';
            item.style.opacity = '1';
        });

        // Remove old items
        while (this.feedElement.children.length > this.maxItems) {
            this.feedElement.removeChild(this.feedElement.lastChild);
        }

        // Auto-scroll if enabled
        if (this.autoScroll) {
            this.feedElement.scrollTop = 0;
        }

        // Emit custom event
        window.dispatchEvent(new CustomEvent('feedItemAdded', { 
            detail: { message, severity } 
        }));
    }

    clearFeed() {
        if (this.feedElement) {
            this.feedElement.innerHTML = '';
        }
    }

    getTimeString() {
        const now = new Date();
        return now.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit',
            hour12: false 
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    playNotificationSound() {
        if (!this.soundEnabled) return;
        
        // Simple beep using Web Audio API
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 800;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.1);
    }

    updateConnectionStatus(connected) {
        const statusDot = document.querySelector('.status-indicator');
        if (statusDot) {
            if (connected) {
                statusDot.style.background = 'var(--success)';
            } else {
                statusDot.style.background = 'var(--danger)';
            }
        }

        if (!connected) {
            this.addItem('Connection to server lost. Attempting to reconnect...', 'high');
        } else {
            this.addItem('Connected to server successfully', 'low');
        }
    }

    enableSound() {
        this.soundEnabled = true;
    }

    disableSound() {
        this.soundEnabled = false;
    }

    setMaxItems(max) {
        this.maxItems = max;
    }
}

// Initialize live feed when DOM is ready
let liveFeed;
document.addEventListener('DOMContentLoaded', () => {
    liveFeed = new LiveFeed('live-feed', {
        maxItems: 20,
        autoScroll: true,
        soundEnabled: false // Change to true to enable sounds
    });
});

// Expose clearFeed function globally
function clearFeed() {
    if (liveFeed) {
        liveFeed.clearFeed();
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LiveFeed;
}