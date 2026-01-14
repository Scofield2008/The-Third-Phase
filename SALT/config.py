"""
SALT SIEM v3.0 - Configuration
"""

import os

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'salt-siem-v3-secret-change-in-production')
    
    # Upload settings
    UPLOAD_FOLDER = 'uploads'
    REPORTS_FOLDER = 'reports'
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB
    
    # Database/Storage
    DATA_FOLDER = 'data'
    ENCRYPTION_KEY_FILE = 'data/encryption.key'
    
    # SocketIO
    SOCKETIO_ASYNC_MODE = 'eventlet'
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = 150  # requests per minute
    RATE_LIMIT_WARNING = 80    # warning threshold
    
    # Threat Scoring
    THREAT_SCORE_LOW = 2
    THREAT_SCORE_MEDIUM = 5
    THREAT_SCORE_HIGH = 9
    THREAT_SCORE_CRITICAL = 10
    
    # YARA Rules
    YARA_RULES_ENABLED = True
    
    # Features
    ENABLE_NOTIFICATIONS = True
    ENABLE_REAL_TIME_FEED = True
    ENABLE_CHARTS = True
    ENABLE_VIRUSTOTAL = False  # Requires API key
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # UI Settings
    DEFAULT_THEME = 'dark'
    ITEMS_PER_PAGE = 50
    CHART_REFRESH_INTERVAL = 5000  # milliseconds
    
    # Intrusion Detection
    ENABLE_SQL_INJECTION_DETECTION = True
    ENABLE_XSS_DETECTION = True
    ENABLE_DOS_PROTECTION = True
    ENABLE_SCANNER_DETECTION = True

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    # Tighter security for production
    RATE_LIMIT_REQUESTS = 100
    MAX_CONTENT_LENGTH = 512 * 1024 * 1024  # 512MB

# Select config based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])