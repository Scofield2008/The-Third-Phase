"""
SALT SIEM v3.0 - Intrusion Detection System
Detects SQL injection, XSS, DoS, and other attacks
"""

import re
import time
from collections import defaultdict


class IntrusionDetector:
    """
    Real-time intrusion detection system
    
    Features:
    - SQL injection detection
    - XSS attack detection
    - DoS protection (rate limiting)
    - Scanner tool detection
    - Path traversal detection
    - Command injection detection
    """
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"select.*from",
        r"insert.*into",
        r"delete.*from",
        r"drop.*table",
        r"update.*set",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
        r"document\.cookie",
        r"alert\s*\(",
        r"<img.*onerror",
        r"<svg.*onload",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.%2f",
    ]
    
    # Command injection patterns
    CMD_INJECTION_PATTERNS = [
        r";\s*(ls|cat|wget|curl|nc|bash|sh)",
        r"\|\s*(ls|cat|wget|curl|nc|bash|sh)",
        r"`.*`",
        r"\$\(.*\)",
    ]
    
    # Suspicious scanner user agents
    SCANNER_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster',
        'burp', 'acunetix', 'nessus', 'openvas', 'w3af'
    ]
    
    def __init__(self, config=None):
        """
        Initialize intrusion detector
        
        Args:
            config: Configuration dict with rate limits, etc.
        """
        self.config = config or {}
        
        # Rate limiting
        self.rate_limit = self.config.get('RATE_LIMIT_REQUESTS', 150)
        self.rate_warning = self.config.get('RATE_LIMIT_WARNING', 80)
        
        # Tracking dictionaries
        self.request_tracker = defaultdict(list)
        self.sql_attempts = defaultdict(int)
        self.xss_attempts = defaultdict(int)
        self.path_attempts = defaultdict(int)
        self.cmd_attempts = defaultdict(int)
        
    def check_rate_limit(self, ip_address):
        """
        Check if IP is making too many requests
        
        Args:
            ip_address (str): Client IP address
            
        Returns:
            tuple: (is_blocked, request_count, severity)
        """
        now = time.time()
        
        # Add current request
        self.request_tracker[ip_address].append(now)
        
        # Remove requests older than 60 seconds
        self.request_tracker[ip_address] = [
            t for t in self.request_tracker[ip_address] 
            if now - t < 60
        ]
        
        count = len(self.request_tracker[ip_address])
        
        if count > self.rate_limit:
            return (True, count, 'Critical')  # Block
        elif count > self.rate_warning:
            return (False, count, 'Medium')   # Warn
        else:
            return (False, count, 'Low')      # Normal
            
    def detect_sql_injection(self, value, ip_address):
        """
        Detect SQL injection attempts
        
        Args:
            value (str): Input value to check
            ip_address (str): Client IP
            
        Returns:
            bool: True if SQL injection detected
        """
        value_lower = str(value).lower()
        
        for pattern in self.SQL_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                self.sql_attempts[ip_address] += 1
                return True
                
        return False
        
    def detect_xss(self, value, ip_address):
        """
        Detect XSS attacks
        
        Args:
            value (str): Input value to check
            ip_address (str): Client IP
            
        Returns:
            bool: True if XSS detected
        """
        value_str = str(value)
        
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value_str, re.IGNORECASE):
                self.xss_attempts[ip_address] += 1
                return True
                
        return False
        
    def detect_path_traversal(self, value, ip_address):
        """
        Detect path traversal attempts
        
        Args:
            value (str): Input value to check
            ip_address (str): Client IP
            
        Returns:
            bool: True if path traversal detected
        """
        value_str = str(value)
        
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value_str, re.IGNORECASE):
                self.path_attempts[ip_address] += 1
                return True
                
        return False
        
    def detect_command_injection(self, value, ip_address):
        """
        Detect command injection attempts
        
        Args:
            value (str): Input value to check
            ip_address (str): Client IP
            
        Returns:
            bool: True if command injection detected
        """
        value_str = str(value)
        
        for pattern in self.CMD_INJECTION_PATTERNS:
            if re.search(pattern, value_str):
                self.cmd_attempts[ip_address] += 1
                return True
                
        return False
        
    def detect_scanner(self, user_agent):
        """
        Detect security scanner tools
        
        Args:
            user_agent (str): User-Agent header
            
        Returns:
            bool: True if scanner detected
        """
        if not user_agent:
            return False
            
        ua_lower = user_agent.lower()
        
        for scanner in self.SCANNER_AGENTS:
            if scanner in ua_lower:
                return True
                
        return False
        
    def get_ip_stats(self, ip_address):
        """
        Get attack statistics for an IP
        
        Args:
            ip_address (str): Client IP
            
        Returns:
            dict: Attack statistics
        """
        return {
            'sql_attempts': self.sql_attempts.get(ip_address, 0),
            'xss_attempts': self.xss_attempts.get(ip_address, 0),
            'path_attempts': self.path_attempts.get(ip_address, 0),
            'cmd_attempts': self.cmd_attempts.get(ip_address, 0),
            'total_requests': len(self.request_tracker.get(ip_address, [])),
            'is_suspicious': self._is_suspicious_ip(ip_address)
        }
        
    def _is_suspicious_ip(self, ip_address):
        """Check if IP has suspicious activity"""
        stats = {
            'sql': self.sql_attempts.get(ip_address, 0),
            'xss': self.xss_attempts.get(ip_address, 0),
            'path': self.path_attempts.get(ip_address, 0),
            'cmd': self.cmd_attempts.get(ip_address, 0)
        }
        
        # Consider suspicious if any attack type > 3 attempts
        return any(count > 3 for count in stats.values())
        
    def clear_old_data(self, max_age_seconds=3600):
        """
        Clear tracking data older than max_age
        
        Args:
            max_age_seconds (int): Max age in seconds (default 1 hour)
        """
        now = time.time()
        
        # Clear old request tracker entries
        for ip in list(self.request_tracker.keys()):
            self.request_tracker[ip] = [
                t for t in self.request_tracker[ip]
                if now - t < max_age_seconds
            ]
            if not self.request_tracker[ip]:
                del self.request_tracker[ip]
                