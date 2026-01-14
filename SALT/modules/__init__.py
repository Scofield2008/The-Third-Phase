"""
SALT SIEM v3.0 - Modules Package
Security Analytics and Logging Tool
"""

__version__ = '3.0.0'
__author__ = 'SALT SIEM '

# Import main modules for easy access
from .zone_sandbox import ZoneSandbox
from .intrusion_detection import IntrusionDetector
from .notification import NotificationManager

__all__ = [
    'ZoneSandbox',
    'IntrusionDetector', 
    'NotificationManager'
]