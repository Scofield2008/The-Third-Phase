"""
SALT SIEM v3.0 - Notification System
Handles alerts, emails, webhooks, and desktop notifications
"""

import os
import json
import datetime
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional


class NotificationManager:
    """Manages all notification types for SALT SIEM"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.notification_history = []
        self.enabled_channels = {
            'console': True,
            'email': self.config.get('email_enabled', False),
            'webhook': self.config.get('webhook_enabled', False),
            'desktop': self.config.get('desktop_enabled', False)
        }
        
        # Email configuration
        self.smtp_server = self.config.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.smtp_username = self.config.get('smtp_username', '')
        self.smtp_password = self.config.get('smtp_password', '')
        self.email_from = self.config.get('email_from', 'salt-siem@example.com')
        self.email_to = self.config.get('email_to', [])
        
        # Webhook configuration
        self.webhook_url = self.config.get('webhook_url', '')
        self.webhook_headers = self.config.get('webhook_headers', {'Content-Type': 'application/json'})
        
        # Notification thresholds
        self.min_severity = self.config.get('min_severity', 'Medium')
        self.severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    
    def should_notify(self, severity: str) -> bool:
        """Check if notification should be sent based on severity"""
        current_level = self.severity_levels.get(severity, 0)
        min_level = self.severity_levels.get(self.min_severity, 0)
        return current_level >= min_level
    
    def send_notification(self, alert_type: str, severity: str, message: str, 
                         metadata: Optional[Dict] = None) -> Dict:
        """
        Send notification through all enabled channels
        
        Args:
            alert_type: Type of alert (Malware Detection, SQL Injection, etc.)
            severity: Alert severity (Low, Medium, High, Critical)
            message: Alert message
            metadata: Additional data (file hash, IP, etc.)
        
        Returns:
            Dictionary with status of each notification channel
        """
        if not self.should_notify(severity):
            return {'sent': False, 'reason': 'Below minimum severity threshold'}
        
        notification = {
            'timestamp': datetime.datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'metadata': metadata or {}
        }
        
        results = {}
        
        # Console notification (always enabled)
        if self.enabled_channels['console']:
            results['console'] = self._send_console(notification)
        
        # Email notification
        if self.enabled_channels['email']:
            results['email'] = self._send_email(notification)
        
        # Webhook notification
        if self.enabled_channels['webhook']:
            results['webhook'] = self._send_webhook(notification)
        
        # Save to history
        self.notification_history.append({
            **notification,
            'results': results
        })
        
        # Keep only last 100 notifications
        if len(self.notification_history) > 100:
            self.notification_history = self.notification_history[-100:]
        
        return results
    
    def _send_console(self, notification: Dict) -> Dict:
        """Print notification to console"""
        try:
            severity_icon = {
                'Low': '✓',
                'Medium': '⚠️',
                'High': '🔴',
                'Critical': '🚨'
            }.get(notification['severity'], 'ℹ️')
            
            print(f"\n{'='*70}")
            print(f"{severity_icon} SALT SIEM ALERT - {notification['severity'].upper()}")
            print(f"{'='*70}")
            print(f"Type: {notification['type']}")
            print(f"Time: {notification['timestamp']}")
            print(f"Message: {notification['message']}")
            if notification['metadata']:
                print(f"Details: {json.dumps(notification['metadata'], indent=2)}")
            print(f"{'='*70}\n")
            
            return {'success': True, 'method': 'console'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_email(self, notification: Dict) -> Dict:
        """Send email notification"""
        if not self.smtp_username or not self.email_to:
            return {'success': False, 'error': 'Email not configured'}
        
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[SALT SIEM] {notification['severity']} Alert: {notification['type']}"
            msg['From'] = self.email_from
            msg['To'] = ', '.join(self.email_to)
            
            # HTML email body
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
                <div style="background: white; padding: 20px; border-radius: 8px; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #d32f2f; margin-top: 0;">SALT SIEM Alert</h2>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Severity:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #eee; color: #d32f2f;">{notification['severity']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Type:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;">{notification['type']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Time:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;">{notification['timestamp']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>Message:</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #eee;">{notification['message']}</td>
                        </tr>
                    </table>
                    
                    {self._format_metadata_html(notification['metadata']) if notification['metadata'] else ''}
                    
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
                        <p>This is an automated alert from SALT SIEM v3.0</p>
                        <p>Please review the incident in your SALT dashboard.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            return {'success': True, 'method': 'email', 'recipients': len(self.email_to)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_webhook(self, notification: Dict) -> Dict:
        """Send webhook notification (Slack, Discord, etc.)"""
        if not self.webhook_url:
            return {'success': False, 'error': 'Webhook not configured'}
        
        try:
            # Format payload based on webhook type
            payload = self._format_webhook_payload(notification)
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.webhook_headers,
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                return {'success': True, 'method': 'webhook', 'status_code': response.status_code}
            else:
                return {'success': False, 'status_code': response.status_code, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _format_webhook_payload(self, notification: Dict) -> Dict:
        """Format notification for webhook (Slack/Discord compatible)"""
        color_map = {
            'Low': '#3fb950',
            'Medium': '#d29922',
            'High': '#f85149',
            'Critical': '#da3633'
        }
        
        # Slack/Discord compatible format
        payload = {
            'username': 'SALT SIEM',
            'embeds': [{
                'title': f'{notification["severity"]} Alert: {notification["type"]}',
                'description': notification['message'],
                'color': int(color_map.get(notification['severity'], '#ffffff').replace('#', ''), 16),
                'fields': [
                    {'name': 'Severity', 'value': notification['severity'], 'inline': True},
                    {'name': 'Type', 'value': notification['type'], 'inline': True},
                    {'name': 'Time', 'value': notification['timestamp'], 'inline': False}
                ],
                'footer': {'text': 'SALT SIEM v3.0'},
                'timestamp': notification['timestamp']
            }]
        }
        
        # Add metadata fields
        if notification.get('metadata'):
            for key, value in notification['metadata'].items():
                payload['embeds'][0]['fields'].append({
                    'name': key.replace('_', ' ').title(),
                    'value': str(value),
                    'inline': True
                })
        
        return payload
    
    def _format_metadata_html(self, metadata: Dict) -> str:
        """Format metadata as HTML table"""
        if not metadata:
            return ''
        
        html = '<h3 style="margin-top: 20px;">Additional Details</h3><table style="width: 100%; border-collapse: collapse;">'
        for key, value in metadata.items():
            html += f'''
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>{key.replace('_', ' ').title()}:</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">{value}</td>
            </tr>
            '''
        html += '</table>'
        return html
    
    def test_notifications(self) -> Dict:
        """Test all enabled notification channels"""
        test_notification = {
            'timestamp': datetime.datetime.now().isoformat(),
            'type': 'Test Alert',
            'severity': 'Low',
            'message': 'This is a test notification from SALT SIEM',
            'metadata': {'test': True}
        }
        
        results = {}
        
        if self.enabled_channels['console']:
            results['console'] = self._send_console(test_notification)
        
        if self.enabled_channels['email']:
            results['email'] = self._send_email(test_notification)
        
        if self.enabled_channels['webhook']:
            results['webhook'] = self._send_webhook(test_notification)
        
        return results
    
    def configure_email(self, smtp_server: str, smtp_port: int, username: str, 
                       password: str, email_from: str, email_to: List[str]):
        """Configure email notifications"""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_username = username
        self.smtp_password = password
        self.email_from = email_from
        self.email_to = email_to
        self.enabled_channels['email'] = True
    
    def configure_webhook(self, url: str, headers: Optional[Dict] = None):
        """Configure webhook notifications"""
        self.webhook_url = url
        if headers:
            self.webhook_headers = headers
        self.enabled_channels['webhook'] = True
    
    def disable_channel(self, channel: str):
        """Disable a notification channel"""
        if channel in self.enabled_channels:
            self.enabled_channels[channel] = False
    
    def enable_channel(self, channel: str):
        """Enable a notification channel"""
        if channel in self.enabled_channels:
            self.enabled_channels[channel] = True
    
    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get notification history"""
        return self.notification_history[-limit:]
    
    def get_stats(self) -> Dict:
        """Get notification statistics"""
        total = len(self.notification_history)
        successful = sum(1 for n in self.notification_history 
                        if any(r.get('success') for r in n.get('results', {}).values()))
        
        by_severity = {}
        for notification in self.notification_history:
            severity = notification['severity']
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_notifications': total,
            'successful': successful,
            'failed': total - successful,
            'by_severity': by_severity,
            'enabled_channels': [k for k, v in self.enabled_channels.items() if v]
        }


# Quick test function
def test_notification_system():
    """Test the notification system"""
    manager = NotificationManager({
        'min_severity': 'Low',
        'email_enabled': False,  # Set to True and configure to test
        'webhook_enabled': False  # Set to True and configure to test
    })
    
    print("Testing notification system...")
    
    # Test console notification
    result = manager.send_notification(
        alert_type='Test Alert',
        severity='High',
        message='This is a test notification',
        metadata={'test': True, 'source': 'test_function'}
    )
    
    print("\nNotification Results:")
    print(json.dumps(result, indent=2))
    
    # Get stats
    stats = manager.get_stats()
    print("\nNotification Stats:")
    print(json.dumps(stats, indent=2))


if __name__ == '__main__':
    test_notification_system()