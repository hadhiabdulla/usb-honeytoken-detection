#!/usr/bin/env python3
"""
Alert System Module
Handles notifications when honeytoken access is detected
"""

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AlertSystem:
    """
    Manages alert notifications for honeytoken access detection
    """
    
    def __init__(self, config_file="alert_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.alert_log = []
    
    def load_config(self):
        """
        Load alert configuration from file
        """
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender': '',
                'password': '',
                'recipients': []
            },
            'log': {
                'enabled': True,
                'log_file': 'honeytoken_alerts.log'
            },
            'console': {
                'enabled': True
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    for key in default_config:
                        if key in loaded_config:
                            default_config[key].update(loaded_config[key])
                logger.info("Alert configuration loaded")
            else:
                logger.info("No alert config found, using defaults")
                self.save_config(default_config)
        except Exception as e:
            logger.error(f"Error loading alert config: {e}")
        
        return default_config
    
    def save_config(self, config=None):
        """
        Save alert configuration to file
        """
        try:
            if config is None:
                config = self.config
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info("Alert configuration saved")
        except Exception as e:
            logger.error(f"Error saving alert config: {e}")
    
    def send_alert(self, device_info, tokens):
        """
        Send alert through configured channels
        """
        timestamp = datetime.now().isoformat()
        
        alert_data = {
            'timestamp': timestamp,
            'device_info': device_info,
            'tokens': tokens
        }
        
        # Log to alert log
        self.alert_log.append(alert_data)
        
        # Console alert
        if self.config['console']['enabled']:
            self._send_console_alert(alert_data)
        
        # Log file alert
        if self.config['log']['enabled']:
            self._send_log_alert(alert_data)
        
        # Email alert
        if self.config['email']['enabled']:
            self._send_email_alert(alert_data)
    
    def _send_console_alert(self, alert_data):
        """
        Display alert in console
        """
        print("\n" + "="*60)
        print("🚨 HONEYTOKEN ACCESS DETECTED! 🚨")
        print("="*60)
        print(f"Timestamp: {alert_data['timestamp']}")
        print(f"Device: {alert_data['device_info']}")
        print("\nAccessed Honeytokens:")
        for token in alert_data['tokens']:
            print(f"  - {token['name']} (ID: {token['token_id']})")
            print(f"    Path: {token['path']}")
            print(f"    Access Time: {token['access_time']}")
        print("="*60 + "\n")
    
    def _send_log_alert(self, alert_data):
        """
        Write alert to log file
        """
        try:
            log_file = self.config['log']['log_file']
            
            with open(log_file, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"ALERT: Honeytoken Access Detected\n")
                f.write(f"Timestamp: {alert_data['timestamp']}\n")
                f.write(f"Device: {alert_data['device_info']}\n")
                f.write(f"Tokens:\n")
                for token in alert_data['tokens']:
                    f.write(f"  - {token['name']} ({token['token_id']})\n")
                    f.write(f"    Path: {token['path']}\n")
                    f.write(f"    Access: {token['access_time']}\n")
                f.write(f"{'='*60}\n")
            
            logger.info(f"Alert logged to {log_file}")
            
        except Exception as e:
            logger.error(f"Error writing to log file: {e}")
    
    def _send_email_alert(self, alert_data):
        """
        Send alert via email
        """
        try:
            email_config = self.config['email']
            
            if not email_config['sender'] or not email_config['recipients']:
                logger.warning("Email not configured properly, skipping email alert")
                return
            
            # Create message
            subject = f"🚨 Honeytoken Access Alert - {alert_data['timestamp']}"
            
            body = f"""HONEYTOKEN ACCESS DETECTED!

Timestamp: {alert_data['timestamp']}
Device Information: {alert_data['device_info']}

Accessed Honeytokens:
"""
            
            for token in alert_data['tokens']:
                body += f"\n- Token: {token['name']} (ID: {token['token_id']})"
                body += f"\n  Path: {token['path']}"
                body += f"\n  Access Time: {token['access_time']}\n"
            
            body += "\n" + "="*60
            body += "\nThis is an automated security alert from USB Honeytoken Detection System."
            body += "\nPlease investigate immediately."
            
            # Create MIME message
            msg = MIMEMultipart()
            msg['From'] = email_config['sender']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                if email_config.get('password'):
                    server.login(email_config['sender'], email_config['password'])
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {email_config['recipients']}")
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
    
    def get_alert_log(self):
        """
        Return the alert log
        """
        return self.alert_log
    
    def configure_email(self, smtp_server, smtp_port, sender, password, recipients):
        """
        Configure email alert settings
        """
        self.config['email'] = {
            'enabled': True,
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'sender': sender,
            'password': password,
            'recipients': recipients if isinstance(recipients, list) else [recipients]
        }
        self.save_config()
        logger.info("Email configuration updated")
    
    def test_alert(self):
        """
        Send a test alert to verify configuration
        """
        test_data = {
            'timestamp': datetime.now().isoformat(),
            'device_info': 'Test Device',
            'tokens': [{
                'token_id': 'test_token_1',
                'name': 'Test_Honeytoken.txt',
                'path': '/test/path/Test_Honeytoken.txt',
                'access_time': datetime.now().isoformat()
            }]
        }
        
        logger.info("Sending test alert...")
        self.send_alert(test_data['device_info'], test_data['tokens'])


if __name__ == "__main__":
    # Example usage
    alert_system = AlertSystem()
    
    # Send a test alert
    alert_system.test_alert()
    
    logger.info("Alert system initialized and test alert sent")
