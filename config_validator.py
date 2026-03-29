"""Configuration validator for email alert settings.

Provides utilities to validate SMTP configuration before deployment.
"""

import json
import re
import smtplib
from email.mime.text import MIMEText


class ConfigValidator:
    """Validates email configuration for alert system."""
    
    def __init__(self, config_path="alert_config.json"):
        self.config_path = config_path
        self.config = None
        self.errors = []
    
    def load_config(self):
        """Load configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
            return True
        except FileNotFoundError:
            self.errors.append(f"Config file not found: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON format: {str(e)}")
            return False
    
    def validate_email_format(self, email):
        """Validate email address format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_structure(self):
        """Validate config file structure."""
        if not self.config:
            self.errors.append("No configuration loaded")
            return False
        
        required_fields = ['smtp_server', 'smtp_port', 'sender_email', 'receiver_email']
        missing = [field for field in required_fields if field not in self.config]
        
        if missing:
            self.errors.append(f"Missing required fields: {', '.join(missing)}")
            return False
        
        # Validate email formats
        if not self.validate_email_format(self.config['sender_email']):
            self.errors.append(f"Invalid sender email: {self.config['sender_email']}")
            return False
        
        if not self.validate_email_format(self.config['receiver_email']):
            self.errors.append(f"Invalid receiver email: {self.config['receiver_email']}")
            return False
        
        # Validate port
        try:
            port = int(self.config['smtp_port'])
            if port < 1 or port > 65535:
                self.errors.append(f"Invalid port number: {port}")
                return False
        except ValueError:
            self.errors.append(f"Port must be an integer: {self.config['smtp_port']}")
            return False
        
        return True
    
    def test_connection(self):
        """Test SMTP server connection (without authentication)."""
        if not self.config:
            self.errors.append("No configuration to test")
            return False
        
        try:
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.ehlo()
            server.quit()
            return True
        except Exception as e:
            self.errors.append(f"Connection test failed: {str(e)}")
            return False
    
    def validate_all(self, test_connection=False):
        """Run all validation checks."""
        self.errors = []  # Reset errors
        
        if not self.load_config():
            return False
        
        if not self.validate_structure():
            return False
        
        if test_connection and not self.test_connection():
            return False
        
        return True
    
    def get_report(self):
        """Get validation report."""
        if not self.errors:
            return "✓ Configuration is valid"
        
        report = "Configuration validation failed:\n"
        for i, error in enumerate(self.errors, 1):
            report += f"  {i}. {error}\n"
        return report


if __name__ == "__main__":
    # Quick validation test
    validator = ConfigValidator()
    
    print("Validating email configuration...")
    is_valid = validator.validate_all(test_connection=False)
    
    print(validator.get_report())
    
    if is_valid:
        print("\nConfiguration ready for use!")
    else:
        print("\nPlease fix errors before deploying.")
