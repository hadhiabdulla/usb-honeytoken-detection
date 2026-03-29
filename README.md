# USB Honeytoken Detection System

A security tool for detecting unauthorized USB device access using honeytoken techniques. This system monitors USB connections and deploys decoy files (honeytokens) to detect and alert on unauthorized data access attempts.

## Project Overview

The USB Honeytoken Detection System is designed to enhance security by detecting when USB devices are used to access sensitive information. It deploys honeytokens (decoy files) that appear to contain valuable information but actually serve as tripwires to alert administrators when accessed.

**Last Updated:** October 31, 2025

## Architecture

The system consists of four main modules:

### 1. USB Monitor (`usb_monitor.py`)
- Monitors USB device connections in real-time
- Supports both pyudev-based monitoring (Linux) and fallback polling methods (cross-platform)
- Triggers honeytoken access checks when new devices are detected
- Integrates with the alert system for immediate notifications

### 2. Honeytoken Manager (`honeytoken_manager.py`)
- Creates and manages honeytoken files with realistic content
- Supports multiple content types (text documents, API keys, credentials)
- Tracks honeytoken deployment and access patterns
- Maintains persistent configuration and access logs
- Monitors file access times to detect unauthorized access

### 3. Alert System (`alert.py`)
- Multi-channel notification system (console, log file, email)
- Configurable alert settings via JSON configuration
- Detailed alert information including device info and accessed tokens
- SMTP email support for remote notifications
- Persistent alert logging

### 4. Test Suite (`test_cases.py`)
- Comprehensive unit tests for all modules
- Integration tests for complete workflows
- Uses unittest framework with mock support
- Tests cover creation, deployment, and detection scenarios

## System Requirements

- Python 3.7+
- Operating System: Windows, Linux, macOS
- Optional: `pyudev` library (for enhanced Linux USB monitoring)

## Installation

```bash
# Clone the repository
git clone https://github.com/hadhiabdulla/usb-honeytoken-detection.git
cd usb-honeytoken-detection
git checkout project

# Install optional dependencies (Linux only)
pip install pyudev
```

## Quick Start

### 1. Create and Deploy Honeytokens

```python
from honeytoken_manager import HoneytokenManager

# Initialize the manager
manager = HoneytokenManager()

# Create honeytokens
token_id1, content1 = manager.create_honeytoken("Confidential_API_Keys.txt", "text")
token_id2, content2 = manager.create_honeytoken("Secret_Document.txt", "document")

# Deploy to a target directory (e.g., Documents folder)
manager.deploy_honeytoken(token_id1, "/path/to/target/directory")
manager.deploy_honeytoken(token_id2, "/path/to/target/directory")
```

### 2. Start USB Monitoring

```python
from usb_monitor import USBMonitor

# Initialize and start monitoring
monitor = USBMonitor()
try:
    monitor.start_monitoring()
except KeyboardInterrupt:
    monitor.stop_monitoring()
    print("Monitoring stopped")
```

### 3. Configure Alerts (Optional)

```python
from alert import AlertSystem

# Initialize alert system
alert_system = AlertSystem()

# Configure email alerts
alert_system.configure_email(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    sender='your-email@gmail.com',
    password='your-app-password',
    recipients=['security-team@company.com']
)

# Test the alert system
alert_system.test_alert()
```

### 4. Run Tests

```bash
# Run all tests with verbose output
python test_cases.py -v

# Run specific test class
python -m unittest test_cases.TestHoneytokenManager -v
```

## Usage Example

```python
#!/usr/bin/env python3

from usb_monitor import USBMonitor
from honeytoken_manager import HoneytokenManager
from alert import AlertSystem
import os

def main():
    # Initialize components
    manager = HoneytokenManager()
    alert_system = AlertSystem()
    
    # Create and deploy honeytokens
    print("Creating honeytokens...")
    token1, _ = manager.create_honeytoken("Company_Credentials.txt", "text")
    token2, _ = manager.create_honeytoken("Financial_Report.txt", "document")
    
    # Deploy to Documents folder
    docs_path = os.path.expanduser("~/Documents")
    manager.deploy_honeytoken(token1, docs_path)
    manager.deploy_honeytoken(token2, docs_path)
    
    print(f"Deployed honeytokens to {docs_path}")
    
    # Start monitoring
    print("Starting USB monitoring...")
    monitor = USBMonitor()
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("\nMonitoring stopped by user")

if __name__ == "__main__":
    main()
```

## Configuration Files

The system uses JSON configuration files:

- `honeytoken_config.json` - Stores honeytoken metadata and access logs
- `alert_config.json` - Alert system configuration (email, logging settings)

These files are created automatically on first run with default settings.

## Security Considerations

- Honeytokens should contain realistic but fake information
- Deploy honeytokens in locations where they appear valuable but aren't actually sensitive
- Regularly rotate honeytoken content to maintain effectiveness
- Monitor alert logs regularly for potential security incidents
- Keep email credentials secure (use app-specific passwords)

## Testing

The test suite includes:

- **Unit Tests**: Individual component testing (HoneytokenManager, AlertSystem)
- **Integration Tests**: Full workflow testing (creation → deployment → detection)
- **Mock Tests**: Email and SMTP functionality testing

Run tests before deployment to ensure system integrity.

## Troubleshooting

### USB Monitoring Not Working
- **Linux**: Install `pyudev` for enhanced monitoring: `pip install pyudev`
- **Windows/Mac**: System uses fallback polling method automatically
- Check system permissions for USB device access

### Email Alerts Not Sending
- Verify SMTP settings in `alert_config.json`
- Use app-specific passwords for Gmail (not regular password)
- Check firewall settings for SMTP port access (587 or 465)

### Honeytokens Not Detected
- Ensure honeytokens are deployed before monitoring starts
- Check file access time detection threshold (default: 60 seconds)
- Verify file permissions allow read access

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License

Copyright (c) 2025 Hadhi Abdulla

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments

- Built as part of a security research project
- Inspired by honeytoken and honeypot security concepts
- Designed for educational and security monitoring purposes

## Contact

For questions or support, please open an issue on GitHub.

---

**Note**: This tool is designed for legitimate security monitoring purposes only. Ensure compliance with applicable laws and regulations in your jurisdiction before deployment.
