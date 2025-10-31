#!/usr/bin/env python3
"""
USB Monitor Module
Monitors USB device connections and triggers honeytoken checks
"""

import os
import time
import logging
from pathlib import Path
try:
    import pyudev
except ImportError:
    pyudev = None

from honeytoken_manager import HoneytokenManager
from alert import AlertSystem

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class USBMonitor:
    """
    Monitors USB device connections and checks for honeytoken access
    """
    
    def __init__(self):
        self.honeytoken_manager = HoneytokenManager()
        self.alert_system = AlertSystem()
        self.monitoring = False
        
    def start_monitoring(self):
        """
        Start monitoring USB device connections
        """
        logger.info("Starting USB monitoring...")
        self.monitoring = True
        
        if pyudev:
            self._monitor_with_pyudev()
        else:
            logger.warning("pyudev not available, using fallback monitoring")
            self._monitor_fallback()
    
    def _monitor_with_pyudev(self):
        """
        Monitor USB connections using pyudev
        """
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='usb')
        
        logger.info("Monitoring USB devices with pyudev...")
        
        for device in iter(monitor.poll, None):
            if not self.monitoring:
                break
                
            if device.action == 'add':
                logger.info(f"USB device connected: {device.device_node}")
                self._check_device(device)
    
    def _monitor_fallback(self):
        """
        Fallback monitoring method by checking mount points
        """
        logger.info("Using fallback USB monitoring...")
        known_devices = set()
        
        while self.monitoring:
            try:
                if os.name == 'nt':  # Windows
                    import string
                    from ctypes import windll
                    
                    drives = []
                    bitmask = windll.kernel32.GetLogicalDrives()
                    for letter in string.ascii_uppercase:
                        if bitmask & 1:
                            drives.append(letter)
                        bitmask >>= 1
                    
                    current_devices = set(drives)
                else:  # Unix-like
                    media_path = Path('/media') / os.getenv('USER', '')
                    if media_path.exists():
                        current_devices = set([d.name for d in media_path.iterdir() if d.is_dir()])
                    else:
                        current_devices = set()
                
                new_devices = current_devices - known_devices
                
                for device in new_devices:
                    logger.info(f"New device detected: {device}")
                    self._check_device_by_name(device)
                
                known_devices = current_devices
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error in fallback monitoring: {e}")
                time.sleep(2)
    
    def _check_device(self, device):
        """
        Check if device accessed honeytokens
        """
        try:
            # Check for honeytoken access
            accessed_tokens = self.honeytoken_manager.check_access()
            
            if accessed_tokens:
                logger.warning(f"Honeytoken access detected! Tokens: {accessed_tokens}")
                self.alert_system.send_alert(
                    device_info=str(device),
                    tokens=accessed_tokens
                )
        except Exception as e:
            logger.error(f"Error checking device: {e}")
    
    def _check_device_by_name(self, device_name):
        """
        Check device by name for honeytoken access
        """
        try:
            accessed_tokens = self.honeytoken_manager.check_access()
            
            if accessed_tokens:
                logger.warning(f"Honeytoken access detected on {device_name}! Tokens: {accessed_tokens}")
                self.alert_system.send_alert(
                    device_info=device_name,
                    tokens=accessed_tokens
                )
        except Exception as e:
            logger.error(f"Error checking device {device_name}: {e}")
    
    def stop_monitoring(self):
        """
        Stop USB monitoring
        """
        logger.info("Stopping USB monitoring...")
        self.monitoring = False


if __name__ == "__main__":
    monitor = USBMonitor()
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        logger.info("Monitoring stopped by user")
