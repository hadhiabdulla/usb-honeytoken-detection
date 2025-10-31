#!/usr/bin/env python3
"""
Test Cases Module
Unit tests for USB Honeytoken Detection System
"""

import unittest
import os
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from honeytoken_manager import HoneytokenManager
from alert import AlertSystem


class TestHoneytokenManager(unittest.TestCase):
    """
    Test cases for HoneytokenManager class
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.test_dir, 'test_config.json')
        self.manager = HoneytokenManager(config_file=self.config_file)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_create_honeytoken(self):
        """Test honeytoken creation"""
        token_id, content = self.manager.create_honeytoken("test_token.txt", "text")
        
        self.assertIsNotNone(token_id)
        self.assertIsNotNone(content)
        self.assertIn(token_id, self.manager.honeytokens)
        self.assertEqual(self.manager.honeytokens[token_id]['name'], "test_token.txt")
    
    def test_create_multiple_honeytokens(self):
        """Test creating multiple honeytokens"""
        token_id1, _ = self.manager.create_honeytoken("token1.txt", "text")
        token_id2, _ = self.manager.create_honeytoken("token2.txt", "document")
        
        self.assertEqual(len(self.manager.honeytokens), 2)
        self.assertNotEqual(token_id1, token_id2)
    
    def test_deploy_honeytoken(self):
        """Test honeytoken deployment"""
        token_id, _ = self.manager.create_honeytoken("deploy_test.txt", "text")
        target_path = self.test_dir
        
        result = self.manager.deploy_honeytoken(token_id, target_path)
        
        self.assertTrue(result)
        deployed_file = Path(target_path) / "deploy_test.txt"
        self.assertTrue(deployed_file.exists())
    
    def test_deploy_nonexistent_token(self):
        """Test deploying a non-existent token"""
        result = self.manager.deploy_honeytoken("nonexistent_token", self.test_dir)
        self.assertFalse(result)
    
    def test_save_and_load_config(self):
        """Test configuration save and load"""
        token_id, _ = self.manager.create_honeytoken("config_test.txt", "text")
        
        # Create new manager instance with same config file
        new_manager = HoneytokenManager(config_file=self.config_file)
        
        self.assertEqual(len(new_manager.honeytokens), 1)
        self.assertIn(token_id, new_manager.honeytokens)
    
    def test_check_access_no_access(self):
        """Test checking for access when no access occurred"""
        token_id, _ = self.manager.create_honeytoken("access_test.txt", "text")
        self.manager.deploy_honeytoken(token_id, self.test_dir)
        
        accessed = self.manager.check_access()
        
        # Should return empty list if no recent access
        self.assertIsInstance(accessed, list)
    
    def test_list_honeytokens(self):
        """Test listing all honeytokens"""
        self.manager.create_honeytoken("token1.txt", "text")
        self.manager.create_honeytoken("token2.txt", "document")
        
        tokens = self.manager.list_honeytokens()
        
        self.assertEqual(len(tokens), 2)
        self.assertIsInstance(tokens, dict)
    
    def test_honeytoken_content_generation(self):
        """Test that honeytoken content is generated correctly"""
        token_id, content = self.manager.create_honeytoken("content_test.txt", "text")
        
        self.assertIn("CONFIDENTIAL", content)
        self.assertIn("API Keys", content)
        self.assertTrue(len(content) > 0)


class TestAlertSystem(unittest.TestCase):
    """
    Test cases for AlertSystem class
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.test_dir, 'test_alert_config.json')
        self.alert_system = AlertSystem(config_file=self.config_file)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_load_default_config(self):
        """Test loading default configuration"""
        self.assertIn('email', self.alert_system.config)
        self.assertIn('log', self.alert_system.config)
        self.assertIn('console', self.alert_system.config)
    
    def test_send_console_alert(self):
        """Test sending console alert"""
        test_tokens = [{
            'token_id': 'test_1',
            'name': 'test.txt',
            'path': '/test/path/test.txt',
            'access_time': '2025-10-31T21:00:00'
        }]
        
        # Should not raise exception
        try:
            self.alert_system.send_alert('test_device', test_tokens)
            success = True
        except Exception:
            success = False
        
        self.assertTrue(success)
    
    def test_alert_log(self):
        """Test alert logging"""
        test_tokens = [{
            'token_id': 'test_1',
            'name': 'test.txt',
            'path': '/test/path/test.txt',
            'access_time': '2025-10-31T21:00:00'
        }]
        
        self.alert_system.send_alert('test_device', test_tokens)
        
        log = self.alert_system.get_alert_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]['device_info'], 'test_device')
    
    def test_configure_email(self):
        """Test email configuration"""
        self.alert_system.configure_email(
            smtp_server='smtp.test.com',
            smtp_port=587,
            sender='test@test.com',
            password='testpass',
            recipients=['recipient@test.com']
        )
        
        self.assertTrue(self.alert_system.config['email']['enabled'])
        self.assertEqual(self.alert_system.config['email']['sender'], 'test@test.com')
        self.assertEqual(self.alert_system.config['email']['recipients'], ['recipient@test.com'])
    
    def test_save_and_load_config(self):
        """Test configuration save and load"""
        self.alert_system.config['console']['enabled'] = False
        self.alert_system.save_config()
        
        # Create new instance with same config file
        new_alert_system = AlertSystem(config_file=self.config_file)
        
        self.assertFalse(new_alert_system.config['console']['enabled'])
    
    @patch('smtplib.SMTP')
    def test_send_email_alert(self, mock_smtp):
        """Test sending email alert (mocked)"""
        # Configure email
        self.alert_system.configure_email(
            smtp_server='smtp.test.com',
            smtp_port=587,
            sender='test@test.com',
            password='testpass',
            recipients=['recipient@test.com']
        )
        
        test_tokens = [{
            'token_id': 'test_1',
            'name': 'test.txt',
            'path': '/test/path/test.txt',
            'access_time': '2025-10-31T21:00:00'
        }]
        
        # Mock SMTP server
        mock_smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
        
        # Should not raise exception
        try:
            self.alert_system.send_alert('test_device', test_tokens)
            success = True
        except Exception:
            success = False
        
        self.assertTrue(success)


class TestIntegration(unittest.TestCase):
    """
    Integration tests for the complete system
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.manager = HoneytokenManager(config_file=os.path.join(self.test_dir, 'tokens.json'))
        self.alert_system = AlertSystem(config_file=os.path.join(self.test_dir, 'alerts.json'))
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_full_workflow(self):
        """Test complete workflow from creation to alert"""
        # Create honeytoken
        token_id, content = self.manager.create_honeytoken("workflow_test.txt", "text")
        self.assertIsNotNone(token_id)
        
        # Deploy honeytoken
        result = self.manager.deploy_honeytoken(token_id, self.test_dir)
        self.assertTrue(result)
        
        # Verify file exists
        deployed_file = Path(self.test_dir) / "workflow_test.txt"
        self.assertTrue(deployed_file.exists())
        
        # Check that we can read the file
        with open(deployed_file, 'r') as f:
            file_content = f.read()
        self.assertEqual(file_content, content)
    
    def test_multiple_token_deployment(self):
        """Test deploying multiple honeytokens"""
        # Create multiple tokens
        tokens = []
        for i in range(3):
            token_id, _ = self.manager.create_honeytoken(f"token_{i}.txt", "text")
            tokens.append(token_id)
            self.manager.deploy_honeytoken(token_id, self.test_dir)
        
        # Verify all files exist
        for i in range(3):
            file_path = Path(self.test_dir) / f"token_{i}.txt"
            self.assertTrue(file_path.exists())


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)
