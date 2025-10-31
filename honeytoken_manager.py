#!/usr/bin/env python3
"""
Honeytoken Manager Module
Manages honeytoken creation, placement, and access detection
"""

import os
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class HoneytokenManager:
    """
    Manages honeytokens - decoy files that detect unauthorized access
    """
    
    def __init__(self, config_file="honeytoken_config.json"):
        self.config_file = config_file
        self.honeytokens = {}
        self.access_log = []
        self.load_config()
    
    def load_config(self):
        """
        Load honeytoken configuration from file
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.honeytokens = data.get('honeytokens', {})
                    self.access_log = data.get('access_log', [])
                logger.info(f"Loaded {len(self.honeytokens)} honeytokens from config")
            else:
                logger.info("No existing config found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    def save_config(self):
        """
        Save honeytoken configuration to file
        """
        try:
            data = {
                'honeytokens': self.honeytokens,
                'access_log': self.access_log
            }
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Configuration saved")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def create_honeytoken(self, name, content_type="text"):
        """
        Create a new honeytoken file
        """
        try:
            # Generate unique content based on type
            if content_type == "text":
                content = self._generate_text_content(name)
            elif content_type == "document":
                content = self._generate_document_content(name)
            else:
                content = f"Honeytoken: {name}\n"
            
            # Calculate hash of content
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Store honeytoken metadata
            token_id = f"token_{len(self.honeytokens) + 1}"
            self.honeytokens[token_id] = {
                'name': name,
                'type': content_type,
                'hash': content_hash,
                'created': datetime.now().isoformat(),
                'content': content
            }
            
            self.save_config()
            logger.info(f"Created honeytoken: {name} (ID: {token_id})")
            return token_id, content
            
        except Exception as e:
            logger.error(f"Error creating honeytoken: {e}")
            return None, None
    
    def _generate_text_content(self, name):
        """
        Generate realistic text content for honeytoken
        """
        return f"""CONFIDENTIAL DOCUMENT
        
Document: {name}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is a sensitive document containing proprietary information.
Unauthorized access or distribution is prohibited.

API Keys:
- Production Key: HT_{hashlib.md5(name.encode()).hexdigest()[:16]}
- Development Key: HT_{hashlib.md5((name + '_dev').encode()).hexdigest()[:16]}

Database Credentials:
- Server: db.internal.company.com
- Username: admin_{name.lower().replace(' ', '_')}
- Password: {hashlib.sha256(name.encode()).hexdigest()[:12]}

This document is monitored for unauthorized access.
"""
    
    def _generate_document_content(self, name):
        """
        Generate document-style content for honeytoken
        """
        return f"""===============================================
CONFIDENTIAL BUSINESS DOCUMENT
===============================================

Title: {name}
Date: {datetime.now().strftime('%Y-%m-%d')}
Classification: RESTRICTED

Executive Summary:
This document contains sensitive business information
that should only be accessed by authorized personnel.

Key Information:
- Project Code: PROJ-{hashlib.md5(name.encode()).hexdigest()[:8].upper()}
- Access Code: {hashlib.sha256(name.encode()).hexdigest()[:16].upper()}

===============================================
WARNING: This document is monitored
===============================================
"""
    
    def deploy_honeytoken(self, token_id, target_path):
        """
        Deploy a honeytoken to a target location
        """
        try:
            if token_id not in self.honeytokens:
                logger.error(f"Token {token_id} not found")
                return False
            
            token = self.honeytokens[token_id]
            target_file = Path(target_path) / token['name']
            
            # Write honeytoken to file
            with open(target_file, 'w') as f:
                f.write(token['content'])
            
            # Update token metadata
            self.honeytokens[token_id]['deployed_path'] = str(target_file)
            self.honeytokens[token_id]['deployed_time'] = datetime.now().isoformat()
            self.save_config()
            
            logger.info(f"Deployed honeytoken {token_id} to {target_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error deploying honeytoken: {e}")
            return False
    
    def check_access(self):
        """
        Check if any honeytokens have been accessed
        """
        accessed_tokens = []
        
        try:
            for token_id, token in self.honeytokens.items():
                if 'deployed_path' not in token:
                    continue
                
                file_path = Path(token['deployed_path'])
                
                # Check if file exists and has been modified
                if file_path.exists():
                    # Check last access time
                    stat_info = os.stat(file_path)
                    access_time = stat_info.st_atime
                    
                    # If file was accessed recently (within last minute)
                    if time.time() - access_time < 60:
                        accessed_tokens.append({
                            'token_id': token_id,
                            'name': token['name'],
                            'path': str(file_path),
                            'access_time': datetime.fromtimestamp(access_time).isoformat()
                        })
                        
                        # Log the access
                        self._log_access(token_id, access_time)
                        
                        logger.warning(f"Access detected: {token['name']}")
                        
        except Exception as e:
            logger.error(f"Error checking access: {e}")
        
        return accessed_tokens
    
    def _log_access(self, token_id, access_time):
        """
        Log honeytoken access
        """
        access_entry = {
            'token_id': token_id,
            'timestamp': datetime.fromtimestamp(access_time).isoformat(),
            'detected': datetime.now().isoformat()
        }
        self.access_log.append(access_entry)
        self.save_config()
    
    def get_access_log(self):
        """
        Return the access log
        """
        return self.access_log
    
    def list_honeytokens(self):
        """
        List all configured honeytokens
        """
        return self.honeytokens


if __name__ == "__main__":
    # Example usage
    manager = HoneytokenManager()
    
    # Create some honeytokens
    token_id1, content1 = manager.create_honeytoken("API_Keys.txt", "text")
    token_id2, content2 = manager.create_honeytoken("Confidential_Report.txt", "document")
    
    logger.info(f"Created tokens: {token_id1}, {token_id2}")
    logger.info(f"Total honeytokens: {len(manager.list_honeytokens())}")
