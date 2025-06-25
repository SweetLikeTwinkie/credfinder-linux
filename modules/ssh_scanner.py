#!/usr/bin/env python3
"""
SSH Credential Discovery Module

This module searches for SSH keys, checks SSH agents, and analyzes SSH configurations.
It's designed to find credentials that could be used for lateral movement or privilege escalation.

Key Features:
- Discovers private/public SSH keys with security analysis
- Dumps SSH agent identities if available  
- Parses known_hosts files for target information
- Analyzes SSH config files for interesting settings
- Checks authorized_keys files for persistence mechanisms

Contributors: This module is safe and doesn't require elevated privileges.
All file operations include proper error handling and permission checks.
"""

import os
import subprocess
import glob
import re
from pathlib import Path
from typing import List, Dict, Any
from modules.utils.logger import get_logger


class SSHScanner:
    def __init__(self, config):
        self.config = config
        self.scan_paths = config.get("scan_paths", {}).get("ssh", [])
        self.logger = get_logger("credfinder.sshscanner")
        
        # Load SSH-specific settings from config to avoid hardcoded values
        self.ssh_settings = config.get("module_settings", {}).get("ssh", {})
        self.key_patterns = self.ssh_settings.get("key_patterns", [
            "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "id_xmss*", "ssh_host_*_key"
        ])
        self.secure_permissions = self.ssh_settings.get("secure_permissions", [384, 256])  # 0o600, 0o400 in decimal
        self.key_truncate_length = self.ssh_settings.get("key_data_truncate_length", 50)
        self.ssh_agent_timeout = self.ssh_settings.get("ssh_agent_timeout", 5)
        self.fingerprint_timeout = self.ssh_settings.get("fingerprint_timeout", 5)
        
    def scan(self) -> Dict[str, Any]:
        """
        Main scan method that orchestrates all SSH-related credential discovery.
        
        Returns:
            Dict containing all SSH findings organized by type
        """
        results = {
            "private_keys": [],
            "public_keys": [],
            "ssh_agent": None,
            "known_hosts": [],
            "config_files": [],
            "authorized_keys": []
        }
        
        # Search for SSH keys in configured paths
        results["private_keys"] = self._find_private_keys()
        results["public_keys"] = self._find_public_keys()
        
        # Check if SSH agent is running and dump loaded identities
        results["ssh_agent"] = self._check_ssh_agent()
        
        # Find and parse SSH-related configuration files
        results["known_hosts"] = self._find_known_hosts()
        results["config_files"] = self._find_ssh_configs()
        results["authorized_keys"] = self._find_authorized_keys()
        
        return results
    
    def _find_private_keys(self) -> List[Dict[str, Any]]:
        """
        Search for private SSH keys using configurable patterns.
        
        Private keys are high-value targets as they can provide direct access
        to remote systems. This method performs security analysis on found keys.
        
        Returns:
            List of private key information with security assessment
        """
        private_keys = []
        
        for path in self.scan_paths:
            expanded_paths = glob.glob(os.path.expanduser(path))
            for expanded_path in expanded_paths:
                for pattern in self.key_patterns:
                    search_pattern = os.path.join(expanded_path, pattern)
                    files = glob.glob(search_pattern)
                    for file_path in files:
                        # Only process actual files that aren't public keys (.pub extension)
                        if os.path.isfile(file_path) and not file_path.endswith('.pub'):
                            key_info = self._analyze_private_key(file_path)
                            if key_info:
                                private_keys.append(key_info)
        
        return private_keys
    
    def _find_public_keys(self) -> List[Dict[str, Any]]:
        """
        Search for public SSH keys.
        
        Public keys can reveal information about the user's SSH infrastructure
        and help understand trust relationships between systems.
        
        Returns:
            List of public key information
        """
        public_keys = []
        
        for path in self.scan_paths:
            expanded_paths = glob.glob(os.path.expanduser(path))
            for expanded_path in expanded_paths:
                search_pattern = os.path.join(expanded_path, "*.pub")
                files = glob.glob(search_pattern)
                for file_path in files:
                    if os.path.isfile(file_path):
                        key_info = self._analyze_public_key(file_path)
                        if key_info:
                            public_keys.append(key_info)
        
        return public_keys
    
    def _analyze_private_key(self, file_path: str) -> Dict[str, Any]:
        """
        Perform detailed security analysis of a private SSH key.
        
        This method checks:
        - Encryption status (encrypted keys are safer)
        - File permissions (should be 600 or 400)
        - Security issues (readable by others, etc.)
        - Risk assessment based on security posture
        
        Args:
            file_path: Path to the private key file
            
        Returns:
            Dict with key analysis or None if analysis fails
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check if key is password-protected (encrypted)
            is_encrypted = "ENCRYPTED" in content or "Proc-Type: 4,ENCRYPTED" in content
            
            # Analyze file permissions for security issues
            stat_info = os.stat(file_path)
            permissions_octal = oct(stat_info.st_mode)[-3:]  # Last 3 digits as string for display
            permissions_int = stat_info.st_mode & 0o777  # Permission bits as integer for analysis
            
            # Check if permissions match secure settings from config
            is_secure = permissions_int in self.secure_permissions
            
            # Identify specific security issues with file permissions
            security_issues = []
            if permissions_int & 0o044:  # Readable by group (040) or others (004)
                security_issues.append("Key is readable by group or others")
            if permissions_int & 0o022:  # Writable by group (020) or others (002)
                security_issues.append("Key is writable by group or others")
            if permissions_int & 0o111:  # Executable bits set (unusual for keys)
                security_issues.append("Key file is executable")
            
            # Assess overall risk level based on encryption and permissions
            if not is_encrypted and not is_secure:
                risk_level = "critical"  # Unencrypted key with bad permissions
            elif not is_encrypted:
                risk_level = "medium"    # Unencrypted but good permissions
            else:
                risk_level = "low"       # Encrypted key (safest)
            
            return {
                "path": file_path,
                "encrypted": is_encrypted,
                "permissions": permissions_octal,
                "permissions_int": permissions_int,
                "secure_permissions": is_secure,
                "security_issues": security_issues,
                "size": os.path.getsize(file_path),
                "owner": self._get_file_owner_name(file_path),
                "risk_level": risk_level
            }
        except (PermissionError, FileNotFoundError) as e:
            self.logger.warning(f"Cannot access private key {file_path}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Failed to analyze private key {file_path}: {e}")
            return None
    
    def _analyze_public_key(self, file_path: str) -> Dict[str, Any]:
        """
        Parse and analyze a public SSH key file.
        
        Public keys contain the key type, key data, and optional comment.
        The comment often contains useful information like username@hostname.
        
        Args:
            file_path: Path to the public key file
            
        Returns:
            Dict with parsed key information or None if parsing fails
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            # Parse the standard SSH public key format: type data [comment]
            parts = content.split()
            if len(parts) >= 2:
                key_type = parts[0]  # e.g., ssh-rsa, ssh-ed25519
                key_data = parts[1]  # Base64-encoded key data
                comment = ' '.join(parts[2:]) if len(parts) > 2 else ""  # Optional comment
                
                # Truncate key data for display (configurable length)
                display_key = key_data[:self.key_truncate_length]
                if len(key_data) > self.key_truncate_length:
                    display_key += "..."
                
                return {
                    "path": file_path,
                    "key_type": key_type,
                    "key_data": display_key,
                    "comment": comment,
                    "size": os.path.getsize(file_path),
                    "owner": self._get_file_owner_name(file_path)
                }
        except Exception as e:
            self.logger.warning(f"Failed to analyze public key {file_path}: {e}")
            return None
        
        return None
    
    def _check_ssh_agent(self) -> Dict[str, Any]:
        """
        Check if SSH agent is running and attempt to dump loaded identities.
        
        SSH agent stores decrypted private keys in memory for convenience.
        If agent is running, we can list the loaded keys without needing passwords.
        This is valuable for understanding what keys are actively available.
        
        Returns:
            Dict with agent status and loaded identities
        """
        agent_info = {
            "running": False,
            "socket": None,
            "identities": []
        }
        
        # SSH agent communicates via a Unix socket specified in SSH_AUTH_SOCK
        ssh_auth_sock = os.environ.get('SSH_AUTH_SOCK')
        if ssh_auth_sock:
            agent_info["socket"] = ssh_auth_sock
            agent_info["running"] = True
            
            # Try to list loaded identities using ssh-add
            try:
                result = subprocess.run(
                    ['ssh-add', '-l'],  # List loaded keys
                    capture_output=True,
                    text=True,
                    timeout=self.ssh_agent_timeout
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        # Skip empty lines and "no identities" message
                        if line and not line.startswith('The agent has no identities'):
                            # Parse ssh-add output: bitsize fingerprint comment (type)
                            parts = line.split()
                            if len(parts) >= 4:
                                identity = {
                                    "fingerprint": parts[1],
                                    "key_type": parts[2], 
                                    "comment": ' '.join(parts[3:])
                                }
                                agent_info["identities"].append(identity)
            except subprocess.TimeoutExpired:
                self.logger.warning("SSH agent query timed out")
            except Exception:
                # SSH agent might be locked or ssh-add not available
                pass
        
        return agent_info
    
    def _find_known_hosts(self) -> List[Dict[str, Any]]:
        """
        Find and parse known_hosts files.
        
        known_hosts files contain fingerprints of servers the user has connected to.
        This provides intelligence about the network infrastructure and target systems.
        
        Returns:
            List of known_hosts files with parsed host information
        """
        known_hosts = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            known_hosts_path = os.path.join(expanded_path, "known_hosts")
            
            if os.path.isfile(known_hosts_path):
                try:
                    with open(known_hosts_path, 'r') as f:
                        lines = f.readlines()
                    
                    hosts = []
                    for line in lines:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 3:
                                # Standard format: hostname keytype keydata
                                hostname = parts[0]
                                key_type = parts[1]
                                key_data = parts[2]
                                
                                # Truncate key data for display
                                display_key = key_data[:self.key_truncate_length]
                                if len(key_data) > self.key_truncate_length:
                                    display_key += "..."
                                
                                hosts.append({
                                    "hostname": hostname,
                                    "key_type": key_type,
                                    "key_data": display_key
                                })
                    
                    if hosts:
                        known_hosts.append({
                            "path": known_hosts_path,
                            "hosts": hosts,
                            "count": len(hosts),
                            "owner": self._get_file_owner_name(known_hosts_path)
                        })
                except Exception:
                    # File might be corrupted or have permission issues
                    pass
        
        return known_hosts
    
    def _find_ssh_configs(self) -> List[Dict[str, Any]]:
        """
        Find and parse SSH configuration files.
        
        SSH config files can contain valuable information like:
        - Custom key files (IdentityFile)
        - Host aliases and connection details
        - Jump host configurations
        
        Returns:
            List of SSH config files with interesting settings
        """
        configs = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            config_path = os.path.join(expanded_path, "config")
            
            if os.path.isfile(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                    
                    interesting_configs = []
                    
                    # Look for IdentityFile directives (custom key locations)
                    identity_files = re.findall(r'IdentityFile\s+(.+)', content)
                    for identity_file in identity_files:
                        interesting_configs.append({
                            "type": "IdentityFile",
                            "value": identity_file.strip()
                        })
                    
                    # Look for Host entries (connection targets)
                    hosts = re.findall(r'Host\s+(.+)', content)
                    for host in hosts:
                        interesting_configs.append({
                            "type": "Host",
                            "value": host.strip()
                        })
                    
                    if interesting_configs:
                        configs.append({
                            "path": config_path,
                            "configs": interesting_configs,
                            "owner": self._get_file_owner_name(config_path)
                        })
                except Exception:
                    # Config file might have permission issues or be corrupted
                    pass
        
        return configs
    
    def _find_authorized_keys(self) -> List[Dict[str, Any]]:
        """
        Find and parse authorized_keys files.
        
        authorized_keys files contain public keys that can authenticate to this system.
        This is useful for understanding:
        - Who can access this system
        - Potential persistence mechanisms
        - Trust relationships
        
        Returns:
            List of authorized_keys files with parsed key information
        """
        authorized_keys = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            authorized_keys_path = os.path.join(expanded_path, "authorized_keys")
            
            if os.path.isfile(authorized_keys_path):
                try:
                    with open(authorized_keys_path, 'r') as f:
                        content = f.read()
                    
                    keys = []
                    for line in content.splitlines():
                        line = line.strip()
                        # Parse valid SSH public key lines (skip comments and empty lines)
                        if line and not line.startswith('#') and line.startswith('ssh-'):
                            parts = line.split()
                            if len(parts) >= 2:
                                key_type = parts[0]
                                key_data = parts[1]
                                comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
                                
                                # Try to get key fingerprint for identification
                                fingerprint = self._get_key_fingerprint(key_type + " " + key_data)
                                
                                # Truncate key data for display
                                display_key = key_data[:self.key_truncate_length]
                                if len(key_data) > self.key_truncate_length:
                                    display_key += "..."
                                
                                keys.append({
                                    "key_type": key_type,
                                    "key_data": display_key,
                                    "comment": comment,
                                    "fingerprint": fingerprint
                                })
                    
                    if keys:
                        authorized_keys.append({
                            "path": authorized_keys_path,
                            "keys": keys,
                            "count": len(keys),
                            "owner": self._get_file_owner_name(authorized_keys_path),
                            "permissions": oct(os.stat(authorized_keys_path).st_mode)[-3:]
                        })
                except Exception:
                    # File might have permission issues
                    pass
        
        return authorized_keys
    
    def _get_key_fingerprint(self, key_data: str) -> str:
        """
        Generate SSH key fingerprint using ssh-keygen.
        
        Fingerprints are useful for identifying and correlating keys across systems.
        
        Args:
            key_data: Full SSH public key string
            
        Returns:
            Key fingerprint or None if generation fails
        """
        try:
            import tempfile
            # Create temporary file with the key data
            with tempfile.NamedTemporaryFile('w+', delete=False) as tmpfile:
                tmpfile.write(key_data)
                tmpfile.flush()
                tmpfile_name = tmpfile.name
            
            # Use ssh-keygen to generate fingerprint
            result = subprocess.run(
                ['ssh-keygen', '-l', '-f', tmpfile_name],
                capture_output=True,
                text=True,
                timeout=self.fingerprint_timeout
            )
            
            # Clean up temporary file
            os.unlink(tmpfile_name)
            
            if result.returncode == 0 and result.stdout:
                # Parse fingerprint from output format: "bits fingerprint comment (type)"
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1]  # The fingerprint part
        except Exception:
            # ssh-keygen might not be available or key format invalid
            pass
        return None
    
    def _get_file_owner_name(self, file_path: str) -> str:
        """
        Get the username of the file owner.
        
        Useful for understanding which user account owns SSH keys and configs.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Username or "unknown" if lookup fails
        """
        try:
            import pwd
            stat = os.stat(file_path)
            owner = pwd.getpwuid(stat.st_uid).pw_name
            return owner
        except Exception:
            return "unknown" 