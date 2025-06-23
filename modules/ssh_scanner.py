#!/usr/bin/env python3
"""
SSH Credential Discovery Module
Searches for SSH keys and checks SSH agents
"""

import os
import subprocess
import glob
import re
from pathlib import Path
from typing import List, Dict, Any


class SSHScanner:
    def __init__(self, config):
        self.config = config
        self.scan_paths = config.get("scan_paths", {}).get("ssh", [])
        
    def scan(self) -> Dict[str, Any]:
        """Main scan method"""
        results = {
            "private_keys": [],
            "public_keys": [],
            "ssh_agent": None,
            "known_hosts": [],
            "config_files": [],
            "authorized_keys": []
        }
        
        # Scan for SSH keys
        results["private_keys"] = self._find_private_keys()
        results["public_keys"] = self._find_public_keys()
        
        # Check SSH agent
        results["ssh_agent"] = self._check_ssh_agent()
        
        # Find known_hosts files
        results["known_hosts"] = self._find_known_hosts()
        
        # Find SSH config files
        results["config_files"] = self._find_ssh_configs()
        
        # Find authorized_keys files
        results["authorized_keys"] = self._find_authorized_keys()
        
        return results
    
    def _find_private_keys(self) -> List[Dict[str, Any]]:
        """Find private SSH keys"""
        private_keys = []
        key_patterns = [
            "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
            "id_xmss*", "ssh_host_*_key"
        ]
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            
            for pattern in key_patterns:
                search_pattern = os.path.join(expanded_path, pattern)
                files = glob.glob(search_pattern)
                
                for file_path in files:
                    if os.path.isfile(file_path) and not file_path.endswith('.pub'):
                        key_info = self._analyze_private_key(file_path)
                        if key_info:
                            private_keys.append(key_info)
        
        return private_keys
    
    def _find_public_keys(self) -> List[Dict[str, Any]]:
        """Find public SSH keys"""
        public_keys = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            search_pattern = os.path.join(expanded_path, "*.pub")
            files = glob.glob(search_pattern)
            
            for file_path in files:
                if os.path.isfile(file_path):
                    key_info = self._analyze_public_key(file_path)
                    if key_info:
                        public_keys.append(key_info)
        
        return public_keys
    
    def _analyze_private_key(self, file_path: str) -> Dict[str, Any]:
        """Analyze a private key file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check if key is encrypted
            is_encrypted = "ENCRYPTED" in content or "Proc-Type: 4,ENCRYPTED" in content
            
            # Get file permissions
            stat = os.stat(file_path)
            permissions = oct(stat.st_mode)[-3:]
            
            # Check if permissions are too open
            is_secure = permissions in ['600', '400']
            
            return {
                "path": file_path,
                "encrypted": is_encrypted,
                "permissions": permissions,
                "secure_permissions": is_secure,
                "size": os.path.getsize(file_path),
                "owner": self._get_file_owner(file_path)
            }
        except Exception as e:
            print(f"Warning: Failed to analyze private key {file_path}: {e}")
            return None
    
    def _analyze_public_key(self, file_path: str) -> Dict[str, Any]:
        """Analyze a public key file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            # Parse key type and comment
            parts = content.split()
            if len(parts) >= 2:
                key_type = parts[0]
                key_data = parts[1]
                comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
                
                return {
                    "path": file_path,
                    "key_type": key_type,
                    "key_data": key_data[:50] + "..." if len(key_data) > 50 else key_data,
                    "comment": comment,
                    "size": os.path.getsize(file_path),
                    "owner": self._get_file_owner(file_path)
                }
        except Exception as e:
            print(f"Warning: Failed to analyze public key {file_path}: {e}")
            return None
        
        return None
    
    def _check_ssh_agent(self) -> Dict[str, Any]:
        """Check if SSH agent is running and dump identities"""
        agent_info = {
            "running": False,
            "socket": None,
            "identities": []
        }
        
        # Check SSH_AUTH_SOCK environment variable
        ssh_auth_sock = os.environ.get('SSH_AUTH_SOCK')
        if ssh_auth_sock:
            agent_info["socket"] = ssh_auth_sock
            agent_info["running"] = True
            
            # Try to list identities
            try:
                result = subprocess.run(
                    ['ssh-add', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line and not line.startswith('The agent has no identities'):
                            # Parse identity info
                            parts = line.split()
                            if len(parts) >= 4:
                                identity = {
                                    "fingerprint": parts[1],
                                    "key_type": parts[2],
                                    "comment": ' '.join(parts[3:])
                                }
                                agent_info["identities"].append(identity)
            except Exception as e:
                pass
        
        return agent_info
    
    def _find_known_hosts(self) -> List[Dict[str, Any]]:
        """Find known_hosts files"""
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
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 2:
                                hosts.append({
                                    "hostname": parts[0],
                                    "key_type": parts[1],
                                    "key_data": parts[2][:50] + "..." if len(parts[2]) > 50 else parts[2]
                                })
                    
                    if hosts:
                        known_hosts.append({
                            "path": known_hosts_path,
                            "hosts": hosts,
                            "count": len(hosts),
                            "owner": self._get_file_owner(known_hosts_path)
                        })
                except Exception as e:
                    pass
        
        return known_hosts
    
    def _find_ssh_configs(self) -> List[Dict[str, Any]]:
        """Find SSH config files"""
        configs = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            config_path = os.path.join(expanded_path, "config")
            
            if os.path.isfile(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                    
                    # Look for interesting configurations
                    interesting_configs = []
                    
                    # Check for IdentityFile entries
                    identity_files = re.findall(r'IdentityFile\s+(.+)', content)
                    for identity_file in identity_files:
                        interesting_configs.append({
                            "type": "IdentityFile",
                            "value": identity_file.strip()
                        })
                    
                    # Check for Host entries
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
                            "owner": self._get_file_owner(config_path)
                        })
                except Exception as e:
                    pass
        
        return configs
    
    def _find_authorized_keys(self) -> List[Dict[str, Any]]:
        """Find authorized_keys files"""
        authorized_keys = []
        
        for path in self.scan_paths:
            expanded_path = os.path.expanduser(path)
            authorized_keys_path = os.path.join(expanded_path, "authorized_keys")
            
            if os.path.isfile(authorized_keys_path):
                try:
                    with open(authorized_keys_path, 'r') as f:
                        content = f.read()
                    
                    # Parse authorized_keys content
                    keys = []
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and line.startswith('ssh-'):
                            parts = line.split()
                            if len(parts) >= 2:
                                key_type = parts[0]
                                key_data = parts[1]
                                comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
                                
                                # Try to get fingerprint
                                fingerprint = self._get_key_fingerprint(key_type + " " + key_data)
                                
                                keys.append({
                                    "key_type": key_type,
                                    "key_data": key_data[:50] + "..." if len(key_data) > 50 else key_data,
                                    "comment": comment,
                                    "fingerprint": fingerprint
                                })
                    
                    if keys:
                        authorized_keys.append({
                            "path": authorized_keys_path,
                            "keys": keys,
                            "count": len(keys),
                            "owner": self._get_file_owner(authorized_keys_path),
                            "permissions": oct(os.stat(authorized_keys_path).st_mode)[-3:]
                        })
                except Exception as e:
                    pass
        
        return authorized_keys
    
    def _get_key_fingerprint(self, key_data: str) -> str:
        """Get SSH key fingerprint"""
        try:
            # Use ssh-keygen to get fingerprint
            result = subprocess.run(
                ['ssh-keygen', '-l', '-f', '-'],
                input=key_data.encode(),
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                # Parse fingerprint from output
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1]
        except Exception:
            pass
        return None
    
    def _get_file_owner(self, file_path: str) -> str:
        """Get file owner"""
        try:
            import pwd
            stat = os.stat(file_path)
            owner = pwd.getpwuid(stat.st_uid).pw_name
            return owner
        except Exception:
            return "unknown" 