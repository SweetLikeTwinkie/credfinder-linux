#!/usr/bin/env python3
"""
Dotfile Credential Scanner Module
Scans configuration files for secrets
"""

import os
import re
import glob
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any


class DotfileScanner:
    def __init__(self, config):
        self.config = config
        self.scan_paths = config.get("scan_paths", {})
        self.patterns = config.get("patterns", {})
        
    def scan(self) -> Dict[str, Any]:
        """Main scan method"""
        results = {
            "config_files": [],
            "env_files": [],
            "git_configs": [],
            "aws_configs": [],
            "docker_configs": [],
            "kubernetes_configs": [],
            "database_configs": [],
            "other_configs": []
        }
        
        # Scan config files
        results["config_files"] = self._scan_config_files()
        
        # Scan .env files
        results["env_files"] = self._scan_env_files()
        
        # Scan Git configurations
        results["git_configs"] = self._scan_git_configs()
        
        # Scan AWS configurations
        results["aws_configs"] = self._scan_aws_configs()
        
        # Scan Docker configurations
        results["docker_configs"] = self._scan_docker_configs()
        
        # Scan Kubernetes configurations
        results["kubernetes_configs"] = self._scan_kubernetes_configs()
        
        # Scan database configurations
        results["database_configs"] = self._scan_database_configs()
        
        # Scan other configurations
        results["other_configs"] = self._scan_other_configs()
        
        return results
    
    def _scan_config_files(self) -> List[Dict[str, Any]]:
        """Scan general configuration files"""
        findings = []
        config_paths = self.scan_paths.get("config_files", [])
        
        for base_path in config_paths:
            expanded_path = os.path.expanduser(base_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    if content:
                        pattern_matches = self._check_patterns(content)
                        if pattern_matches:
                            findings.append({
                                "file": expanded_path,
                                "type": "config_file",
                                "pattern_matches": pattern_matches,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        return findings
    
    def _scan_env_files(self) -> List[Dict[str, Any]]:
        """Scan .env files"""
        findings = []
        
        # Common .env file locations
        env_paths = [
            "~/.env*",
            "~/.config/*/.env*",
            "~/.local/share/*/.env*",
            "~/projects/*/.env*",
            "~/workspace/*/.env*"
        ]
        
        for pattern in env_paths:
            expanded_pattern = os.path.expanduser(pattern)
            files = glob.glob(expanded_pattern)
            
            for file_path in files:
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        if content:
                            env_vars = self._parse_env_file(content)
                            if env_vars:
                                findings.append({
                                    "file": file_path,
                                    "type": "env_file",
                                    "variables": env_vars,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
                    
                    except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                        continue
        
        return findings
    
    def _scan_git_configs(self) -> List[Dict[str, Any]]:
        """Scan Git configurations"""
        findings = []
        
        git_paths = [
            "~/.git-credentials",
            "~/.gitconfig",
            "~/.config/git/config"
        ]
        
        for git_path in git_paths:
            expanded_path = os.path.expanduser(git_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    if content:
                        git_config = self._parse_git_config(content)
                        if git_config:
                            findings.append({
                                "file": expanded_path,
                                "type": "git_config",
                                "config": git_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        return findings
    
    def _scan_aws_configs(self) -> List[Dict[str, Any]]:
        """Scan AWS configurations"""
        findings = []
        
        aws_paths = [
            "~/.aws/credentials",
            "~/.aws/config"
        ]
        
        for aws_path in aws_paths:
            expanded_path = os.path.expanduser(aws_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    if content:
                        aws_config = self._parse_aws_config(content, os.path.basename(expanded_path))
                        if aws_config:
                            findings.append({
                                "file": expanded_path,
                                "type": "aws_config",
                                "config": aws_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        return findings
    
    def _scan_docker_configs(self) -> List[Dict[str, Any]]:
        """Scan Docker configurations"""
        findings = []
        
        docker_paths = [
            "~/.docker/config.json",
            "~/.config/docker/config.json"
        ]
        
        for docker_path in docker_paths:
            expanded_path = os.path.expanduser(docker_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    if content:
                        docker_config = self._parse_docker_config(content)
                        if docker_config:
                            findings.append({
                                "file": expanded_path,
                                "type": "docker_config",
                                "config": docker_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        return findings
    
    def _scan_kubernetes_configs(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes configurations"""
        findings = []
        
        k8s_paths = [
            "~/.kube/config",
            "~/.config/kube/config"
        ]
        
        for k8s_path in k8s_paths:
            expanded_path = os.path.expanduser(k8s_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    if content:
                        k8s_config = self._parse_kubernetes_config(content)
                        if k8s_config:
                            findings.append({
                                "file": expanded_path,
                                "type": "kubernetes_config",
                                "config": k8s_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        return findings
    
    def _scan_database_configs(self) -> List[Dict[str, Any]]:
        """Scan database configurations"""
        findings = []
        
        db_patterns = [
            "~/.my.cnf",
            "~/.pgpass",
            "~/.psqlrc",
            "~/.config/*/database.yml",
            "~/.config/*/config.yml"
        ]
        
        for pattern in db_patterns:
            expanded_pattern = os.path.expanduser(pattern)
            files = glob.glob(expanded_pattern)
            
            for file_path in files:
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        if content:
                            db_config = self._parse_database_config(content, file_path)
                            if db_config:
                                findings.append({
                                    "file": file_path,
                                    "type": "database_config",
                                    "config": db_config,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
                    
                    except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                        continue
        
        return findings
    
    def _scan_other_configs(self) -> List[Dict[str, Any]]:
        """Scan other configuration files"""
        findings = []
        
        other_patterns = [
            "~/.npmrc",
            "~/.pypirc",
            "~/.netrc",
            "~/.config/*/secrets.json",
            "~/.config/*/settings.json"
        ]
        
        for pattern in other_patterns:
            expanded_pattern = os.path.expanduser(pattern)
            files = glob.glob(expanded_pattern)
            
            for file_path in files:
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        if content:
                            pattern_matches = self._check_patterns(content)
                            if pattern_matches:
                                findings.append({
                                    "file": file_path,
                                    "type": "other_config",
                                    "pattern_matches": pattern_matches,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
                    
                    except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                        continue
        
        return findings
    
    def _check_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check content against configured patterns"""
        matches = []
        
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    regex_matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in regex_matches:
                        matches.append({
                            "type": pattern_type,
                            "pattern": pattern,
                            "match": match if isinstance(match, str) else match[0] if match else "",
                            "context": self._get_context(content, match)
                        })
                except re.error:
                    continue
        
        return matches
    
    def _get_context(self, content: str, match: str, context_size: int = 50) -> str:
        """Get context around a match"""
        try:
            if isinstance(match, str):
                start = content.find(match)
                if start != -1:
                    start = max(0, start - context_size)
                    end = min(len(content), start + len(match) + context_size)
                    return content[start:end]
        except:
            pass
        return ""
    
    def _parse_env_file(self, content: str) -> List[Dict[str, str]]:
        """Parse .env file content"""
        variables = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                variables.append({
                    "key": key.strip(),
                    "value": value.strip()
                })
        
        return variables
    
    def _parse_git_config(self, content: str) -> Dict[str, Any]:
        """Parse Git configuration"""
        config = {
            "credentials": [],
            "user": {},
            "remote": {}
        }
        
        # Parse git-credentials file
        if "https://" in content or "http://" in content:
            for line in content.split('\n'):
                line = line.strip()
                if line and ('https://' in line or 'http://' in line):
                    parts = line.split('://')
                    if len(parts) == 2:
                        protocol = parts[0]
                        rest = parts[1]
                        if '@' in rest:
                            credentials, url = rest.split('@', 1)
                            if ':' in credentials:
                                username, password = credentials.split(':', 1)
                                config["credentials"].append({
                                    "protocol": protocol,
                                    "username": username,
                                    "password": password,
                                    "url": url
                                })
        
        # Parse gitconfig file
        else:
            current_section = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                elif '=' in line and current_section:
                    key, value = line.split('=', 1)
                    if current_section == 'user':
                        config["user"][key.strip()] = value.strip()
                    elif current_section.startswith('remote'):
                        if "remote" not in config:
                            config["remote"] = {}
                        config["remote"][key.strip()] = value.strip()
        
        return config
    
    def _parse_aws_config(self, content: str, filename: str) -> Dict[str, Any]:
        """Parse AWS configuration"""
        config = {
            "profiles": {},
            "credentials": {}
        }
        
        if filename == "credentials":
            current_profile = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_profile = line[1:-1]
                    config["credentials"][current_profile] = {}
                elif '=' in line and current_profile:
                    key, value = line.split('=', 1)
                    config["credentials"][current_profile][key.strip()] = value.strip()
        
        elif filename == "config":
            current_profile = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_profile = line[1:-1]
                    config["profiles"][current_profile] = {}
                elif '=' in line and current_profile:
                    key, value = line.split('=', 1)
                    config["profiles"][current_profile][key.strip()] = value.strip()
        
        return config
    
    def _parse_docker_config(self, content: str) -> Dict[str, Any]:
        """Parse Docker configuration"""
        try:
            config = json.loads(content)
            return config
        except json.JSONDecodeError:
            return {}
    
    def _parse_kubernetes_config(self, content: str) -> Dict[str, Any]:
        """Parse Kubernetes configuration"""
        try:
            config = yaml.safe_load(content)
            return config
        except yaml.YAMLError:
            return {}
    
    def _parse_database_config(self, content: str, file_path: str) -> Dict[str, Any]:
        """Parse database configuration"""
        config = {}
        
        if file_path.endswith('.cnf'):
            # MySQL configuration
            current_section = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    config[current_section] = {}
                elif '=' in line and current_section:
                    key, value = line.split('=', 1)
                    config[current_section][key.strip()] = value.strip()
        
        elif file_path.endswith('.yml') or file_path.endswith('.yaml'):
            # YAML configuration
            try:
                config = yaml.safe_load(content)
            except yaml.YAMLError:
                pass
        
        elif file_path.endswith('.json'):
            # JSON configuration
            try:
                config = json.loads(content)
            except json.JSONDecodeError:
                pass
        
        return config 