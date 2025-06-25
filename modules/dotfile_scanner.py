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
from modules.utils.logger import get_logger


class DotfileScanner:
    def __init__(self, config):
        self.config = config
        self.scan_paths = config.get("scan_paths", {})
        self.patterns = config.get("patterns", {})
        self.logger = get_logger("credfinder.dotfilescanner")
        
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
            "other_configs": [],
            "scan_stats": {
                "files_scanned": 0,
                "files_with_findings": 0,
                "access_denied": 0,
                "file_not_found": 0,
                "decode_errors": 0,
                "other_errors": 0
            }
        }
        
        # Scan config files
        results["config_files"] = self._scan_config_files(results["scan_stats"])
        
        # Scan .env files
        results["env_files"] = self._scan_env_files(results["scan_stats"])
        
        # Scan Git configurations
        results["git_configs"] = self._scan_git_configs(results["scan_stats"])
        
        # Scan AWS configurations
        results["aws_configs"] = self._scan_aws_configs(results["scan_stats"])
        
        # Scan Docker configurations
        results["docker_configs"] = self._scan_docker_configs(results["scan_stats"])
        
        # Scan Kubernetes configurations
        results["kubernetes_configs"] = self._scan_kubernetes_configs(results["scan_stats"])
        
        # Scan database configurations
        results["database_configs"] = self._scan_database_configs(results["scan_stats"])
        
        # Scan other configurations
        results["other_configs"] = self._scan_other_configs(results["scan_stats"])
        
        # Log summary statistics
        stats = results["scan_stats"]
        self.logger.info(f"Dotfile scan completed: {stats['files_scanned']} files scanned, "
                        f"{stats['files_with_findings']} with findings, "
                        f"{stats['access_denied']} access denied, "
                        f"{stats['file_not_found']} not found, "
                        f"{stats['decode_errors']} decode errors")
        
        return results
    
    def _scan_config_files(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan general configuration files"""
        findings = []
        config_paths = self.scan_paths.get("config_files", [])
        
        for base_path in config_paths:
            try:
                expanded_path = os.path.expanduser(base_path)
                
                if os.path.exists(expanded_path):
                    stats["files_scanned"] += 1
                    content = self._safe_read_file(expanded_path, stats)
                    
                    if content:
                        pattern_matches = self._check_patterns(content)
                        if pattern_matches:
                            stats["files_with_findings"] += 1
                            findings.append({
                                "file": expanded_path,
                                "type": "config_file",
                                "pattern_matches": pattern_matches,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                else:
                    stats["file_not_found"] += 1
                    
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Unexpected error scanning config file {base_path}: {e}")
        
        return findings
    
    def _safe_read_file(self, file_path: str, stats: Dict[str, int]) -> str:
        """Safely read file content with proper error handling and logging"""
        try:
            # Check file size to prevent reading huge files
            file_size = os.path.getsize(file_path)
            max_size = 10 * 1024 * 1024  # 10MB limit
            
            if file_size > max_size:
                self.logger.warning(f"File too large ({file_size} bytes), skipping: {file_path}")
                return ""
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
                
        except PermissionError:
            stats["access_denied"] += 1
            self.logger.debug(f"Access denied: {file_path}")
            return ""
        except FileNotFoundError:
            stats["file_not_found"] += 1
            self.logger.debug(f"File not found: {file_path}")
            return ""
        except UnicodeDecodeError:
            stats["decode_errors"] += 1
            self.logger.debug(f"Unicode decode error: {file_path}")
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    return f.read()
            except Exception:
                return ""
        except Exception as e:
            stats["other_errors"] += 1
            self.logger.warning(f"Error reading file {file_path}: {e}")
            return ""
    
    def _scan_env_files(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan .env files"""
        findings = []
        
        # Common .env file locations
        env_patterns = [
            "~/.env*",
            "~/.config/*/.env*",
            "~/.local/share/*/.env*",
            "~/projects/*/.env*",
            "~/workspace/*/.env*"
        ]
        
        for pattern in env_patterns:
            try:
                expanded_pattern = os.path.expanduser(pattern)
                files = glob.glob(expanded_pattern)
                
                for file_path in files:
                    if os.path.isfile(file_path):
                        stats["files_scanned"] += 1
                        content = self._safe_read_file(file_path, stats)
                        
                        if content:
                            env_vars = self._parse_env_file(content)
                            if env_vars:
                                stats["files_with_findings"] += 1
                                findings.append({
                                    "file": file_path,
                                    "type": "env_file",
                                    "variables": env_vars,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
                                
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Error scanning env files with pattern {pattern}: {e}")
        
        return findings
    
    def _scan_git_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan Git configurations"""
        findings = []
        
        git_paths = [
            "~/.git-credentials",
            "~/.gitconfig",
            "~/.config/git/config"
        ]
        
        for git_path in git_paths:
            try:
                expanded_path = os.path.expanduser(git_path)
                
                if os.path.exists(expanded_path):
                    stats["files_scanned"] += 1
                    content = self._safe_read_file(expanded_path, stats)
                    
                    if content:
                        git_config = self._parse_git_config(content)
                        if git_config:
                            stats["files_with_findings"] += 1
                            findings.append({
                                "file": expanded_path,
                                "type": "git_config",
                                "config": git_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                else:
                    stats["file_not_found"] += 1
                    
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Unexpected error scanning git config file {git_path}: {e}")
        
        return findings
    
    def _scan_aws_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan AWS configurations"""
        findings = []
        
        aws_paths = [
            "~/.aws/credentials",
            "~/.aws/config"
        ]
        
        for aws_path in aws_paths:
            try:
                expanded_path = os.path.expanduser(aws_path)
                
                if os.path.exists(expanded_path):
                    stats["files_scanned"] += 1
                    content = self._safe_read_file(expanded_path, stats)
                    
                    if content:
                        aws_config = self._parse_aws_config(content, os.path.basename(expanded_path))
                        if aws_config:
                            stats["files_with_findings"] += 1
                            findings.append({
                                "file": expanded_path,
                                "type": "aws_config",
                                "config": aws_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                else:
                    stats["file_not_found"] += 1
                    
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Unexpected error scanning aws config file {aws_path}: {e}")
        
        return findings
    
    def _scan_docker_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan Docker configurations"""
        findings = []
        
        docker_paths = [
            "~/.docker/config.json",
            "~/.config/docker/config.json"
        ]
        
        for docker_path in docker_paths:
            try:
                expanded_path = os.path.expanduser(docker_path)
                
                if os.path.exists(expanded_path):
                    stats["files_scanned"] += 1
                    content = self._safe_read_file(expanded_path, stats)
                    
                    if content:
                        docker_config = self._parse_docker_config(content)
                        if docker_config:
                            stats["files_with_findings"] += 1
                            findings.append({
                                "file": expanded_path,
                                "type": "docker_config",
                                "config": docker_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                else:
                    stats["file_not_found"] += 1
                    
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Unexpected error scanning docker config file {docker_path}: {e}")
        
        return findings
    
    def _scan_kubernetes_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """Scan Kubernetes configurations"""
        findings = []
        
        k8s_paths = [
            "~/.kube/config",
            "~/.config/kube/config"
        ]
        
        for k8s_path in k8s_paths:
            try:
                expanded_path = os.path.expanduser(k8s_path)
                
                if os.path.exists(expanded_path):
                    stats["files_scanned"] += 1
                    content = self._safe_read_file(expanded_path, stats)
                    
                    if content:
                        k8s_config = self._parse_kubernetes_config(content)
                        if k8s_config:
                            stats["files_with_findings"] += 1
                            findings.append({
                                "file": expanded_path,
                                "type": "kubernetes_config",
                                "config": k8s_config,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            })
                else:
                    stats["file_not_found"] += 1
                    
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Unexpected error scanning kubernetes config file {k8s_path}: {e}")
        
        return findings
    
    def _scan_database_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
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
            try:
                expanded_pattern = os.path.expanduser(pattern)
                files = glob.glob(expanded_pattern)
                
                for file_path in files:
                    if os.path.isfile(file_path):
                        stats["files_scanned"] += 1
                        content = self._safe_read_file(file_path, stats)
                        
                        if content:
                            db_config = self._parse_database_config(content, file_path)
                            if db_config:
                                stats["files_with_findings"] += 1
                                findings.append({
                                    "file": file_path,
                                    "type": "database_config",
                                    "config": db_config,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Error scanning database config file {pattern}: {e}")
        
        return findings
    
    def _scan_other_configs(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
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
            try:
                expanded_pattern = os.path.expanduser(pattern)
                files = glob.glob(expanded_pattern)
                
                for file_path in files:
                    if os.path.isfile(file_path):
                        stats["files_scanned"] += 1
                        content = self._safe_read_file(file_path, stats)
                        
                        if content:
                            pattern_matches = self._check_patterns(content)
                            if pattern_matches:
                                stats["files_with_findings"] += 1
                                findings.append({
                                    "file": file_path,
                                    "type": "other_config",
                                    "pattern_matches": pattern_matches,
                                    "content_preview": content[:500] + "..." if len(content) > 500 else content
                                })
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Error scanning other config file {pattern}: {e}")
        
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
            # Handle different match types from regex findall
            if isinstance(match, tuple):
                # For regex groups, use the first non-empty group
                match_str = next((m for m in match if m), "") if match else ""
            elif isinstance(match, str):
                match_str = match
            else:
                match_str = str(match)
            
            if match_str:
                start = content.find(match_str)
                if start != -1:
                    start = max(0, start - context_size)
                    end = min(len(content), start + len(match_str) + context_size * 2)
                    return content[start:end]
        except Exception as e:
            # Log the error for debugging but don't fail
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