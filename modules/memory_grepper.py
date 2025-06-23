#!/usr/bin/env python3
"""
Memory-Based Secret Hunting Module
Searches processes and memory for secrets
"""

import os
import re
import subprocess
from typing import List, Dict, Any

# Try to import psutil, but handle gracefully if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. Memory scanning will be limited.")


class MemoryGrepper:
    def __init__(self, config):
        self.config = config
        self.patterns = config.get("patterns", {})
        
    def scan(self) -> Dict[str, Any]:
        """Main scan method"""
        results = {
            "process_environ": [],
            "process_cmdline": [],
            "memory_dumps": [],
            "proc_files": [],
            "volatility_results": {},
            "dependencies": {
                "psutil_available": PSUTIL_AVAILABLE
            }
        }
        
        # Only scan processes if psutil is available
        if PSUTIL_AVAILABLE:
            # Scan process environments
            results["process_environ"] = self._scan_process_environ()
            
            # Scan process command lines
            results["process_cmdline"] = self._scan_process_cmdline()
        else:
            print("Warning: psutil not available, skipping process scanning")
        
        # Scan /proc files (this doesn't require psutil)
        results["proc_files"] = self._scan_proc_files()
        
        # Try Volatility if available
        if self._check_volatility():
            results["volatility_results"] = self._run_volatility_scan()
        
        return results
    
    def _scan_process_environ(self) -> List[Dict[str, Any]]:
        """Scan process environment variables for secrets"""
        findings = []
        
        if not PSUTIL_AVAILABLE:
            return findings
        
        for proc in psutil.process_iter(['pid', 'name', 'environ']):
            try:
                proc_info = proc.info
                environ = proc_info.get('environ', {})
                
                if environ:
                    secrets = self._search_environ_for_secrets(environ, proc_info)
                    if secrets:
                        findings.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "secrets": secrets
                        })
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"Warning: Error scanning process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
                continue
        
        return findings
    
    def _scan_process_cmdline(self) -> List[Dict[str, Any]]:
        """Scan process command lines for secrets"""
        findings = []
        
        if not PSUTIL_AVAILABLE:
            return findings
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                cmdline = proc_info.get('cmdline', [])
                
                if cmdline:
                    secrets = self._search_cmdline_for_secrets(cmdline, proc_info)
                    if secrets:
                        findings.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cmdline": ' '.join(cmdline),
                            "secrets": secrets
                        })
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"Warning: Error scanning process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
                continue
        
        return findings
    
    def _search_environ_for_secrets(self, environ: Dict[str, str], proc_info: Dict) -> List[Dict[str, Any]]:
        """Search environment variables for secrets"""
        secrets = []
        
        sensitive_vars = [
            'PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'KEY', 'API_KEY',
            'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'GITHUB_TOKEN', 'SLACK_TOKEN',
            'DATABASE_URL', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD',
            'REDIS_PASSWORD', 'MONGODB_PASSWORD', 'JWT_SECRET'
        ]
        
        for var_name, var_value in environ.items():
            if var_value and len(var_value) > 0:
                # Check for sensitive variable names
                if any(sensitive in var_name.upper() for sensitive in sensitive_vars):
                    secrets.append({
                        "type": "environment_variable",
                        "name": var_name,
                        "value": var_value,
                        "pattern_matched": "sensitive_variable_name"
                    })
                
                # Check for pattern matches in values
                pattern_matches = self._check_patterns(var_value)
                if pattern_matches:
                    secrets.append({
                        "type": "environment_variable",
                        "name": var_name,
                        "value": var_value,
                        "pattern_matches": pattern_matches
                    })
        
        return secrets
    
    def _search_cmdline_for_secrets(self, cmdline: List[str], proc_info: Dict) -> List[Dict[str, Any]]:
        """Search command line arguments for secrets"""
        secrets = []
        
        cmdline_str = ' '.join(cmdline)
        
        # Check for pattern matches in command line
        pattern_matches = self._check_patterns(cmdline_str)
        if pattern_matches:
            secrets.append({
                "type": "command_line",
                "value": cmdline_str,
                "pattern_matches": pattern_matches
            })
        
        # Check for specific command line patterns
        cmdline_patterns = [
            r'--password\s+([^\s]+)',
            r'-p\s+([^\s]+)',
            r'--secret\s+([^\s]+)',
            r'--token\s+([^\s]+)',
            r'--key\s+([^\s]+)',
            r'--api-key\s+([^\s]+)',
            r'--aws-access-key\s+([^\s]+)',
            r'--aws-secret-key\s+([^\s]+)'
        ]
        
        for pattern in cmdline_patterns:
            matches = re.findall(pattern, cmdline_str, re.IGNORECASE)
            for match in matches:
                secrets.append({
                    "type": "command_line_argument",
                    "pattern": pattern,
                    "value": match,
                    "full_cmdline": cmdline_str
                })
        
        return secrets
    
    def _scan_proc_files(self) -> List[Dict[str, Any]]:
        """Scan /proc files for secrets"""
        findings = []
        
        proc_paths = [
            "/proc/*/environ",
            "/proc/*/cmdline",
            "/proc/*/status",
            "/proc/*/maps"
        ]
        
        for proc_path in proc_paths:
            try:
                # Use find to get all matching files
                result = subprocess.run(
                    ['find', '/proc', '-maxdepth', '2', '-name', os.path.basename(proc_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    
                    for file_path in files:
                        if file_path and os.path.exists(file_path):
                            try:
                                with open(file_path, 'r', errors='ignore') as f:
                                    content = f.read()
                                
                                if content:
                                    pattern_matches = self._check_patterns(content)
                                    if pattern_matches:
                                        findings.append({
                                            "file": file_path,
                                            "type": os.path.basename(file_path),
                                            "pattern_matches": pattern_matches,
                                            "content_preview": content[:200] + "..." if len(content) > 200 else content
                                        })
                            
                            except (PermissionError, FileNotFoundError):
                                continue
            
            except subprocess.TimeoutExpired:
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
    
    def _check_volatility(self) -> bool:
        """Check if Volatility is available"""
        try:
            result = subprocess.run(
                ['vol', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _run_volatility_scan(self) -> Dict[str, Any]:
        """Run Volatility memory analysis"""
        results = {
            "profiles": [],
            "processes": [],
            "envars": [],
            "cmdline": [],
            "error": None
        }
        
        try:
            # Get available profiles
            profile_result = subprocess.run(
                ['vol', '--info'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if profile_result.returncode == 0:
                # Parse profiles (simplified)
                results["profiles"] = ["Linux"]  # Default for Linux
            
            # Try to get process list
            try:
                proc_result = subprocess.run(
                    ['vol', '-f', '/dev/mem', '--profile=Linux', 'linux_pslist'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if proc_result.returncode == 0:
                    results["processes"] = self._parse_volatility_processes(proc_result.stdout)
            except:
                pass
            
            # Try to get environment variables
            try:
                env_result = subprocess.run(
                    ['vol', '-f', '/dev/mem', '--profile=Linux', 'linux_environ'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if env_result.returncode == 0:
                    results["envars"] = self._parse_volatility_envars(env_result.stdout)
            except:
                pass
            
            # Try to get command lines
            try:
                cmd_result = subprocess.run(
                    ['vol', '-f', '/dev/mem', '--profile=Linux', 'linux_cmdline'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if cmd_result.returncode == 0:
                    results["cmdline"] = self._parse_volatility_cmdline(cmd_result.stdout)
            except:
                pass
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _parse_volatility_processes(self, output: str) -> List[Dict[str, Any]]:
        """Parse Volatility process list output"""
        processes = []
        
        for line in output.strip().split('\n'):
            if line and not line.startswith('Volatility'):
                parts = line.split()
                if len(parts) >= 4:
                    processes.append({
                        "pid": parts[0],
                        "ppid": parts[1],
                        "name": parts[2],
                        "cmdline": ' '.join(parts[3:])
                    })
        
        return processes
    
    def _parse_volatility_envars(self, output: str) -> List[Dict[str, Any]]:
        """Parse Volatility environment variables output"""
        envars = []
        
        for line in output.strip().split('\n'):
            if '=' in line and not line.startswith('Volatility'):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    envars.append({
                        "variable": parts[0].strip(),
                        "value": parts[1].strip()
                    })
        
        return envars
    
    def _parse_volatility_cmdline(self, output: str) -> List[Dict[str, Any]]:
        """Parse Volatility command line output"""
        cmdlines = []
        
        for line in output.strip().split('\n'):
            if line and not line.startswith('Volatility'):
                parts = line.split()
                if len(parts) >= 2:
                    cmdlines.append({
                        "pid": parts[0],
                        "cmdline": ' '.join(parts[1:])
                    })
        
        return cmdlines
    
    def search_specific_processes(self, process_names: List[str]) -> List[Dict[str, Any]]:
        """Search for secrets in specific processes"""
        findings = []
        
        for proc in psutil.process_iter(['pid', 'name', 'environ', 'cmdline']):
            try:
                proc_info = proc.info
                if proc_info['name'] in process_names:
                    # Search environment
                    environ_secrets = self._search_environ_for_secrets(
                        proc_info.get('environ', {}), proc_info
                    )
                    
                    # Search command line
                    cmdline_secrets = self._search_cmdline_for_secrets(
                        proc_info.get('cmdline', []), proc_info
                    )
                    
                    if environ_secrets or cmdline_secrets:
                        findings.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "environ_secrets": environ_secrets,
                            "cmdline_secrets": cmdline_secrets
                        })
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return findings 