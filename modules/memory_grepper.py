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

# Try to import yara, but handle gracefully if not available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class MemoryGrepper:
    def __init__(self, config):
        self.config = config
        self.patterns = config.get("patterns", {})
        # All memory/Volatility/YARA options are now read from config['modules']['memory']
        memcfg = config.get("modules", {}).get("memory", {})
        self.memory_dump_path = memcfg.get("memory_dump_path", "/dev/mem")
        self.volatility_plugins = memcfg.get("volatility_plugins", [
            "linux_envars", "linux_cmdline", "linux_bash", "linux_strings", "linux_yarascan", "linux_pslist"
        ])
        self.volatility_profile = memcfg.get("volatility_profile", "Linux")
        self.yara_rules_path = memcfg.get("yara_rules_path")
        self.yara_rules = None
        from modules.utils.logger import get_logger
        self.logger = get_logger("credfinder.memorygrepper")
        if YARA_AVAILABLE and self.yara_rules_path and os.path.exists(self.yara_rules_path):
            try:
                self.yara_rules = yara.compile(filepath=self.yara_rules_path)
            except Exception as e:
                self.logger.warning(f"Failed to compile YARA rules: {e}")
                self.yara_rules = None
        elif self.yara_rules_path and not YARA_AVAILABLE:
            self.logger.warning("YARA rules specified but yara-python is not installed.")
        
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
            self.logger.warning("psutil not available, skipping process scanning")
        
        # Scan /proc files (this doesn't require psutil)
        results["proc_files"] = self._scan_proc_files()
        
        # Try Volatility if available
        if self._check_volatility():
            results["volatility_results"] = self._run_volatility_scan()
        else:
            results["volatility_results"] = {"error": "Volatility not found or not available"}
        
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
                self.logger.warning(f"Error scanning process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
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
                self.logger.warning(f"Error scanning process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
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
                        match_value = self._extract_match_value(match)
                        context = self._get_context(content, match_value)
                        
                        matches.append({
                            "type": pattern_type,
                            "pattern": pattern,
                            "match": match_value,
                            "context": context,
                            "full_match": match  # Keep original match for debugging
                        })
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Error processing pattern '{pattern}': {e}")
                    continue
        
        return matches
    
    def _extract_match_value(self, match) -> str:
        """Extract meaningful value from regex match result"""
        try:
            if isinstance(match, str):
                return match
            elif isinstance(match, tuple):
                # For regex groups, find the first non-empty group
                for group in match:
                    if group and isinstance(group, str) and group.strip():
                        return group.strip()
                # If no meaningful group found, join all groups
                return ' '.join(str(g) for g in match if g)
            elif isinstance(match, list):
                # Handle list of matches
                return str(match[0]) if match else ""
            else:
                return str(match)
        except Exception as e:
            self.logger.debug(f"Error extracting match value: {e}")
            return str(match) if match else ""
    
    def _get_context(self, content: str, match_value: str, context_size: int = 50) -> str:
        """Get context around a match with improved error handling"""
        try:
            if not match_value or not content:
                return ""
            
            # Find the match in the content
            match_pos = content.find(match_value)
            if match_pos == -1:
                # Try case-insensitive search
                match_pos = content.lower().find(match_value.lower())
                if match_pos == -1:
                    return ""
            
            # Calculate context boundaries
            start = max(0, match_pos - context_size)
            end = min(len(content), match_pos + len(match_value) + context_size)
            
            context = content[start:end]
            
            # Clean up context (remove excessive whitespace, newlines)
            context = ' '.join(context.split())
            
            # Truncate if still too long
            if len(context) > context_size * 4:
                context = context[:context_size * 4] + "..."
            
            return context
            
        except Exception as e:
            self.logger.debug(f"Error getting context for match '{match_value}': {e}")
            return f"Match: {match_value}"
    
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
    
    def _detect_volatility(self) -> str:
        """Detect Volatility 3 (vol.py) or Volatility 2 (vol) CLI. Returns command or None."""
        for cmd in ["vol.py", "vol", "volatility", "volatility3"]:
            try:
                result = subprocess.run([cmd, "--help"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return cmd
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None
    
    def _run_volatility_scan(self) -> Dict[str, Any]:
        """Run Volatility memory analysis (real integration, configurable plugins).
        All options are read from config['modules']['memory'].
        For each plugin, also scan output for secrets using self.patterns and add a 'secrets' field.
        If YARA is enabled, also add a 'yara_matches' field."""
        results = {}
        vol_cmd = self._detect_volatility()
        if not vol_cmd:
            results["error"] = "Volatility not found."
            return results
        dump_path = self.memory_dump_path
        if not os.path.exists(dump_path):
            results["error"] = f"Memory dump not found: {dump_path}"
            return results
        is_vol3 = "vol" in vol_cmd and ("vol.py" in vol_cmd or "volatility3" in vol_cmd)
        for plugin in self.volatility_plugins:
            key = plugin
            try:
                if is_vol3:
                    args = [vol_cmd, "-f", dump_path, f"linux.{plugin}"]
                else:
                    args = [vol_cmd, "-f", dump_path, "--profile=" + self.volatility_profile, plugin]
                if is_vol3:
                    args += ["--output", "json"]
                proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
                plugin_result = None
                if proc.returncode == 0:
                    try:
                        import json
                        plugin_result = json.loads(proc.stdout)
                    except Exception:
                        plugin_result = proc.stdout.strip().splitlines()
                else:
                    plugin_result = {"error": proc.stderr.strip() or "Unknown error"}
                # --- Pattern matching on plugin output ---
                secrets = []
                if isinstance(plugin_result, list):
                    for line in plugin_result:
                        secrets.extend(self._check_patterns(str(line)))
                elif isinstance(plugin_result, dict):
                    for v in plugin_result.values():
                        if isinstance(v, str):
                            secrets.extend(self._check_patterns(v))
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, str):
                                    secrets.extend(self._check_patterns(item))
                                elif isinstance(item, dict):
                                    for val in item.values():
                                        if isinstance(val, str):
                                            secrets.extend(self._check_patterns(val))
                elif isinstance(plugin_result, str):
                    secrets.extend(self._check_patterns(plugin_result))
                # --- YARA matching on plugin output ---
                yara_matches = []
                if self.yara_rules:
                    def scan_yara(data):
                        try:
                            matches = self.yara_rules.match(data=data)
                            return [
                                {
                                    "rule": m.rule,
                                    "strings": [(offset, s, v.decode(errors='replace') if isinstance(v, bytes) else v)
                                                 for (offset, s, v) in m.strings]
                                }
                                for m in matches
                            ]
                        except Exception as e:
                            return [{"error": str(e)}]
                    if isinstance(plugin_result, list):
                        for line in plugin_result:
                            yara_matches.extend(scan_yara(str(line)))
                    elif isinstance(plugin_result, dict):
                        for v in plugin_result.values():
                            if isinstance(v, str):
                                yara_matches.extend(scan_yara(v))
                            elif isinstance(v, list):
                                for item in v:
                                    if isinstance(item, str):
                                        yara_matches.extend(scan_yara(item))
                                    elif isinstance(item, dict):
                                        for val in item.values():
                                            if isinstance(val, str):
                                                yara_matches.extend(scan_yara(val))
                    elif isinstance(plugin_result, str):
                        yara_matches.extend(scan_yara(plugin_result))
                results[key] = {
                    "output": plugin_result,
                    "secrets": secrets,
                    "yara_matches": yara_matches
                }
            except Exception as e:
                results[key] = {"error": str(e), "secrets": [], "yara_matches": []}
        return results
    
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