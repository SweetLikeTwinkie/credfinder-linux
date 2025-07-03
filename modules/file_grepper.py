#!/usr/bin/env python3
"""
File Grepper Module

This module performs safe, file-based credential scanning across the filesystem.
It searches for credential patterns in common file types and locations without
requiring dangerous memory access or elevated privileges.

Key Features:
- Pattern-based credential detection using regex
- Safe file size and type filtering
- Process environment variable scanning via ps command
- Common temporary location scanning
- Binary file detection and skipping
- Configurable search parameters

Contributors: This module is designed for safety and performance.
All file operations include size limits, error handling, and timeout protection.
The search scope can be customized via configuration to balance thoroughness vs speed.
"""

import os
import re
import glob
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from modules.utils.logger import get_logger


class FileGrepper:
    def __init__(self, config):
        self.config = config
        self.patterns = config.get("patterns", {})
        self.scan_paths = config.get("scan_paths", {})
        self.logger = get_logger("credfinder.filegrepper")
        
        # Load exclusion settings
        self.exclusions = config.get("exclusions", {})
        self.excluded_dirs = set(self.exclusions.get("directories", []))
        self.excluded_file_patterns = self.exclusions.get("file_patterns", [])
        self.excluded_path_patterns = self.exclusions.get("path_patterns", [])

        
        # Load file grep settings from config to avoid hardcoded values
        self.grep_settings = config.get("module_settings", {}).get("file_grep", {})
        
        # File search configuration
        self.file_extensions = self.grep_settings.get("file_extensions", [
            "*.txt", "*.log", "*.conf", "*.config", "*.ini", "*.properties",
            "*.yaml", "*.yml", "*.json", "*.xml", "*.env", "*.sh", "*.py",
            "*.js", "*.php", "*.rb", "*.go", "*.java", "*.sql", "*.bak",
            "*.backup", "*.old", "*.tmp"
        ])
        self.search_base_paths = self.grep_settings.get("search_base_paths", [
            "~/", "~/.config/", "~/.local/", "/tmp/", "/var/tmp/",
            "/var/log/", "/etc/", "/opt/", "/srv/"
        ])
        
        # File processing limits (for performance and safety)
        self.max_files_per_pattern = self.grep_settings.get("max_files_per_pattern", 100)
        self.max_files_common_location = self.grep_settings.get("max_files_common_location", 50)
        self.max_file_size_bytes = self.grep_settings.get("max_file_size_bytes", 10485760)  # 10MB
        self.max_file_read_bytes = self.grep_settings.get("max_file_read_bytes", 100000)    # 100KB
        self.max_common_file_read_bytes = self.grep_settings.get("max_common_file_read_bytes", 50000)  # 50KB
        
        # Process and output configuration
        self.process_scan_timeout = self.grep_settings.get("process_scan_timeout", 30)
        self.command_preview_length = self.grep_settings.get("command_preview_length", 200)
        self.context_size = self.grep_settings.get("context_size", 80)
        self.min_match_length = self.grep_settings.get("min_match_length", 3)
        self.binary_detection_chunk_size = self.grep_settings.get("binary_detection_chunk_size", 1024)
        
    def scan(self) -> Dict[str, Any]:
        """
        Main scan method that coordinates all file-based credential searches.
        
        This method orchestrates three types of scans:
        1. Broad file scanning using common extensions and paths
        2. Process environment variable scanning (safe via ps command)
        3. Targeted scanning of common credential storage locations
        
        Returns:
            Dict with organized scan results and statistics
        """
        results = {
            "file_matches": [],
            "process_environ": [],
            "common_locations": [],
            "scan_stats": {
                "files_scanned": 0,
                "files_with_findings": 0,
                "access_denied": 0,
                "patterns_matched": 0
            }
        }
        
        # Scan common file locations for credential patterns
        results["file_matches"] = self._scan_files(results["scan_stats"])
        
        # Scan process environment variables using safe ps command
        results["process_environ"] = self._scan_process_environ(results["scan_stats"])
        
        # Scan specific common credential storage locations
        results["common_locations"] = self._scan_common_locations(results["scan_stats"])
        
        self.logger.info(f"File grep completed: {results['scan_stats']['files_scanned']} files scanned, "
                        f"{results['scan_stats']['files_with_findings']} with findings")
        
        return results
    
    def _scan_files(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Scan files across the filesystem using configurable patterns.
        
        This method searches through common directories using file extension filters
        to find potential credential-containing files. It includes safety limits
        to prevent excessive resource usage.
        
        Args:
            stats: Statistics dictionary to update during scanning
            
        Returns:
            List of files containing credential pattern matches
        """
        findings = []
        
        for base_path in self.search_base_paths:
            try:
                expanded_path = os.path.expanduser(base_path)
                if not os.path.exists(expanded_path):
                    continue
                    
                # Search each configured file extension in this path
                for ext in self.file_extensions:
                    pattern = os.path.join(expanded_path, "**", ext)
                    try:
                        # SECURITY FIX: Limit recursive depth to prevent DoS attacks
                        # Only search 3 levels deep to prevent infinite loops with symlinks
                        files = []
                        for depth in range(3):  # 0, 1, 2 levels deep
                            search_pattern = expanded_path + ("/*" * (depth + 1)) + "/" + ext
                            files.extend(glob.glob(search_pattern))
                        # Remove duplicates while preserving order
                        files = list(dict.fromkeys(files))
                        # Limit files per pattern to prevent excessive processing
                        for file_path in files[:self.max_files_per_pattern]:
                            # Skip excluded files
                            if self._should_exclude_path(file_path):
                                continue
                                
                            # Apply size filter to avoid reading huge files
                            if (os.path.isfile(file_path) and 
                                os.path.getsize(file_path) < self.max_file_size_bytes):
                                
                                finding = self._scan_single_file(file_path, stats)
                                if finding:
                                    findings.append(finding)
                                    stats["files_with_findings"] += 1
                                stats["files_scanned"] += 1
                    except (PermissionError, OSError):
                        stats["access_denied"] += 1
                        continue
                        
            except Exception as e:
                self.logger.warning(f"Error scanning path {base_path}: {e}")
                continue
        
        return findings
    
    def _scan_single_file(self, file_path: str, stats: Dict[str, int]) -> Dict[str, Any]:
        """
        Scan a single file for credential patterns.
        
        This method safely reads and analyzes individual files with proper
        error handling and size limits to prevent resource exhaustion.
        
        Args:
            file_path: Path to the file to scan
            stats: Statistics dictionary to update
            
        Returns:
            Dict with file info and matches, or None if no matches found
        """
        try:
            # Read file content with size limit for safety
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(self.max_file_read_bytes)
            
            # Check for credential patterns in the content
            pattern_matches = self._check_patterns(content)
            if pattern_matches:
                stats["patterns_matched"] += len(pattern_matches)
                return {
                    "file": file_path,
                    "type": "file_scan",
                    "pattern_matches": pattern_matches,
                    "file_size": os.path.getsize(file_path),
                    "modified_time": os.path.getmtime(file_path)
                }
        except (PermissionError, UnicodeDecodeError, OSError):
            stats["access_denied"] += 1
        except Exception as e:
            self.logger.debug(f"Error scanning file {file_path}: {e}")
        
        return None
    
    def _scan_process_environ(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Safely scan process environment variables for credentials.
        
        This method uses the 'ps' command to examine environment variables
        of running processes. This is much safer than reading /proc directly
        and doesn't require elevated privileges.
        
        Args:
            stats: Statistics dictionary to update
            
        Returns:
            List of processes with credential patterns in their environment
        """
        findings = []
        
        try:
            # Use ps command with environment display (safer than /proc access)
            result = subprocess.run(
                ['ps', 'eww', '-o', 'pid,cmd'],  # Show environment and wide format
                capture_output=True,
                text=True,
                timeout=self.process_scan_timeout
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    # Look for lines containing environment variables (key=value format)
                    if '=' in line:
                        pattern_matches = self._check_patterns(line)
                        if pattern_matches:
                            # Extract PID from the process line
                            parts = line.split(None, 1)
                            pid = parts[0] if parts[0].isdigit() else "unknown"
                            
                            # Truncate command line for display
                            command_preview = line[:self.command_preview_length]
                            if len(line) > self.command_preview_length:
                                command_preview += "..."
                            
                            findings.append({
                                "pid": pid,
                                "type": "process_environment",
                                "pattern_matches": pattern_matches,
                                "command_preview": command_preview
                            })
                            stats["patterns_matched"] += len(pattern_matches)
                            
        except subprocess.TimeoutExpired:
            self.logger.warning("Process environment scan timed out")
        except Exception as e:
            self.logger.warning(f"Error scanning process environment: {e}")
        
        return findings
    
    def _scan_common_locations(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Scan common locations where credentials are often stored.
        
        This method targets specific paths where credentials are commonly found,
        such as temporary directories, download folders, and shared memory.
        
        Args:
            stats: Statistics dictionary to update
            
        Returns:
            List of files in common locations containing credential patterns
        """
        findings = []
        
        common_paths = self.scan_paths.get("common_files", [])
        
        for path_pattern in common_paths:
            try:
                expanded_pattern = os.path.expanduser(path_pattern)
                files = glob.glob(expanded_pattern)
                
                # Limit files per pattern to prevent excessive processing
                for file_path in files[:self.max_files_common_location]:
                    if os.path.isfile(file_path):
                        # Skip excluded files
                        if self._should_exclude_path(file_path):
                            continue
                        
                        try:
                            # Skip binary files to improve performance and accuracy
                            if self._is_binary_file(file_path):
                                continue
                                
                            # Read with smaller limit for common locations (faster processing)
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read(self.max_common_file_read_bytes)
                            
                            pattern_matches = self._check_patterns(content)
                            if pattern_matches:
                                findings.append({
                                    "file": file_path,
                                    "type": "common_location",
                                    "pattern_matches": pattern_matches,
                                    "location_type": self._get_location_type(file_path)
                                })
                                stats["patterns_matched"] += len(pattern_matches)
                                stats["files_with_findings"] += 1
                            
                            stats["files_scanned"] += 1
                            
                        except (PermissionError, UnicodeDecodeError):
                            stats["access_denied"] += 1
                        except Exception as e:
                            self.logger.debug(f"Error scanning common location {file_path}: {e}")
                            
            except Exception as e:
                self.logger.warning(f"Error scanning common location pattern {path_pattern}: {e}")
        
        return findings
    
    def _check_patterns(self, content: str) -> List[Dict[str, Any]]:
        """
        Check content against all configured credential patterns.
        
        This method applies all configured regex patterns to the given content
        and returns information about any matches found, including context.
        
        Args:
            content: Text content to search for patterns
            
        Returns:
            List of pattern match information
        """
        matches = []
        
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    # Use case-insensitive multiline search for better matching
                    regex_matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in regex_matches:
                        match_value = self._extract_match_value(match)
                        # Filter out very short matches (likely false positives)
                        if match_value and len(match_value) > self.min_match_length:
                            context = self._get_context(content, match_value)
                            
                            matches.append({
                                "type": pattern_type,
                                "pattern": pattern,
                                "match": match_value,
                                "context": context
                            })
                except re.error:
                    self.logger.debug(f"Invalid regex pattern: {pattern}")
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing pattern {pattern}: {e}")
                    continue
        
        return matches
    
    def _extract_match_value(self, match) -> str:
        """
        Extract the meaningful value from a regex match result.
        
        Regex matches can return strings, tuples (for groups), or other types.
        This method normalizes the result to get the actual credential value.
        
        Args:
            match: Result from re.findall()
            
        Returns:
            Cleaned string value of the match
        """
        if isinstance(match, str):
            return match.strip()
        elif isinstance(match, tuple):
            # For regex groups, find the first non-empty group
            for group in match:
                if group and isinstance(group, str) and group.strip():
                    return group.strip()
            # If no good group found, join all groups
            return ' '.join(str(g) for g in match if g)
        else:
            return str(match).strip()
    
    def _get_context(self, content: str, match_value: str) -> str:
        """
        Extract surrounding context text around a pattern match.
        
        Context helps analysts understand how the credential is used
        and determine if it's a false positive or legitimate finding.
        
        Args:
            content: Full text content
            match_value: The matched credential string
            
        Returns:
            Context string with surrounding text
        """
        try:
            # Find the position of the match in the content
            match_pos = content.find(match_value)
            if match_pos == -1:
                # Try case-insensitive search as fallback
                match_pos = content.lower().find(match_value.lower())
                if match_pos == -1:
                    return ""
            
            # Calculate context boundaries
            start = max(0, match_pos - self.context_size)
            end = min(len(content), match_pos + len(match_value) + self.context_size)
            
            context = content[start:end]
            # Clean up whitespace for better readability
            context = ' '.join(context.split())
            
            # Truncate if still too long
            max_context_length = self.context_size * 3
            if len(context) > max_context_length:
                context = context[:max_context_length] + "..."
            
            return context
            
        except Exception:
            # Fallback to just showing the match
            return f"Match: {match_value}"
    
    def _is_binary_file(self, file_path: str) -> bool:
        """
        Check if a file is binary (contains non-text data).
        
        Binary files are skipped to improve performance and reduce false positives.
        This method reads a small chunk and looks for null bytes which indicate binary data.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if file appears to be binary, False otherwise
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(self.binary_detection_chunk_size)
                # Null bytes are strong indicators of binary data
                return b'\0' in chunk
        except Exception:
            # If we can't read it, assume it's binary to be safe
            return True
    
    def _get_location_type(self, file_path: str) -> str:
        """
        Categorize the type of location where a file was found.
        
        This helps analysts understand the context of credential discoveries
        and prioritize their investigation efforts.
        
        Args:
            file_path: Path to the file
            
        Returns:
            String describing the location type
        """
        # Categorize based on path patterns
        if '/tmp/' in file_path or '/var/tmp/' in file_path:
            return "temporary"
        elif '/dev/shm/' in file_path:
            return "shared_memory"
        elif 'Downloads' in file_path:
            return "downloads"
        elif 'Desktop' in file_path:
            return "desktop"
        else:
            return "other"
    
    def _should_exclude_path(self, path: str) -> bool:
        """
        Check if a path should be excluded based on exclusion rules.
        
        Args:
            path: Path to check for exclusions
            
        Returns:
            True if path should be excluded
        """
        import fnmatch
        
        # Normalize path for consistent checking
        normalized_path = os.path.normpath(path)
        path_parts = normalized_path.split(os.sep)
        
        # Check directory exclusions
        for part in path_parts:
            if part in self.excluded_dirs:
                return True
        
        # Check path pattern exclusions
        for pattern in self.excluded_path_patterns:
            if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(path, pattern):
                return True
        
        # Check file pattern exclusions for files
        if os.path.isfile(path):
            filename = os.path.basename(path)
            for pattern in self.excluded_file_patterns:
                if fnmatch.fnmatch(filename, pattern):
                    return True
        
        return False
    
 