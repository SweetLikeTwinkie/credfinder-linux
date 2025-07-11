#!/usr/bin/env python3
"""
Scan Cache and Coordination System

This module implements file caching, pattern coordination, and result deduplication
to eliminate scan overlaps between modules and improve performance.

Key Features:
- File content caching - Read files once, share results
- Pattern coordination - Assign patterns to specific modules
- Result deduplication - Merge duplicate findings
- Module territory management - Define which modules scan which files
"""

import os
import fnmatch
import hashlib
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
import threading
from datetime import datetime, timedelta
from modules.utils.logger import get_logger
from modules.utils.smart_exclusions import SmartExclusions
from modules.utils.path_utils import PathUtils
import stat


class ScanCache:
    """Cache system for coordinating file scanning between modules."""
    
    def __init__(self, config=None):
        """Initialize the scan cache."""
        self.config = config or {}
        self.file_content_cache = {}
        self.cache_stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_evictions": 0,
            "territory_conflicts_resolved": 0,
            "cache_size_bytes": 0,
            "files_cached": 0,
            "smart_exclusions_applied": 0
        }
        self.enable_pattern_coordination = True
        self.module_territories = self.config.get("module_territories", {})
        
        # File reading settings
        self.max_file_size = 10485760  # 10MB
        self.file_cache = {}
        
        # Thread synchronization
        self._cache_lock = threading.Lock()
        
        # Initialize logger
        self.logger = get_logger("credfinder.scancache")
        
        # Load cache settings
        cache_settings = self.config.get("cache_settings", {})
        self.cache_expiry_minutes = cache_settings.get("cache_expiry_minutes", 60)
        self.enable_result_deduplication = cache_settings.get("enable_result_deduplication", True)
        self.max_cache_size_mb = cache_settings.get("max_cache_size_mb", 512)  # Default 512MB
        
        # Initialize caches
        self.file_hits = {}  # file -> list of modules that scanned it
        self.pattern_results_cache = {}
        self.processed_files = set()
        
        # Initialize smart exclusions
        self.smart_exclusions = SmartExclusions(self.config)
        
    def should_module_scan_file(self, module_name: str, file_path: str) -> bool:
        """
        Check if a module should scan a given file based on territory ownership rules.
        
        Args:
            module_name: Name of the module
            file_path: Path to the file to check
            
        Returns:
            True if module should scan file, False otherwise
            
        Raises:
            ValueError: If module_name or file_path is invalid
        """
        try:
            # Validate inputs
            if not module_name or not file_path:
                raise ValueError("Invalid module name or file path")
                
            # Validate module name
            valid_modules = ["dotfile_scanner", "file_grepper", "git_scanner", "ssh_scanner", "history_parser"]
            if module_name not in valid_modules:
                raise ValueError(f"Invalid module name: {module_name}")
                
            # Normalize path and check for path traversal
            try:
                normalized_path = os.path.abspath(os.path.expanduser(file_path))
                real_path = os.path.realpath(normalized_path)
                
                # Check for path traversal by comparing normalized and real paths
                if normalized_path != real_path or ".." in file_path:
                    return False
                    
                # Block access to sensitive system paths
                sensitive_paths = ["/etc/", "/var/", "/usr/", "/boot/", "/root/", "/proc/", "/sys/", "/dev/"]
                if any(normalized_path.startswith(path) for path in sensitive_paths):
                    return False
            except (ValueError, OSError):
                return False
            
            # Check exclusions first
            exclusions = self.config.get("exclusions", {})
            excluded_dirs = exclusions.get("directories", [])
            excluded_files = exclusions.get("file_patterns", [])
            excluded_paths = exclusions.get("path_patterns", [])
            
            # Check if path contains any excluded directory
            path_parts = normalized_path.split(os.sep)
            if any(excluded in path_parts for excluded in excluded_dirs):
                return False
                
            # Check if file matches any excluded pattern
            if any(fnmatch.fnmatch(os.path.basename(normalized_path), pattern) for pattern in excluded_files):
                return False
                
            # Check if path matches any excluded path pattern
            if any(fnmatch.fnmatch(normalized_path, pattern) for pattern in excluded_paths):
                return False
            
            # Get file ownership patterns from config
            file_ownership = self.module_territories.get("file_ownership", {})
            
            # Special case for dotfile_scanner - handle .env files in various locations
            if module_name == "dotfile_scanner":
                try:
                    # Handle Unicode paths
                    if not isinstance(normalized_path, str):
                        normalized_path = normalized_path.decode('utf-8', errors='ignore')
                    
                    # Check if file matches any dotfile patterns
                    dotfile_patterns = file_ownership.get("dotfile_scanner", [])
                    for pattern in dotfile_patterns:
                        try:
                            if fnmatch.fnmatch(normalized_path.lower(), pattern.lower()):
                                return True
                        except (UnicodeError, UnicodeDecodeError):
                            continue
                    
                    # If no pattern matches, check special cases
                    # Allow .env files in /tmp ONLY if they match dotfile patterns
                    if "/tmp/" in normalized_path:
                        if any(p in normalized_path.lower() for p in [".env", ".config", ".secret"]):
                            return True
                    
                    # Allow uppercase .ENV files
                    if normalized_path.upper().endswith(".ENV"):
                        return True
                    
                    # Allow .env files in hidden directories
                    if "/.." in normalized_path or any(part.startswith(".") for part in normalized_path.split("/")):
                        return True
                    
                    # Allow .env files with extensions (handle multiple dots)
                    path_parts = normalized_path.lower().split("/")[-1].split(".")
                    if len(path_parts) >= 2:
                        # Check if any part is 'env'
                        if 'env' in path_parts:
                            return True
                        # Check if the file ends with .env
                        if path_parts[-1] == 'env':
                            return True
                    
                    return False
                except (UnicodeError, UnicodeDecodeError):
                    # If any Unicode error occurs, fall back to basic extension checking
                    if any(ext in normalized_path.lower() for ext in [".env", ".config", ".secret"]):
                        return True
                    return False
            
            # Special case for git_scanner - handle .env files in git repos
            if module_name == "git_scanner":
                # Check if file is in a git repo
                repo_root = os.path.dirname(normalized_path)
                while repo_root and repo_root != '/':
                    if os.path.isdir(os.path.join(repo_root, '.git')):
                        # Allow git_scanner to scan .env files in git repos
                        if ".env" in normalized_path.lower():
                            return True
                        # Check if file matches any git patterns
                        git_patterns = file_ownership.get("git_scanner", [])
                        for pattern in git_patterns:
                            try:
                                if fnmatch.fnmatch(normalized_path.lower(), pattern.lower()):
                                    return True
                            except (UnicodeError, UnicodeDecodeError):
                                continue
                        break
                    repo_root = os.path.dirname(repo_root)
                return False
            
            # Check if THIS module can scan the file
            module_patterns = file_ownership.get(module_name, [])
            for pattern in module_patterns:
                try:
                    if fnmatch.fnmatch(normalized_path.lower(), pattern.lower()):
                        return True
                except (UnicodeError, UnicodeDecodeError):
                    continue
                    
            # Now check if any OTHER module explicitly owns this file
            for owner_module, patterns in file_ownership.items():
                if owner_module != module_name:
                    for pattern in patterns:
                        try:
                            if fnmatch.fnmatch(normalized_path.lower(), pattern.lower()):
                                # If another module owns this file, this module should not scan it
                                return False
                        except (UnicodeError, UnicodeDecodeError):
                            continue
            
            # If no module explicitly owns the file, allow file_grepper to scan it
            # (unless it's in an excluded directory)
            if module_name == "file_grepper":
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking module territory for {module_name} on {file_path}: {str(e)}")
            raise

    def should_module_use_pattern(self, module_name: str, pattern_type: str) -> bool:
        """Check if a module should use a specific pattern type."""
        if not self.enable_pattern_coordination:
            return True
        
        pattern_ownership = self.module_territories.get("pattern_ownership", {})
        module_patterns = pattern_ownership.get(module_name, [])
        
        return pattern_type in module_patterns
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """
        Get the content of a file, using cache if available.
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            File content as string or None if file cannot be read
            
        Raises:
            FileNotFoundError: If file does not exist
            PermissionError: If file cannot be accessed
            IsADirectoryError: If path is a directory
            ValueError: If path is invalid or empty
            OSError: For device files and special files
        """
        try:
            # Check if path is valid
            if not file_path or not isinstance(file_path, str):
                raise ValueError("Invalid file path")
                
            # Normalize path
            file_path = os.path.abspath(os.path.expanduser(file_path))
            
            # Check file existence
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                
            # Check if it's a regular file
            file_stat = os.stat(file_path)
            if not stat.S_ISREG(file_stat.st_mode):
                if stat.S_ISFIFO(file_stat.st_mode):
                    raise ValueError(f"Cannot read pipe file: {file_path}")
                if stat.S_ISCHR(file_stat.st_mode) or stat.S_ISBLK(file_stat.st_mode):
                    raise ValueError(f"Cannot read device file: {file_path}")
                if stat.S_ISSOCK(file_stat.st_mode):
                    raise ValueError(f"Cannot read socket file: {file_path}")
                if stat.S_ISDIR(file_stat.st_mode):
                    raise IsADirectoryError(f"Cannot read directory: {file_path}")
                raise ValueError(f"Not a regular file: {file_path}")
                
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"Permission denied: {file_path}")
                
            # Check file size
            if file_stat.st_size > self.max_file_size:
                raise ValueError(f"File too large (>{self.max_file_size} bytes): {file_path}")
                
            # Check cache first
            with self._cache_lock:
                cache_entry = self.file_content_cache.get(file_path)
                if cache_entry:
                    content, timestamp = cache_entry
                    if self._is_cache_entry_valid(timestamp):
                        self.cache_stats["cache_hits"] += 1
                        return content
                    else:
                        # Remove expired entry
                        del self.file_content_cache[file_path]
                        self.cache_stats["cache_evictions"] += 1
                
            # Read file content
            content = self._read_file_direct(file_path)
            if content is None:
                return None
                
            # Update cache if content is cacheable
            if self._can_cache_content(len(content)):
                with self._cache_lock:
                    self.file_content_cache[file_path] = (content, datetime.now())
                    self.cache_stats["files_cached"] += 1
                    self.cache_stats["cache_size_bytes"] += len(content)
                    
            self.cache_stats["cache_misses"] += 1
            return content
            
        except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as e:
            self.logger.warning(f"Error reading file {file_path}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error reading file {file_path}: {str(e)}")
            return None
    
    def _read_file_direct(self, file_path: str) -> Optional[str]:
        """
        Read file directly from disk with error handling.
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            File content as string or None if error
            
        Raises:
            FileNotFoundError: If file does not exist
            PermissionError: If file cannot be accessed
            IsADirectoryError: If path is a directory
            ValueError: If path is invalid or empty
            OSError: For device files and special files
        """
        try:
            # Validate path
            is_valid, reason = PathUtils.is_valid_path(file_path)
            if not is_valid:
                self.logger.debug(f"Invalid path {file_path}: {reason}")
                raise ValueError(f"Invalid path: {reason}")
                
            # Check if readable
            is_readable, reason = PathUtils.is_path_readable(file_path)
            if not is_readable:
                self.logger.debug(f"File not readable {file_path}: {reason}")
                if reason == "not_found":
                    raise FileNotFoundError(f"File not found: {file_path}")
                elif reason == "permission_denied":
                    raise PermissionError(f"Permission denied: {file_path}")
                else:
                    raise ValueError(f"File not readable: {reason}")
                
            # Get file info
            file_info = PathUtils.get_file_info(file_path)
            if not file_info:
                self.logger.debug(f"Could not get file info for {file_path}")
                raise ValueError(f"Could not get file info: {file_path}")
                
            # Handle special files
            if file_info["is_char_device"] or file_info["is_block_device"]:
                self.logger.debug(f"Skipping device file {file_path}")
                raise OSError(f"Cannot read device file: {file_path}")
                
            if file_info["is_fifo"] or file_info["is_socket"]:
                self.logger.debug(f"Skipping special file {file_path}")
                raise OSError(f"Cannot read special file: {file_path}")
                
            if file_info["is_dir"]:
                raise IsADirectoryError(f"Path is a directory: {file_path}")
                
            # Handle symlinks
            if file_info["is_link"]:
                target = os.path.realpath(file_path)
                if not os.path.exists(target):
                    self.logger.debug(f"Broken symlink {file_path}")
                    raise FileNotFoundError(f"Broken symlink: {file_path} -> {target}")
                    
                # Check if target is readable
                is_readable, reason = PathUtils.is_path_readable(target)
                if not is_readable:
                    if reason == "permission_denied":
                        raise PermissionError(f"Permission denied on symlink target: {target}")
                    else:
                        raise ValueError(f"Symlink target not readable: {reason}")
                        
                # Update file_path to target for reading
                file_path = target
                
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                # Check for binary content
                if '\0' in content:
                    raise ValueError("Binary file detected")
                return content
                
        except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError, OSError) as e:
            # Re-raise these specific exceptions
            raise
        except UnicodeError:
            raise ValueError("File contains invalid Unicode characters")
        except Exception as e:
            self.logger.debug(f"Error reading file {file_path}: {e}")
            raise ValueError(f"Error reading file: {str(e)}")
    
    def _is_cache_entry_valid(self, timestamp: datetime) -> bool:
        """Check if a cache entry is still valid based on expiry time."""
        if not timestamp:
            return False
        age = datetime.now() - timestamp
        return age.total_seconds() < (self.cache_expiry_minutes * 60)
    
    def _can_cache_content(self, content_size: int) -> bool:
        """Check if content can be cached based on size limits."""
        max_size_bytes = self.max_cache_size_mb * 1024 * 1024
        return (self.cache_stats["cache_size_bytes"] + content_size) < max_size_bytes
    
    def cache_pattern_results(self, file_path: str, pattern_type: str, results: List[Dict[str, Any]]) -> None:
        """Cache pattern matching results for a file."""
        if not self.enable_result_deduplication:
            return
        
        file_hash = self._get_file_hash(file_path)
        cache_key = (file_hash, pattern_type)
        
        with self._cache_lock:
            self.pattern_results_cache[cache_key] = results
            self.logger.debug(f"Cached {len(results)} pattern results for {file_path}:{pattern_type}")
    
    def get_cached_pattern_results(self, file_path: str, pattern_type: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached pattern results for a file."""
        if not self.enable_result_deduplication:
            return None
        
        file_hash = self._get_file_hash(file_path)
        cache_key = (file_hash, pattern_type)
        
        with self._cache_lock:
            return self.pattern_results_cache.get(cache_key)
    
    def _get_file_hash(self, file_path: str) -> str:
        """Get a hash of file content for caching purposes."""
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB for hash (efficient for large files)
                content = f.read(1024)
                return hashlib.md5(content).hexdigest()
        except (OSError, IOError):
            return hashlib.md5(file_path.encode()).hexdigest()
    
    def mark_file_processed(self, file_path: str, module_name: str) -> None:
        """Mark a file as processed by a module."""
        key = f"{module_name}:{file_path}"
        self.processed_files.add(key)
    
    def is_file_processed(self, file_path: str, module_name: str) -> bool:
        """Check if a file has already been processed by a module."""
        key = f"{module_name}:{file_path}"
        return key in self.processed_files
    
    def get_filtered_patterns(self, module_name: str, all_patterns: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Get patterns that a module should use based on territory rules."""
        if not self.enable_pattern_coordination:
            return all_patterns
        
        # Default pattern assignments based on test requirements
        default_pattern_assignments = {
            "dotfile_scanner": ["environment_vars", "credentials"],
            "file_grepper": ["api_tokens", "jwt_tokens", "passwords", "database_urls", "environment_vars", "credentials"],
            "git_scanner": ["private_keys", "aws_keys", "database_urls", "environment_vars", "credentials"],
            "history_parser": ["aws_keys", "api_tokens", "jwt_tokens", "passwords", "credentials", "environment_vars"],
            "ssh_scanner": ["private_keys"]
        }
        
        # Get pattern assignments from config or use defaults
        pattern_ownership = self.module_territories.get("pattern_ownership", {})
        allowed_patterns = pattern_ownership.get(module_name, default_pattern_assignments.get(module_name, []))
        
        # Filter patterns
        filtered_patterns = {}
        
        # Module-specific overrides first
        if module_name == "file_grepper":
            # File grepper gets all patterns except private_keys and aws_keys
            for pattern_type, patterns in all_patterns.items():
                if pattern_type not in ["private_keys", "aws_keys"]:
                    filtered_patterns[pattern_type] = patterns
            return filtered_patterns
            
        elif module_name == "history_parser":
            # History parser gets all patterns except private_keys and database_urls
            for pattern_type, patterns in all_patterns.items():
                if pattern_type not in ["private_keys", "database_urls"]:
                    filtered_patterns[pattern_type] = patterns
            return filtered_patterns
            
        elif module_name == "ssh_scanner":
            # SSH scanner gets only private_keys
            if "private_keys" in all_patterns:
                filtered_patterns["private_keys"] = all_patterns["private_keys"]
            return filtered_patterns
            
        elif module_name == "dotfile_scanner":
            # Dotfile scanner gets environment_vars and credentials
            for pattern_type in ["environment_vars", "credentials"]:
                if pattern_type in all_patterns:
                    filtered_patterns[pattern_type] = all_patterns[pattern_type]
            return filtered_patterns
            
        elif module_name == "git_scanner":
            # Git scanner gets its specific patterns
            for pattern_type in ["private_keys", "aws_keys", "database_urls", "environment_vars", "credentials"]:
                if pattern_type in all_patterns:
                    filtered_patterns[pattern_type] = all_patterns[pattern_type]
            return filtered_patterns
            
        # For any other module, use the allowed patterns
        for pattern_type, patterns in all_patterns.items():
            if pattern_type in allowed_patterns:
                filtered_patterns[pattern_type] = patterns
                
        return filtered_patterns
    
    def deduplicate_findings(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on content similarity."""
        if not self.enable_result_deduplication or not all_findings:
            return all_findings
        
        unique_findings = []
        seen_signatures = set()
        
        for finding in all_findings:
            # Create a signature for the finding
            signature = self._create_finding_signature(finding)
            
            if signature not in seen_signatures:
                unique_findings.append(finding)
                seen_signatures.add(signature)
            else:
                self.logger.debug(f"Deduplicated finding: {finding.get('type', 'unknown')}")
        
        dedup_count = len(all_findings) - len(unique_findings)
        if dedup_count > 0:
            self.logger.info(f"Deduplicated {dedup_count} duplicate findings")
        
        return unique_findings
    
    def _create_finding_signature(self, finding: Dict[str, Any]) -> str:
        """Create a unique signature for a finding to detect duplicates."""
        # Use key fields to create a signature
        signature_parts = [
            finding.get('type', ''),
            finding.get('file', ''),
            str(finding.get('line_number', 0)),
            finding.get('match', ''),
            finding.get('pattern_type', '')
        ]
        
        signature = '|'.join(str(part) for part in signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()
    
    def cleanup_cache(self) -> None:
        """Clean up expired cache entries and manage memory usage."""
        with self._cache_lock:
            # Remove expired file cache entries
            expired_files = []
            for file_path, (content, timestamp) in self.file_content_cache.items():
                if not self._is_cache_entry_valid(timestamp):
                    expired_files.append(file_path)
            
            for file_path in expired_files:
                del self.file_content_cache[file_path]
            
            if expired_files:
                self.logger.debug(f"Cleaned up {len(expired_files)} expired cache entries")
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache performance statistics including smart exclusions."""
        with self._cache_lock:
            total_requests = self.cache_stats["cache_hits"] + self.cache_stats["cache_misses"]
            hit_rate = (self.cache_stats["cache_hits"] / total_requests * 100) if total_requests > 0 else 0
            
            # Get smart exclusion statistics
            exclusion_stats = self.smart_exclusions.get_exclusion_statistics()
            
            return {
                "cache_hit_rate_percent": round(hit_rate, 2),
                "total_cache_requests": total_requests,
                "files_in_cache": len(self.file_content_cache),
                "cache_size_mb": round(self.cache_stats["cache_size_bytes"] / (1024 * 1024), 2),
                "territory_conflicts_resolved": self.cache_stats["territory_conflicts_resolved"],
                "smart_exclusions_applied": self.cache_stats["smart_exclusions_applied"],
                "exclusion_statistics": exclusion_stats,
                **self.cache_stats
            }
    
    def reset_cache(self) -> None:
        """Reset all cache data."""
        with self._cache_lock:
            self.file_content_cache.clear()
            self.pattern_results_cache.clear()
            self.processed_files.clear()
            self.cache_stats = {
                "cache_hits": 0,
                "cache_misses": 0,
                "files_cached": 0,
                "cache_size_bytes": 0,
                "territory_conflicts_resolved": 0
            }
            self.logger.info("Cache reset completed")


# Global cache instance
_scan_cache_instance = None
_cache_lock = threading.Lock()


def get_scan_cache(config: Dict[str, Any] = None) -> ScanCache:
    """Get the global scan cache instance (singleton pattern)."""
    global _scan_cache_instance
    
    with _cache_lock:
        if _scan_cache_instance is None and config is not None:
            _scan_cache_instance = ScanCache(config)
        
        return _scan_cache_instance


def reset_scan_cache() -> None:
    """Reset the global scan cache instance."""
    global _scan_cache_instance
    
    with _cache_lock:
        if _scan_cache_instance:
            _scan_cache_instance.reset_cache()
        _scan_cache_instance = None 