#!/usr/bin/env python3
"""
Smart Exclusion System

This module implements intelligent file and path exclusion logic to skip irrelevant
files early in the scanning process, improving performance and reducing false positives.

Key Features:
- Content-based file classification
- Performance-optimized early filtering
- Dynamic exclusion rules based on file characteristics
- Machine learning-inspired heuristics
- Detailed exclusion statistics and reasoning
"""

import os
import re
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from modules.utils.logger import get_logger
import fnmatch
import stat
from .path_utils import PathUtils

# Global instance for the module-level is_excluded function
_smart_exclusions = None

def get_smart_exclusions(config: Optional[Dict[str, Any]] = None) -> 'SmartExclusions':
    """Get or create the global SmartExclusions instance."""
    global _smart_exclusions
    if _smart_exclusions is None and config is not None:
        _smart_exclusions = SmartExclusions(config)
    return _smart_exclusions

def is_excluded(file_path: str) -> tuple[bool, str]:
    """Check if a file should be excluded from scanning.
    
    Args:
        file_path: Path to check
        
    Returns:
        Tuple of (is_excluded, reason)
    """
    if not file_path:
        return True, "empty_path"
        
    # Use PathUtils for path normalization and validation
    normalized_path = PathUtils.normalize_path(file_path)
    if not normalized_path:
        return True, "invalid_path"
        
    # Check path validity
    is_valid, reason = PathUtils.is_valid_path(normalized_path)
    if not is_valid:
        return True, reason
        
    # Get file info
    file_info = PathUtils.get_file_info(normalized_path)
    if not file_info:
        return True, "file_info_error"
        
    # Handle device files - allow them but mark for special handling
    if file_info["is_char_device"] or file_info["is_block_device"]:
        return False, "device_file"
        
    # Handle special files
    if file_info["is_fifo"] or file_info["is_socket"]:
        return True, "special_file"
        
    # Handle symlinks
    if file_info["is_link"]:
        target = os.path.realpath(normalized_path)
        if not os.path.exists(target):
            return True, "broken_symlink"
            
    # Check if file is readable
    is_readable, reason = PathUtils.is_path_readable(normalized_path)
    if not is_readable:
        return True, reason
        
    # Check file size
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    MIN_FILE_SIZE = 10  # 10 bytes
    if file_info["size"] > MAX_FILE_SIZE:
        return True, "file_too_large"
    if file_info["size"] < MIN_FILE_SIZE:
        return True, "file_too_small"
        
    # Check if binary (only for regular files)
    if file_info["is_file"]:
        BINARY_CHECK_SIZE = 1024
        try:
            with open(normalized_path, 'rb') as f:
                chunk = f.read(BINARY_CHECK_SIZE)
                if b'\x00' in chunk:
                    return True, "binary_file"
        except Exception:
            return True, "read_error"
            
    return False, "allowed"


class SmartExclusions:
    """Intelligent file exclusion system for optimized scanning."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("credfinder.smartexclusions")
        
        # Load configuration
        self.smart_exclusions = config.get("smart_exclusions", {})
        self.enable_smart_exclusions = self.smart_exclusions.get("enabled", True)
        self.enable_path_heuristics = self.smart_exclusions.get("path_heuristics", True)
        self.enable_content_classification = self.smart_exclusions.get("content_classification", True)
        
        # Load exclusion patterns
        self.excluded_dirs = set(self.smart_exclusions.get("excluded_dirs", []))
        self.excluded_file_patterns = self.smart_exclusions.get("excluded_file_patterns", [])
        self.excluded_path_patterns = self.smart_exclusions.get("excluded_path_patterns", [])
        self.irrelevant_extensions = set(self.smart_exclusions.get("irrelevant_extensions", []))
        self.irrelevant_dir_patterns = self.smart_exclusions.get("irrelevant_dir_patterns", [])
        
        # File size limits
        self.max_file_size_mb = self.smart_exclusions.get("max_file_size_mb", 50)
        self.min_file_size_bytes = self.smart_exclusions.get("min_file_size_bytes", 10)
        
        # Quick scan settings
        self.quick_scan_bytes = self.smart_exclusions.get("quick_scan_bytes", 1024)
        
        # Initialize statistics
        self.exclusion_stats = {
            "performance_gains": {
                "pattern_exclusions": 0,
                "size_exclusions": 0,
                "binary_exclusions": 0,
                "heuristic_exclusions": 0
            }
        }

    def should_exclude_file(self, file_path: str, module_name: str = None) -> Tuple[bool, str]:
        """
        Check if a file should be excluded from scanning.
        
        Args:
            file_path: Path to check
            module_name: Optional module name for module-specific rules
            
        Returns:
            Tuple of (should_exclude, reason)
        """
        if not self.enable_smart_exclusions:
            return False, "smart_exclusions_disabled"
            
        # Use PathUtils for path handling
        normalized_path = PathUtils.normalize_path(file_path)
        if not normalized_path:
            return True, "invalid_path"
            
        # Basic exclusions
        excluded, reason = self._check_basic_exclusions(normalized_path)
        if excluded:
            return True, reason
            
        # Get file info
        file_info = PathUtils.get_file_info(normalized_path)
        if not file_info:
            return True, "file_info_error"
            
        # Size checks
        if file_info["size"] > (self.max_file_size_mb * 1024 * 1024):
            self.exclusion_stats["performance_gains"]["size_exclusions"] += 1
            return True, f"file_too_large:{file_info['size']}"
            
        if file_info["size"] < self.min_file_size_bytes:
            self.exclusion_stats["performance_gains"]["size_exclusions"] += 1
            return True, f"file_too_small:{file_info['size']}"
            
        # File type checks
        excluded, reason = self._check_file_type(normalized_path)
        if excluded:
            return True, reason
            
        # Path heuristics
        if self.enable_path_heuristics:
            excluded, reason = self._check_path_heuristics(normalized_path)
            if excluded:
                return True, reason
                
        # Content classification
        if self.enable_content_classification:
            excluded, reason = self._check_content_classification(normalized_path)
            if excluded:
                return True, reason
                
        # High-value paths override
        if self._is_high_value_path(normalized_path):
            return False, "high_value_path_override"
            
        return False, "passed_all_checks"
        
    def _check_basic_exclusions(self, file_path: str) -> Tuple[bool, str]:
        """Check basic exclusion rules from configuration."""
        path_parts = Path(file_path).parts
        
        # Directory exclusions
        for part in path_parts:
            if part in self.excluded_dirs:
                self.exclusion_stats["performance_gains"]["pattern_exclusions"] += 1
                return True, f"excluded_directory:{part}"
                
        # File pattern exclusions
        filename = os.path.basename(file_path)
        for pattern in self.excluded_file_patterns:
            if self._matches_pattern(filename, pattern):
                self.exclusion_stats["performance_gains"]["pattern_exclusions"] += 1
                return True, f"excluded_file_pattern:{pattern}"
                
        # Path pattern exclusions
        for pattern in self.excluded_path_patterns:
            if self._matches_pattern(file_path, pattern):
                self.exclusion_stats["performance_gains"]["pattern_exclusions"] += 1
                return True, f"excluded_path_pattern:{pattern}"
                
        return False, ""
        
    def _check_file_type(self, file_path: str) -> Tuple[bool, str]:
        """Check file type and extension."""
        # Check file extension
        _, ext = os.path.splitext(file_path.lower())
        if ext in self.irrelevant_extensions:
            self.exclusion_stats["performance_gains"]["pattern_exclusions"] += 1
            return True, f"irrelevant_extension:{ext}"
            
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            # Exclude binary media types
            if mime_type.startswith(('image/', 'audio/', 'video/', 'application/octet-stream')):
                self.exclusion_stats["performance_gains"]["binary_exclusions"] += 1
                return True, f"binary_mime_type:{mime_type}"
                
        return False, ""
        
    def _check_path_heuristics(self, file_path: str) -> Tuple[bool, str]:
        """Apply path-based heuristics for exclusion."""
        normalized_path = os.path.normpath(file_path).lower()
        
        # Check against irrelevant directory patterns
        for pattern in self.irrelevant_dir_patterns:
            if self._matches_pattern(normalized_path, pattern):
                self.exclusion_stats["performance_gains"]["heuristic_exclusions"] += 1
                return True, f"irrelevant_dir_pattern:{pattern}"
                
        # Check path depth
        path_depth = len(Path(file_path).parts)
        if path_depth > 10:  # Arbitrary deep nesting threshold
            self.exclusion_stats["performance_gains"]["heuristic_exclusions"] += 1
            return True, f"deep_nesting:{path_depth}"
            
        return False, ""
        
    def _check_content_classification(self, file_path: str) -> Tuple[bool, str]:
        """Perform quick content-based classification."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(self.quick_scan_bytes)
                
                # Check for binary content
                if b'\x00' in chunk:
                    self.exclusion_stats["performance_gains"]["binary_exclusions"] += 1
                    return True, "binary_content"
                    
        except Exception as e:
            return True, f"content_read_error:{str(e)}"
            
        return False, ""
        
    def _is_high_value_path(self, file_path: str) -> bool:
        """Check if path matches high-value patterns that should never be excluded."""
        high_value_patterns = [
            "*password*", "*secret*", "*key*", "*token*", "*credential*",
            "*.env", "*.env.*", "*config*", "*.yml", "*.yaml",
            "*auth*", "*login*", "*oauth*", "*.pem", "*.key",
            "*.cert", "*.crt", "*.p12", "*.pfx"
        ]
        
        normalized_path = file_path.lower()
        return any(fnmatch.fnmatch(normalized_path, pattern.lower()) for pattern in high_value_patterns)
        
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Safe pattern matching that handles Unicode and special characters."""
        try:
            return fnmatch.fnmatch(path.lower(), pattern.lower())
        except Exception:
            return False
            
    def get_exclusion_statistics(self) -> Dict[str, Any]:
        """Get statistics about exclusions performed by the smart exclusion system."""
        total_exclusions = sum(self.exclusion_stats["performance_gains"].values())
        
        return {
            "total_exclusions": total_exclusions,
            "exclusion_breakdown": {
                "pattern_based": self.exclusion_stats["performance_gains"]["pattern_exclusions"],
                "size_based": self.exclusion_stats["performance_gains"]["size_exclusions"],
                "binary_content": self.exclusion_stats["performance_gains"]["binary_exclusions"],
                "heuristic": self.exclusion_stats["performance_gains"]["heuristic_exclusions"]
            },
            "enabled_features": {
                "smart_exclusions": self.enable_smart_exclusions,
                "path_heuristics": self.enable_path_heuristics,
                "content_classification": self.enable_content_classification
            }
        } 