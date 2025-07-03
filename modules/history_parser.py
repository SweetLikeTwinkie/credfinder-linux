#!/usr/bin/env python3
"""
Shell History Parser Module
This module scans shell history files for credentials and secrets that users
may have accidentally included in command line arguments or environment variables.

Key Features:
- Supports multiple shell history formats (bash, zsh, sh, generic)
- Configurable file size limits for safety
- Pattern-based credential detection
- Risk assessment based on credential types
- Proper encoding handling for various file formats

Contributors: This module is safe and doesn't require elevated privileges.
History files often contain sensitive information in plain text, making this
a high-value module for credential discovery. The risk assessment helps
prioritize findings for investigation.
"""

import os
import re
from typing import List, Dict, Any
from modules.utils.logger import get_logger

class HistoryParser:
    """Parses shell history files for credentials and secrets."""
    
    def __init__(self, config):
        """
        Initialize the HistoryParser with configuration.
        
        Args:
            config: Configuration dictionary containing scan paths and settings
        """
        self.config = config
        self.patterns = config.get("patterns", {})
        self.logger = get_logger("credfinder.historyparser")
        
        # Load history-specific settings from config
        self.history_settings = config.get("module_settings", {}).get("history", {})
        
        # Get history file paths from config (prefer config over hardcoded)
        self.history_paths = []
        config_paths = config.get("scan_paths", {}).get("history_files", [])
        if config_paths:
            # Use configured paths and expand them
            self.history_paths = [os.path.expanduser(path) for path in config_paths]
        else:
            # Fallback to default paths if not configured
            self.history_paths = [
                os.path.expanduser("~/.bash_history"),
                os.path.expanduser("~/.zsh_history"),
                os.path.expanduser("~/.sh_history"),
                os.path.expanduser("~/.history")
            ]
        
        # Load other settings with fallbacks
        self.max_file_size = self.history_settings.get("max_file_size_bytes", 52428800)  # 50MB
        self.context_size = self.history_settings.get("context_size", 30)
        self.risk_patterns = self.history_settings.get("risk_patterns", {
            "critical": ["aws_keys", "api_tokens", "jwt_tokens"],
            "medium": ["passwords"],
            "low": []
        })

    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse all configured history files and return findings.
        
        This method iterates through all configured history file paths,
        reads their contents safely, and searches for credential patterns.
        It includes proper error handling for various file issues.
        
        Returns:
            List of findings with file info, line numbers, and pattern matches
        """
        findings = []
        
        for path in self.history_paths:
            if os.path.exists(path):
                try:
                    # Check file size before processing to prevent memory issues
                    file_size = os.path.getsize(path)
                    
                    if file_size > self.max_file_size:
                        self.logger.warning(f"History file too large ({file_size} bytes), skipping: {path}")
                        continue
                    
                    # Read the history file with proper encoding handling
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    # Process each line for credential patterns
                    for idx, line in enumerate(lines):
                        line = line.strip()
                        # Skip comments (starting with #) and empty lines
                        if not line or line.startswith('#'):
                            continue
                            
                        pattern_matches = self._check_patterns(line)
                        # Filter out obvious false positives
                        filtered_matches = [m for m in pattern_matches if not self._is_false_positive_command(line, m)]
                        
                        if filtered_matches:
                            findings.append({
                                "file": path,
                                "line_number": idx + 1,
                                "command": line,
                                "pattern_matches": filtered_matches,
                                "risk_level": self._assess_risk_level(filtered_matches)
                            })
                            
                except PermissionError:
                    self.logger.debug(f"Access denied to history file: {path}")
                    continue
                except FileNotFoundError:
                    self.logger.debug(f"History file not found: {path}")
                    continue
                except UnicodeDecodeError:
                    self.logger.debug(f"Unicode decode error in history file: {path}")
                    # Try with different encoding
                    try:
                        with open(path, 'r', encoding='latin-1', errors='ignore') as f:
                            lines = f.readlines()
                        for idx, line in enumerate(lines):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            pattern_matches = self._check_patterns(line)
                            # Filter out obvious false positives
                            filtered_matches = [m for m in pattern_matches if not self._is_false_positive_command(line, m)]
                            
                            if filtered_matches:
                                findings.append({
                                    "file": path,
                                    "line_number": idx + 1,
                                    "command": line,
                                    "pattern_matches": filtered_matches,
                                    "risk_level": self._assess_risk_level(filtered_matches)
                                })
                    except Exception as e:
                        self.logger.warning(f"Failed to read history file {path} with fallback encoding: {e}")
                        continue
                except Exception as e:
                    self.logger.warning(f"Error reading history file {path}: {e}")
                    continue
                    
        self.logger.info(f"History scan completed: {len(findings)} findings from {len(self.history_paths)} files")
        return findings

    def _check_patterns(self, content: str) -> List[Dict[str, Any]]:
        """
        Check command line content against configured credential patterns.
        
        This method applies all configured regex patterns to detect various
        types of credentials that might appear in shell commands.
        
        Args:
            content: Single command line to analyze
            
        Returns:
            List of pattern matches with type and context information
        """
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
                            "full_match": match  # Keep original for debugging
                        })
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Error processing pattern '{pattern}': {e}")
                    continue
        return matches

    def _extract_match_value(self, match) -> str:
        """
        Extract meaningful value from regex match result.
        
        Regex patterns can return various formats depending on whether they use
        capturing groups. This method normalizes the output to get the actual value.
        
        Args:
            match: Result from re.findall() - could be string, tuple, or list
            
        Returns:
            String representation of the matched credential
        """
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
                # Handle list of matches (rare case)
                return str(match[0]) if match else ""
            else:
                return str(match)
        except Exception as e:
            self.logger.debug(f"Error extracting match value: {e}")
            return str(match) if match else ""

    def _get_context(self, content: str, match_value: str) -> str:
        """
        Get context around a match with improved error handling.
        
        For command lines, we usually want to see the full command since they're
        typically single lines. This helps understand how the credential was used.
        
        Args:
            content: Full command line content
            match_value: The matched credential string
            
        Returns:
            Context string (often the full command for history entries)
        """
        try:
            if not match_value or not content:
                return ""
            
            # For command line context, if the line is short enough, return it all
            max_full_length = self.context_size * 4
            if len(content) <= max_full_length:
                return content.strip()
            
            # For longer commands, find the match and provide surrounding context
            match_pos = content.find(match_value)
            if match_pos == -1:
                # Try case-insensitive search as fallback
                match_pos = content.lower().find(match_value.lower())
                if match_pos == -1:
                    return content.strip()
            
            # Calculate context boundaries
            start = max(0, match_pos - self.context_size)
            end = min(len(content), match_pos + len(match_value) + self.context_size)
            
            context = content[start:end].strip()
            return context
            
        except Exception as e:
            self.logger.debug(f"Error getting context for match '{match_value}': {e}")
            return content.strip()
    
    def _assess_risk_level(self, pattern_matches: List[Dict[str, Any]]) -> str:
        """
        Assess the risk level based on the types of patterns matched.
        
        Different types of credentials pose different levels of risk.
        This assessment helps analysts prioritize their investigation efforts.
        
        Args:
            pattern_matches: List of pattern match dictionaries
            
        Returns:
            Risk level string: "critical", "medium", or "low"
        """
        if not pattern_matches:
            return "low"
        
        # Check each match against configured risk categories
        for match in pattern_matches:
            pattern_type = match.get('type', '')
            
            # Check critical patterns first (highest priority)
            if pattern_type in self.risk_patterns.get('critical', []):
                return "critical"
            
            # Check medium risk patterns
            elif pattern_type in self.risk_patterns.get('medium', []):
                # Don't immediately return - there might be critical patterns too
                continue
        
        # If we found medium risk patterns but no critical ones
        for match in pattern_matches:
            pattern_type = match.get('type', '')
            if pattern_type in self.risk_patterns.get('medium', []):
                return "medium"
        
        # Default to low risk for any other patterns
        return "low"
    
    def _is_false_positive_command(self, command: str, match: Dict[str, Any]) -> bool:
        """
        Check if a command/match combination is likely a false positive.
        
        Args:
            command: The full command line
            match: The pattern match dictionary
            
        Returns:
            True if this is likely a false positive
        """
        command_lower = command.lower()
        match_text = match.get('match', '').lower()
        pattern_type = match.get('type', '')
        
        # Filter out common false positives
        false_positive_indicators = [
            # Package installations and testing
            'install --without test',
            'bundle install',
            'npm test',
            'go install',
            'pip install',
            'apt install',
            'yum install',
            
            # URLs and examples
            'example.com',
            'localhost',
            '127.0.0.1',
            'github.com/',
            'latest',
            
            # Common test patterns
            'testing',
            'test_',
            '_test',
            '.test',
            'example',
            'demo',
            'sample',
            
            # Backslash continuations (shell syntax)
            '\\\\',
            
            # Version numbers and releases  
            'release',
            'ubuntu',
            'latest',
            'v7.2',
            '+ubuntu',
        ]
        
        # Check if command contains any false positive indicators
        for indicator in false_positive_indicators:
            if indicator in command_lower:
                return True
        
        # Pattern-specific false positive checks
        if pattern_type == 'false_positive_filters':
            return True
            
        # Check for overly common patterns that are likely noise
        if match_text in ['\\\\', 'test', 'example', 'latest']:
            return True
            
        # Filter out very short matches (likely fragments)
        if len(match_text.strip()) < 4:
            return True
            
        return False 