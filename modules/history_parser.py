#!/usr/bin/env python3
"""
Shell History Parser Module
Scans shell history files for credentials and secrets
"""

import os
import re
from typing import List, Dict, Any
from modules.utils.logger import get_logger

class HistoryParser:
    """Parses shell history files for credentials and secrets."""
    def __init__(self, config):
        """Initialize the HistoryParser with the given configuration."""
        self.config = config
        self.history_paths = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.sh_history"),
            os.path.expanduser("~/.history")
        ]
        self.patterns = config.get("patterns", {})
        self.logger = get_logger("credfinder.historyparser")

    def parse(self) -> List[Dict[str, Any]]:
        """Parse all configured history files and return findings."""
        findings = []
        
        for path in self.history_paths:
            if os.path.exists(path):
                try:
                    file_size = os.path.getsize(path)
                    max_size = 50 * 1024 * 1024  # 50MB limit for history files
                    
                    if file_size > max_size:
                        self.logger.warning(f"History file too large ({file_size} bytes), skipping: {path}")
                        continue
                    
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for idx, line in enumerate(lines):
                        line = line.strip()
                        if not line or line.startswith('#'):  # Skip comments and empty lines
                            continue
                            
                        pattern_matches = self._check_patterns(line)
                        if pattern_matches:
                            findings.append({
                                "file": path,
                                "line_number": idx + 1,
                                "command": line,
                                "pattern_matches": pattern_matches,
                                "risk_level": self._assess_risk_level(pattern_matches)
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
                            if pattern_matches:
                                findings.append({
                                    "file": path,
                                    "line_number": idx + 1,
                                    "command": line,
                                    "pattern_matches": pattern_matches,
                                    "risk_level": self._assess_risk_level(pattern_matches)
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
        """Check content against configured patterns with improved handling"""
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
                            "full_match": match
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

    def _get_context(self, content: str, match_value: str, context_size: int = 30) -> str:
        """Get context around a match with improved error handling"""
        try:
            if not match_value or not content:
                return ""
            
            # For command line context, we usually want the whole command
            # since commands are typically single lines
            if len(content) <= context_size * 4:
                return content.strip()
            
            # Find the match in the content
            match_pos = content.find(match_value)
            if match_pos == -1:
                # Try case-insensitive search
                match_pos = content.lower().find(match_value.lower())
                if match_pos == -1:
                    return content.strip()
            
            # Calculate context boundaries
            start = max(0, match_pos - context_size)
            end = min(len(content), match_pos + len(match_value) + context_size)
            
            context = content[start:end].strip()
            return context
            
        except Exception as e:
            self.logger.debug(f"Error getting context for match '{match_value}': {e}")
            return content.strip()
    
    def _assess_risk_level(self, pattern_matches: List[Dict[str, Any]]) -> str:
        """Assess the risk level based on pattern matches"""
        if not pattern_matches:
            return "low"
        
        high_risk_patterns = ['aws_keys', 'api_tokens', 'jwt_tokens']
        medium_risk_patterns = ['passwords']
        
        for match in pattern_matches:
            pattern_type = match.get('type', '')
            if pattern_type in high_risk_patterns:
                return "critical"
            elif pattern_type in medium_risk_patterns:
                return "medium"
        
        return "low" 