#!/usr/bin/env python3
"""
Shell History Parser Module
Scans shell history files for credentials and secrets
"""

import os
import re
from typing import List, Dict, Any

class HistoryParser:
    def __init__(self, config):
        self.config = config
        self.history_paths = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.sh_history"),
            os.path.expanduser("~/.history")
        ]
        self.patterns = config.get("patterns", {})

    def parse(self) -> List[Dict[str, Any]]:
        findings = []
        for path in self.history_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', errors='ignore') as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            continue
                        pattern_matches = self._check_patterns(line)
                        if pattern_matches:
                            findings.append({
                                "file": path,
                                "line_number": idx + 1,
                                "command": line,
                                "pattern_matches": pattern_matches
                            })
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        return findings

    def _check_patterns(self, content: str) -> List[Dict[str, Any]]:
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

    def _get_context(self, content: str, match: str, context_size: int = 30) -> str:
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