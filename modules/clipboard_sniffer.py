#!/usr/bin/env python3
"""
Clipboard Sniffer Module (Optional)
Monitors clipboard for sensitive data
"""

import os
import time
import threading
import subprocess
from typing import List, Dict, Any, Callable
from datetime import datetime

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False

class ClipboardSniffer:
    def __init__(self, config):
        self.config = config
        self.is_running = False
        self.callback = None
        self.last_content = ""
        self.monitor_thread = None
        self.patterns = config.get("patterns", {})
        
    def start(self, callback: Callable = None, interval: float = 1.0) -> bool:
        """Start clipboard monitoring"""
        if not PYPERCLIP_AVAILABLE:
            return False
            
        if self.is_running:
            return False
            
        self.callback = callback
        self.is_running = True
        
        # Start monitoring in separate thread
        self.monitor_thread = threading.Thread(target=self._monitor_clipboard, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return True
    
    def stop(self) -> Dict[str, Any]:
        """Stop clipboard monitoring"""
        if not self.is_running:
            return {"error": "Clipboard sniffer not running"}
            
        self.is_running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
            
        return {"status": "stopped"}
    
    def _monitor_clipboard(self, interval: float):
        """Monitor clipboard content in a loop"""
        while self.is_running:
            try:
                current_content = pyperclip.paste()
                
                # Check if content has changed
                if current_content != self.last_content and current_content.strip():
                    # Analyze new content
                    analysis = self._analyze_clipboard_content(current_content)
                    
                    if analysis["patterns"]:
                        if self.callback:
                            self.callback({
                                "type": "clipboard_content",
                                "content": current_content,
                                "patterns": analysis["patterns"],
                                "timestamp": datetime.now().isoformat()
                            })
                    
                    self.last_content = current_content
                    
            except Exception as e:
                # Handle clipboard access errors
                pass
                
            time.sleep(interval)
    
    def _analyze_clipboard_content(self, content: str) -> Dict[str, Any]:
        """Analyze clipboard content for sensitive data"""
        patterns = []
        
        # Check for pattern matches
        for pattern_type, pattern_list in self.patterns.items():
            for pattern in pattern_list:
                try:
                    import re
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        patterns.append({
                            "type": pattern_type,
                            "pattern": pattern,
                            "match": match if isinstance(match, str) else match[0] if match else "",
                            "context": self._get_context(content, match)
                        })
                except re.error:
                    continue
        
        # Check for common sensitive data patterns
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
            (r'https?://[^\s]+', 'url'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'ip_address'),
            (r'\b[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]{8,}\b', 'potential_password'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'sk_[a-zA-Z0-9]{24}', 'stripe_secret_key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'github_token'),
            (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'jwt_token')
        ]
        
        for pattern, pattern_type in sensitive_patterns:
            try:
                import re
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    patterns.append({
                        "type": pattern_type,
                        "pattern": pattern,
                        "match": match,
                        "context": self._get_context(content, match)
                    })
            except re.error:
                continue
        
        return {
            "patterns": patterns,
            "content_length": len(content),
            "has_sensitive_data": len(patterns) > 0
        }
    
    def _get_context(self, content: str, match: str, context_size: int = 50) -> str:
        """Get context around a match"""
        try:
            start = content.find(match)
            if start != -1:
                start = max(0, start - context_size)
                end = min(len(content), start + len(match) + context_size)
                return content[start:end]
        except:
            pass
        return ""
    
    def get_current_content(self) -> str:
        """Get current clipboard content"""
        if not PYPERCLIP_AVAILABLE:
            return ""
            
        try:
            return pyperclip.paste()
        except:
            return ""
    
    def set_content(self, content: str) -> bool:
        """Set clipboard content"""
        if not PYPERCLIP_AVAILABLE:
            return False
            
        try:
            pyperclip.copy(content)
            return True
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if clipboard sniffer is available on this system"""
        if not PYPERCLIP_AVAILABLE:
            return False
            
        # Check for clipboard tools
        clipboard_tools = ['xclip', 'xsel', 'wl-copy']
        for tool in clipboard_tools:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        return False
    
    def get_clipboard_tool(self) -> str:
        """Get available clipboard tool"""
        clipboard_tools = ['xclip', 'xsel', 'wl-copy']
        for tool in clipboard_tools:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return tool
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None 