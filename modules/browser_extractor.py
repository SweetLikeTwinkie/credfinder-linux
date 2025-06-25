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
import time
import fcntl
from pathlib import Path
from typing import List, Dict, Any, Optional
import subprocess
import sys
from modules.utils.logger import get_logger

# Import crypto libraries if available
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    # Will log in __init__ if needed

# Import secretstorage for GNOME keyring access
try:
    import secretstorage
    SECRETSTORAGE_AVAILABLE = True
except ImportError:
    SECRETSTORAGE_AVAILABLE = False


class BrowserExtractor:
    def __init__(self, config):
        self.config = config
        self.browser_paths = config.get("scan_paths", {}).get("browsers", {})
        self._chrome_key_cache = None
        self.logger = get_logger("credfinder.browserextractor")
        
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
        
        # Create a temporary copy of the database using safe copy
        temp_db_path = None
        try:
            temp_db_path = self._safe_copy_database(login_data_path)
            if not temp_db_path:
                return passwords
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Query for saved passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created, date_last_used
                FROM logins
                WHERE username_value != '' AND password_value != ''
            """)
            
            for row in cursor.fetchall():
                origin_url, username, encrypted_password, date_created, date_last_used = row
                
                # Try to decrypt password
                decrypted_password = self._attempt_chrome_decrypt(encrypted_password)
                
                # Only add if we have valid data
                if username or decrypted_password:
                    passwords.append({
                        "url": origin_url,
                        "username": username,
                        "password": decrypted_password if decrypted_password else "***ENCRYPTED***",
                        "encrypted": decrypted_password is None,
                        "decrypted": decrypted_password is not None,
                        "date_created": date_created,
                        "date_last_used": date_last_used,
                        "profile_path": profile_path
                    })
            
            conn.close()
            
        except Exception as e:
            self.logger.warning(f"Failed to extract passwords from {profile_path}: {e}")
        finally:
            if temp_db_path and os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except Exception as e:
                    self.logger.warning(f"Could not clean up temp file {temp_db_path}: {e}")
        
        return passwords
    
    def _extract_chrome_cookies(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract cookies from Chrome"""
        cookies = []
        cookies_path = os.path.join(profile_path, "Cookies")
        
        if not os.path.exists(cookies_path):
            return cookies
        
        temp_db_path = None
        try:
            temp_db_path = self._safe_copy_database(cookies_path)
            if not temp_db_path:
                return cookies
            
            conn = sqlite3.connect(temp_db_path)
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
                
                # Only add meaningful cookies
                if name and host:
                    cookies.append({
                        "host": host,
                        "name": name,
                        "value": decrypted_value if decrypted_value else "***ENCRYPTED***",
                        "encrypted": decrypted_value is None,
                        "decrypted": decrypted_value is not None,
                        "path": path,
                        "expires": expires,
                        "secure": bool(is_secure),
                        "httponly": bool(is_httponly),
                        "profile_path": profile_path
                    })
            
            conn.close()
            
        except Exception as e:
            self.logger.warning(f"Failed to extract cookies from {profile_path}: {e}")
        finally:
            if temp_db_path and os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except Exception as e:
                    self.logger.warning(f"Could not clean up temp file {temp_db_path}: {e}")
        
        return cookies
    
    def _extract_chrome_autofill(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract autofill data from Chrome"""
        autofill = []
        web_data_path = os.path.join(profile_path, "Web Data")
        
        if not os.path.exists(web_data_path):
            return autofill
        
        temp_db_path = None
        try:
            temp_db_path = self._safe_copy_database(web_data_path)
            if not temp_db_path:
                return autofill
            
            conn = sqlite3.connect(temp_db_path)
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
            self.logger.warning(f"Failed to extract autofill data from {profile_path}: {e}")
        finally:
            if temp_db_path and os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except Exception as e:
                    self.logger.warning(f"Could not clean up temp file {temp_db_path}: {e}")
        
        return autofill
    
    def _get_chrome_encryption_key(self) -> Optional[bytes]:
        """Get Chrome encryption key from system keyring or use default"""
        if self._chrome_key_cache is not None:
            return self._chrome_key_cache
            
        # Try different methods to get the key
        key = None
        
        # Method 1: Try GNOME Keyring via secretstorage
        if SECRETSTORAGE_AVAILABLE:
            try:
                bus = secretstorage.dbus_init()
                collection = secretstorage.get_default_collection(bus)
                for item in collection.get_all_items():
                    if item.get_label() == 'Chrome Safe Storage' or \
                       item.get_label() == 'Chromium Safe Storage':
                        key = item.get_secret()
                        break
            except Exception as e:
                self.logger.warning(f"Failed to get Chrome encryption key from secretstorage: {e}")
        
        # Method 2: Try using secret-tool command
        if not key:
            try:
                for app in ['chrome', 'chromium']:
                    result = subprocess.run(
                        ['secret-tool', 'lookup', 'application', app],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and result.stdout:
                        key = result.stdout.encode()
                        break
            except Exception:
                self.logger.warning("Failed to get Chrome encryption key from secret-tool.")
        
        # Method 3: Try KWallet
        if not key:
            try:
                result = subprocess.run(
                    ['kwallet-query', 'kdewallet', '--read-password', 'Chrome Safe Storage'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout:
                    key = result.stdout.strip().encode()
            except Exception:
                self.logger.warning("Failed to get Chrome encryption key from KWallet.")
        
        # Method 4: Use default password "peanuts" for basic store
        if not key:
            key = b'peanuts'
        
        # Derive the actual encryption key using PBKDF2
        if CRYPTO_AVAILABLE and key:
            # Chrome uses PBKDF2 with SHA1, 1 iteration, and salt 'saltysalt'
            derived_key = PBKDF2(key, b'saltysalt', dkLen=16, count=1)
            self._chrome_key_cache = derived_key
            return derived_key
        
        return None
    
    def _decrypt_chrome_password_v10(self, encrypted_data: bytes) -> Optional[str]:
        """Decrypt Chrome v10 encrypted password (Linux)"""
        if not CRYPTO_AVAILABLE:
            return None
            
        try:
            # Check if data is encrypted (starts with v10)
            if not encrypted_data or len(encrypted_data) < 3:
                return None
                
            if encrypted_data[:3] != b'v10':
                # Try to decode as plain text
                try:
                    return encrypted_data.decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    return None
            
            # Get encryption key
            key = self._get_chrome_encryption_key()
            if not key:
                return None
            
            # Remove 'v10' prefix
            encrypted_data = encrypted_data[3:]
            
            # Initialize AES cipher (Chrome uses AES-128-CBC)
            # IV is the first 16 bytes
            if len(encrypted_data) < 16:
                return None
                
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Remove PKCS7 padding
            padding_length = decrypted[-1]
            if padding_length > 0 and padding_length <= 16:
                decrypted = decrypted[:-padding_length]
            
            # Decode to string
            try:
                return decrypted.decode('utf-8')
            except UnicodeDecodeError:
                # Try latin-1 as fallback
                return decrypted.decode('latin-1', errors='ignore')
                
        except Exception as e:
            self.logger.warning(f"Failed to decrypt Chrome v10 password: {e}")
            return None
    
    def _attempt_chrome_decrypt(self, encrypted_data: bytes) -> Optional[str]:
        """Attempt to decrypt Chrome encrypted data"""
        if not encrypted_data:
            return None
            
        # For Linux, use v10 decryption
        if sys.platform.startswith('linux'):
            return self._decrypt_chrome_password_v10(encrypted_data)
        
        # For other platforms, return None (not implemented)
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
        
        # Method 1: Try using firefox_decrypt if available
        decrypted_passwords = self._try_firefox_decrypt_tool(profile_path)
        if decrypted_passwords:
            return decrypted_passwords
        
        # Method 2: Extract encrypted entries (fallback)
        try:
            # Read logins.json
            with open(logins_json_path, 'r') as f:
                logins_data = json.load(f)
            
            # Extract login entries
            for entry in logins_data.get("logins", []):
                hostname = entry.get("hostname", "")
                form_submit_url = entry.get("formSubmitURL", "")
                username_field = entry.get("usernameField", "")
                password_field = entry.get("passwordField", "")
                encrypted_username = entry.get("encryptedUsername", "")
                encrypted_password = entry.get("encryptedPassword", "")
                time_created = entry.get("timeCreated", 0)
                time_last_used = entry.get("timeLastUsed", 0)
                time_password_changed = entry.get("timePasswordChanged", 0)
                
                # For now, we can't decrypt without NSS libraries
                # But we can show the structure and encrypted data
                passwords.append({
                    "url": hostname,
                    "form_submit_url": form_submit_url,
                    "username": "***ENCRYPTED***",
                    "password": "***ENCRYPTED***",
                    "encrypted": True,
                    "decrypted": False,
                    "username_field": username_field,
                    "password_field": password_field,
                    "time_created": time_created,
                    "time_last_used": time_last_used,
                    "time_password_changed": time_password_changed,
                    "profile_path": profile_path,
                    "note": "Firefox passwords require NSS libraries or firefox_decrypt tool to decrypt"
                })
        
        except Exception as e:
            self.logger.warning(f"Failed to extract Firefox passwords from {profile_path}: {e}")
        
        return passwords
    
    def _try_firefox_decrypt_tool(self, profile_path: str) -> List[Dict[str, Any]]:
        """Try to use firefox_decrypt tool if available"""
        passwords = []
        
        try:
            # Validate profile path to prevent path traversal
            if not self._validate_path(profile_path):
                self.logger.warning(f"Invalid profile path: {profile_path}")
                return passwords
            
            # Check if firefox_decrypt is available
            result = subprocess.run(
                ['which', 'firefox_decrypt'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                # Tool not available
                self.logger.debug("firefox_decrypt tool not found")
                return passwords
            
            # Run firefox_decrypt on the profile with non-interactive mode
            result = subprocess.run(
                ['firefox_decrypt', '--no-interactive', '--format', 'json', profile_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    # Parse JSON output from firefox_decrypt
                    decrypt_data = json.loads(result.stdout)
                    
                    for entry in decrypt_data:
                        if isinstance(entry, dict):
                            passwords.append({
                                "url": entry.get("url", "Unknown"),
                                "username": entry.get("username", ""),
                                "password": entry.get("password", ""),
                                "encrypted": False,
                                "decrypted": True,
                                "profile_path": profile_path,
                                "source": "firefox_decrypt_tool",
                                "time_created": entry.get("time_created", 0),
                                "time_last_used": entry.get("time_last_used", 0)
                            })
                            
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse firefox_decrypt JSON output: {e}")
                    # Try to parse as plain text output
                    for line in result.stdout.strip().split('\n'):
                        if ',' in line:
                            parts = line.split(',')
                            if len(parts) >= 3:
                                passwords.append({
                                    "url": parts[0].strip(),
                                    "username": parts[1].strip(),
                                    "password": parts[2].strip(),
                                    "encrypted": False,
                                    "decrypted": True,
                                    "profile_path": profile_path,
                                    "source": "firefox_decrypt_tool"
                                })
            else:
                self.logger.debug(f"firefox_decrypt failed with return code {result.returncode}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("firefox_decrypt tool timed out")
        except Exception as e:
            self.logger.warning(f"Error running firefox_decrypt tool: {e}")
        
        return passwords
    
    def _validate_path(self, path: str) -> bool:
        """Validate file path to prevent path traversal attacks"""
        try:
            # Resolve the path and check it exists
            resolved_path = Path(path).resolve()
            
            # Check if path exists and is a directory
            if not resolved_path.exists():
                return False
                
            if not resolved_path.is_dir():
                return False
            
            # Prevent path traversal - ensure path doesn't contain suspicious patterns
            path_str = str(resolved_path)
            dangerous_patterns = ['..', '~/', '/tmp/', '/dev/', '/proc/', '/sys/']
            
            for pattern in dangerous_patterns:
                if pattern in path_str:
                    return False
            
            # Check if path is within allowed directories (home directories)
            allowed_prefixes = [
                str(Path.home()),
                '/home/',
                '/Users/',  # macOS
                str(Path('/opt')),  # Some browser installations
            ]
            
            path_allowed = False
            for prefix in allowed_prefixes:
                if path_str.startswith(str(Path(prefix).resolve())):
                    path_allowed = True
                    break
            
            return path_allowed
            
        except Exception as e:
            self.logger.warning(f"Path validation error for {path}: {e}")
            return False
    
    def _safe_copy_database(self, source_path: str, max_retries: int = 3) -> Optional[str]:
        """Safely copy database file with proper validation and locking"""
        import tempfile
        import time
        import fcntl
        
        # Validate source path
        if not self._validate_database_path(source_path):
            self.logger.warning(f"Invalid database path: {source_path}")
            return None
        
        if not os.path.exists(source_path):
            self.logger.warning(f"Database file does not exist: {source_path}")
            return None
        
        # Check file size to prevent copying huge files
        try:
            file_size = os.path.getsize(source_path)
            max_size = 100 * 1024 * 1024  # 100MB limit
            if file_size > max_size:
                self.logger.warning(f"Database file too large ({file_size} bytes): {source_path}")
                return None
        except Exception as e:
            self.logger.warning(f"Cannot check size of database file {source_path}: {e}")
            return None
        
        for attempt in range(max_retries):
            temp_path = None
            source_file = None
            temp_file = None
            
            try:
                # Create secure temporary file
                with tempfile.NamedTemporaryFile(
                    prefix='browser_db_',
                    suffix='.tmp',
                    delete=False
                ) as temp_file_obj:
                    temp_path = temp_file_obj.name
                
                # Open source file with proper locking
                source_file = open(source_path, 'rb')
                
                try:
                    # Try to acquire a shared lock (non-blocking)
                    fcntl.flock(source_file.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    locked = True
                except (OSError, IOError):
                    locked = False
                    self.logger.debug(f"Could not lock database file {source_path}, attempt {attempt + 1}")
                
                # Copy the file
                temp_file = open(temp_path, 'wb')
                
                # Copy in chunks to handle large files
                chunk_size = 64 * 1024  # 64KB chunks
                while True:
                    chunk = source_file.read(chunk_size)
                    if not chunk:
                        break
                    temp_file.write(chunk)
                
                temp_file.flush()
                os.fsync(temp_file.fileno())
                
                # Close files and release locks
                if locked:
                    fcntl.flock(source_file.fileno(), fcntl.LOCK_UN)
                source_file.close()
                temp_file.close()
                
                # Verify the copy
                if os.path.getsize(temp_path) == file_size:
                    self.logger.debug(f"Successfully copied database {source_path} to {temp_path}")
                    return temp_path
                else:
                    self.logger.warning(f"Database copy size mismatch for {source_path}")
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    continue
                    
            except PermissionError:
                self.logger.warning(f"Permission denied copying database {source_path}")
                break
            except Exception as e:
                self.logger.warning(f"Error copying database {source_path} (attempt {attempt + 1}): {e}")
                
                # Clean up files
                if source_file:
                    try:
                        source_file.close()
                    except:
                        pass
                if temp_file:
                    try:
                        temp_file.close()
                    except:
                        pass
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
                
                if attempt < max_retries - 1:
                    time.sleep(0.5)  # Brief delay before retry
                continue
        
        self.logger.error(f"Failed to copy database after {max_retries} attempts: {source_path}")
        return None
    
    def _validate_database_path(self, db_path: str) -> bool:
        """Validate database file path for security"""
        try:
            resolved_path = Path(db_path).resolve()
            path_str = str(resolved_path)
            
            # Check for dangerous paths
            dangerous_paths = ['/dev/', '/proc/', '/sys/', '/tmp/']
            for dangerous in dangerous_paths:
                if path_str.startswith(dangerous):
                    return False
            
            # Must be a regular file
            if resolved_path.exists() and not resolved_path.is_file():
                return False
            
            # Check file extension
            allowed_extensions = ['.db', '.sqlite', '.sqlite3']
            if not any(path_str.endswith(ext) for ext in allowed_extensions):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _extract_firefox_cookies(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract cookies from Firefox"""
        cookies = []
        cookies_sqlite_path = os.path.join(profile_path, "cookies.sqlite")
        
        if not os.path.exists(cookies_sqlite_path):
            return cookies
        
        temp_db_path = None
        try:
            temp_db_path = self._safe_copy_database(cookies_sqlite_path)
            if not temp_db_path:
                return cookies
            
            conn = sqlite3.connect(temp_db_path)
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
            self.logger.warning(f"Failed to extract Firefox cookies from {profile_path}: {e}")
        finally:
            if temp_db_path and os.path.exists(temp_db_path):
                try:
                    os.unlink(temp_db_path)
                except Exception as e:
                    self.logger.warning(f"Could not clean up temp file {temp_db_path}: {e}")
        
        return cookies 