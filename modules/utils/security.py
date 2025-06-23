#!/usr/bin/env python3
"""
Security utilities for safe file operations and path validation
"""

import os
import stat
import shutil
from pathlib import Path
from typing import List, Optional, Union


class SecurityError(Exception):
    """Exception for security issues"""
    pass


class FileSecurityManager:
    """Security manager for file operations"""
    
    def __init__(self, config: dict):
        self.config = config
        security_config = config.get("security", {})
        
        self.max_file_size = security_config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.min_free_space = security_config.get("min_free_space", 100 * 1024 * 1024)  # 100MB
        self.allowed_output_dirs = security_config.get("allowed_output_dirs", ["./reports"])
        self.forbidden_paths = security_config.get("forbidden_paths", ["/dev", "/proc/*/mem"])
        
    def validate_path(self, path: Union[str, Path], check_exists: bool = True) -> Path:
        """Validate path for security"""
        path = Path(path).resolve()
        
        # Check for forbidden paths
        path_str = str(path)
        for forbidden in self.forbidden_paths:
            if path_str.startswith(forbidden.replace("*", "")):
                raise SecurityError(f"Access to forbidden path: {path}")
        
        # Check existence if required
        if check_exists and not path.exists():
            raise SecurityError(f"Path does not exist: {path}")
        
        # Check that this is not a symlink to critical system files
        if path.is_symlink():
            target = path.readlink()
            if str(target).startswith(("/dev", "/proc", "/sys")):
                raise SecurityError(f"Symbolic link points to system path: {target}")
        
        return path
    
    def validate_output_directory(self, output_dir: Union[str, Path]) -> Path:
        """Validate output directory"""
        output_path = Path(output_dir).resolve()
        
        # Check that the directory is in the allowed list
        allowed = False
        for allowed_dir in self.allowed_output_dirs:
            allowed_path = Path(allowed_dir).expanduser().resolve()
            try:
                output_path.relative_to(allowed_path)
                allowed = True
                break
            except ValueError:
                continue
        
        if not allowed:
            raise SecurityError(f"Output directory not in allowed list: {output_path}")
        
        # Check that this is not a symlink
        if output_path.exists() and output_path.is_symlink():
            raise SecurityError(f"Output directory is a symbolic link: {output_path}")
        
        # Check that this is not a device
        if output_path.exists() and not output_path.is_dir():
            raise SecurityError(f"Output path is not a directory: {output_path}")
        
        return output_path
    
    def check_file_size(self, file_path: Union[str, Path]) -> bool:
        """Check file size"""
        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                raise SecurityError(f"File too large: {size} bytes (max: {self.max_file_size})")
            return True
        except OSError as e:
            raise SecurityError(f"Cannot check file size: {e}")
    
    def check_free_space(self, path: Union[str, Path]) -> bool:
        """Check free disk space"""
        try:
            statvfs = os.statvfs(path)
            free_space = statvfs.f_frsize * statvfs.f_bavail
            if free_space < self.min_free_space:
                raise SecurityError(f"Insufficient disk space: {free_space} bytes available")
            return True
        except OSError as e:
            raise SecurityError(f"Cannot check disk space: {e}")
    
    def safe_create_directory(self, dir_path: Union[str, Path], mode: int = 0o750) -> Path:
        """Safely create a directory"""
        dir_path = self.validate_output_directory(dir_path)
        
        if not dir_path.exists():
            # Check free space
            parent = dir_path.parent
            self.check_free_space(parent)
            
            # Create directory with secure permissions
            dir_path.mkdir(parents=True, exist_ok=True, mode=mode)
        
        # Check write permissions
        if not os.access(dir_path, os.W_OK):
            raise SecurityError(f"No write permission for directory: {dir_path}")
        
        return dir_path
    
    def safe_write_file(self, file_path: Union[str, Path], content: Union[str, bytes], 
                       mode: int = 0o640, atomic: bool = True) -> Path:
        """Safely write a file"""
        file_path = Path(file_path).resolve()
        
        # Validate directory
        self.validate_output_directory(file_path.parent)
        
        # Check free space
        self.check_free_space(file_path.parent)
        
        if atomic:
            # Atomic write via temporary file
            temp_path = file_path.with_suffix('.tmp')
            
            try:
                with open(temp_path, 'w' if isinstance(content, str) else 'wb', 
                         encoding='utf-8' if isinstance(content, str) else None) as f:
                    f.write(content)
                
                # Set permissions
                os.chmod(temp_path, mode)
                
                # Atomic rename
                temp_path.rename(file_path)
                
            except Exception as e:
                # Clean up temp file on error
                if temp_path.exists():
                    temp_path.unlink()
                raise SecurityError(f"Failed to write file atomically: {e}")
        else:
            # Regular write
            with open(file_path, 'w' if isinstance(content, str) else 'wb',
                     encoding='utf-8' if isinstance(content, str) else None) as f:
                f.write(content)
            
            os.chmod(file_path, mode)
        
        return file_path
    
    def safe_read_file(self, file_path: Union[str, Path], max_size: Optional[int] = None) -> Union[str, bytes]:
        """Safely read a file"""
        file_path = self.validate_path(file_path, check_exists=True)
        
        # Check file size
        check_size = max_size or self.max_file_size
        size = os.path.getsize(file_path)
        if size > check_size:
            raise SecurityError(f"File too large to read: {size} bytes")
        
        # Check read permissions
        if not os.access(file_path, os.R_OK):
            raise SecurityError(f"No read permission for file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try as binary file
            with open(file_path, 'rb') as f:
                return f.read()
    
    def is_safe_symlink(self, link_path: Union[str, Path]) -> bool:
        """Check symlink safety"""
        link_path = Path(link_path)
        
        if not link_path.is_symlink():
            return True
        
        try:
            target = link_path.readlink()
            target_resolved = link_path.resolve()
            
            # Check that the symlink does not point to system paths
            target_str = str(target_resolved)
            dangerous_paths = ["/dev", "/proc", "/sys", "/boot"]
            
            for dangerous in dangerous_paths:
                if target_str.startswith(dangerous):
                    return False
            
            return True
            
        except (OSError, RuntimeError):
            # Broken or cyclic symlink
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize file name"""
        # Remove dangerous characters
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Limit length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        # Remove leading and trailing spaces
        sanitized = sanitized.strip()
        
        # Ensure name is not empty
        if not sanitized:
            sanitized = "unnamed_file"
        
        return sanitized


class ProcessSecurityManager:
    """Security manager for process operations"""
    
    def __init__(self, config: dict):
        self.config = config
    
    def check_privileges(self) -> dict:
        """Check current privileges"""
        return {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "euid": os.geteuid(),
            "egid": os.getegid(),
            "is_root": os.geteuid() == 0,
            "groups": os.getgroups() if hasattr(os, 'getgroups') else []
        }
    
    def require_privileges(self, operation: str) -> bool:
        """Check required privileges for operation"""
        privileges = self.check_privileges()
        
        # Operations requiring root
        root_operations = ["memory_scan", "keyring_system", "proc_access"]
        
        if operation in root_operations and not privileges["is_root"]:
            raise SecurityError(f"Operation '{operation}' requires root privileges")
        
        return True
    
    def is_process_accessible(self, pid: int) -> bool:
        """Check process accessibility"""
        try:
            # Check if process exists
            os.kill(pid, 0)
            
            # Check access rights to /proc/pid
            proc_path = f"/proc/{pid}"
            return os.access(proc_path, os.R_OK)
            
        except (OSError, ProcessLookupError):
            return False 