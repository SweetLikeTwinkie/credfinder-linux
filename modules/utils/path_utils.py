"""Path utilities for consistent path handling across modules."""
import os
import stat
from pathlib import Path
from typing import Tuple, Optional

class PathUtils:
    @staticmethod
    def normalize_path(path: str) -> str:
        """
        Normalize a file path by expanding user directory and resolving symlinks.
        Handles Unicode paths correctly.
        
        Args:
            path: Raw file path
            
        Returns:
            Normalized absolute path
        """
        try:
            # Handle empty or None paths
            if not path:
                return ""
                
            # Expand user directory and environment variables
            expanded = os.path.expanduser(os.path.expandvars(path))
            
            # Convert to absolute path and resolve symlinks
            resolved = str(Path(expanded).resolve())
            
            return resolved
            
        except Exception:
            return path

    @staticmethod
    def is_valid_path(path: str) -> Tuple[bool, str]:
        """
        Check if a path is valid and safe to access.
        Handles Unicode paths, special characters, and device files.
        
        Args:
            path: Path to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # Handle empty paths
            if not path:
                return False, "empty_path"
                
            # Normalize path
            normalized = PathUtils.normalize_path(path)
            if not normalized:
                return False, "invalid_path"
                
            # Check for path traversal
            if ".." in normalized:
                return False, "path_traversal"
                
            # Check path length (use Windows max as upper bound)
            if len(normalized) > 32767:
                return False, "path_too_long"
                
            # Check if path exists
            if not os.path.exists(normalized):
                return False, "not_found"
                
            # Get file stats
            try:
                st = os.stat(normalized)
            except Exception:
                return False, "stat_failed"
                
            # Handle device files
            if stat.S_ISCHR(st.st_mode):
                return True, "character_device"
            if stat.S_ISBLK(st.st_mode):
                return True, "block_device"
                
            # Handle other special files
            if stat.S_ISFIFO(st.st_mode):
                return True, "named_pipe"
            if stat.S_ISSOCK(st.st_mode):
                return True, "socket"
                
            # Handle symlinks
            if os.path.islink(normalized):
                target = os.path.realpath(normalized)
                if not os.path.exists(target):
                    return False, "broken_symlink"
                return True, "symlink"
                
            # Regular files and directories are valid
            if os.path.isfile(normalized):
                return True, "regular_file"
            if os.path.isdir(normalized):
                return True, "directory"
                
            return False, "unknown_file_type"
            
        except Exception as e:
            return False, f"validation_error:{str(e)}"

    @staticmethod
    def get_file_info(path: str) -> Optional[dict]:
        """
        Get detailed information about a file.
        
        Args:
            path: Path to analyze
            
        Returns:
            Dictionary with file information or None if error
        """
        try:
            normalized = PathUtils.normalize_path(path)
            if not normalized:
                return None
                
            st = os.stat(normalized)
            
            return {
                "path": normalized,
                "size": st.st_size,
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "atime": st.st_atime,
                "mtime": st.st_mtime,
                "ctime": st.st_ctime,
                "is_file": os.path.isfile(normalized),
                "is_dir": os.path.isdir(normalized),
                "is_link": os.path.islink(normalized),
                "is_char_device": stat.S_ISCHR(st.st_mode),
                "is_block_device": stat.S_ISBLK(st.st_mode),
                "is_fifo": stat.S_ISFIFO(st.st_mode),
                "is_socket": stat.S_ISSOCK(st.st_mode)
            }
            
        except Exception:
            return None

    @staticmethod
    def is_path_readable(path: str) -> Tuple[bool, str]:
        """
        Check if a path is readable by the current process.
        
        Args:
            path: Path to check
            
        Returns:
            Tuple of (is_readable, reason)
        """
        try:
            normalized = PathUtils.normalize_path(path)
            if not normalized:
                return False, "invalid_path"
                
            # Check basic access
            if not os.access(normalized, os.R_OK):
                return False, "permission_denied"
                
            # Try opening file to verify
            if os.path.isfile(normalized):
                try:
                    with open(normalized, 'rb') as f:
                        f.read(1)
                    return True, "readable"
                except Exception as e:
                    return False, f"read_error:{str(e)}"
                    
            return True, "readable"
            
        except Exception as e:
            return False, f"access_error:{str(e)}" 