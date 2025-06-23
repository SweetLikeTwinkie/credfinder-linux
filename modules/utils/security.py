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
    """Исключение для проблем безопасности"""
    pass


class FileSecurityManager:
    """Менеджер безопасности для файловых операций"""
    
    def __init__(self, config: dict):
        self.config = config
        security_config = config.get("security", {})
        
        self.max_file_size = security_config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.min_free_space = security_config.get("min_free_space", 100 * 1024 * 1024)  # 100MB
        self.allowed_output_dirs = security_config.get("allowed_output_dirs", ["./reports"])
        self.forbidden_paths = security_config.get("forbidden_paths", ["/dev", "/proc/*/mem"])
        
    def validate_path(self, path: Union[str, Path], check_exists: bool = True) -> Path:
        """Валидация пути на безопасность"""
        path = Path(path).resolve()
        
        # Проверяем на запрещенные пути
        path_str = str(path)
        for forbidden in self.forbidden_paths:
            if path_str.startswith(forbidden.replace("*", "")):
                raise SecurityError(f"Access to forbidden path: {path}")
        
        # Проверяем существование если требуется
        if check_exists and not path.exists():
            raise SecurityError(f"Path does not exist: {path}")
        
        # Проверяем что это не симлинк на критичные системные файлы
        if path.is_symlink():
            target = path.readlink()
            if str(target).startswith(("/dev", "/proc", "/sys")):
                raise SecurityError(f"Symbolic link points to system path: {target}")
        
        return path
    
    def validate_output_directory(self, output_dir: Union[str, Path]) -> Path:
        """Валидация директории вывода"""
        output_path = Path(output_dir).resolve()
        
        # Проверяем что директория в списке разрешенных
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
        
        # Проверяем что это не симлинк
        if output_path.exists() and output_path.is_symlink():
            raise SecurityError(f"Output directory is a symbolic link: {output_path}")
        
        # Проверяем что это не устройство
        if output_path.exists() and not output_path.is_dir():
            raise SecurityError(f"Output path is not a directory: {output_path}")
        
        return output_path
    
    def check_file_size(self, file_path: Union[str, Path]) -> bool:
        """Проверка размера файла"""
        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                raise SecurityError(f"File too large: {size} bytes (max: {self.max_file_size})")
            return True
        except OSError as e:
            raise SecurityError(f"Cannot check file size: {e}")
    
    def check_free_space(self, path: Union[str, Path]) -> bool:
        """Проверка свободного места"""
        try:
            statvfs = os.statvfs(path)
            free_space = statvfs.f_frsize * statvfs.f_bavail
            if free_space < self.min_free_space:
                raise SecurityError(f"Insufficient disk space: {free_space} bytes available")
            return True
        except OSError as e:
            raise SecurityError(f"Cannot check disk space: {e}")
    
    def safe_create_directory(self, dir_path: Union[str, Path], mode: int = 0o750) -> Path:
        """Безопасное создание директории"""
        dir_path = self.validate_output_directory(dir_path)
        
        if not dir_path.exists():
            # Проверяем свободное место
            parent = dir_path.parent
            self.check_free_space(parent)
            
            # Создаем директорию с безопасными правами
            dir_path.mkdir(parents=True, exist_ok=True, mode=mode)
        
        # Проверяем права доступа
        if not os.access(dir_path, os.W_OK):
            raise SecurityError(f"No write permission for directory: {dir_path}")
        
        return dir_path
    
    def safe_write_file(self, file_path: Union[str, Path], content: Union[str, bytes], 
                       mode: int = 0o640, atomic: bool = True) -> Path:
        """Безопасная запись файла"""
        file_path = Path(file_path).resolve()
        
        # Валидируем директорию
        self.validate_output_directory(file_path.parent)
        
        # Проверяем свободное место
        self.check_free_space(file_path.parent)
        
        if atomic:
            # Атомарная запись через временный файл
            temp_path = file_path.with_suffix('.tmp')
            
            try:
                with open(temp_path, 'w' if isinstance(content, str) else 'wb', 
                         encoding='utf-8' if isinstance(content, str) else None) as f:
                    f.write(content)
                
                # Устанавливаем права доступа
                os.chmod(temp_path, mode)
                
                # Атомарное переименование
                temp_path.rename(file_path)
                
            except Exception as e:
                # Очищаем временный файл при ошибке
                if temp_path.exists():
                    temp_path.unlink()
                raise SecurityError(f"Failed to write file atomically: {e}")
        else:
            # Обычная запись
            with open(file_path, 'w' if isinstance(content, str) else 'wb',
                     encoding='utf-8' if isinstance(content, str) else None) as f:
                f.write(content)
            
            os.chmod(file_path, mode)
        
        return file_path
    
    def safe_read_file(self, file_path: Union[str, Path], max_size: Optional[int] = None) -> Union[str, bytes]:
        """Безопасное чтение файла"""
        file_path = self.validate_path(file_path, check_exists=True)
        
        # Проверяем размер файла
        check_size = max_size or self.max_file_size
        size = os.path.getsize(file_path)
        if size > check_size:
            raise SecurityError(f"File too large to read: {size} bytes")
        
        # Проверяем права доступа
        if not os.access(file_path, os.R_OK):
            raise SecurityError(f"No read permission for file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except UnicodeDecodeError:
            # Пробуем как бинарный файл
            with open(file_path, 'rb') as f:
                return f.read()
    
    def is_safe_symlink(self, link_path: Union[str, Path]) -> bool:
        """Проверка безопасности символической ссылки"""
        link_path = Path(link_path)
        
        if not link_path.is_symlink():
            return True
        
        try:
            target = link_path.readlink()
            target_resolved = link_path.resolve()
            
            # Проверяем что ссылка не указывает на системные пути
            target_str = str(target_resolved)
            dangerous_paths = ["/dev", "/proc", "/sys", "/boot"]
            
            for dangerous in dangerous_paths:
                if target_str.startswith(dangerous):
                    return False
            
            return True
            
        except (OSError, RuntimeError):
            # Битая ссылка или циклическая ссылка
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        """Санитизация имени файла"""
        # Убираем опасные символы
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Ограничиваем длину
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        # Убираем пробелы в начале и конце
        sanitized = sanitized.strip()
        
        # Проверяем что имя не пустое
        if not sanitized:
            sanitized = "unnamed_file"
        
        return sanitized


class ProcessSecurityManager:
    """Менеджер безопасности для операций с процессами"""
    
    def __init__(self, config: dict):
        self.config = config
    
    def check_privileges(self) -> dict:
        """Проверка текущих привилегий"""
        return {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "euid": os.geteuid(),
            "egid": os.getegid(),
            "is_root": os.geteuid() == 0,
            "groups": os.getgroups() if hasattr(os, 'getgroups') else []
        }
    
    def require_privileges(self, operation: str) -> bool:
        """Проверка необходимых привилегий для операции"""
        privileges = self.check_privileges()
        
        # Операции требующие root
        root_operations = ["memory_scan", "keyring_system", "proc_access"]
        
        if operation in root_operations and not privileges["is_root"]:
            raise SecurityError(f"Operation '{operation}' requires root privileges")
        
        return True
    
    def is_process_accessible(self, pid: int) -> bool:
        """Проверка доступности процесса"""
        try:
            # Проверяем существование процесса
            os.kill(pid, 0)
            
            # Проверяем права доступа к /proc/pid
            proc_path = f"/proc/{pid}"
            return os.access(proc_path, os.R_OK)
            
        except (OSError, ProcessLookupError):
            return False 