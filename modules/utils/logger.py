import logging
import logging.handlers
import sys
import os
import json
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path


class CredFinderFormatter(logging.Formatter):
    """Custom formatter for credfinder-linux"""
    
    # Color codes for console
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'SUCCESS': '\033[92m',   # Bright Green
        'RESET': '\033[0m'       # Reset
    }
    
    def __init__(self, use_colors=True, minimal=False):
        self.use_colors = use_colors and sys.stderr.isatty()
        self.minimal = minimal
        
        if minimal:
            fmt = '%(levelname)s: %(message)s'
        else:
            fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        super().__init__(fmt, datefmt='%Y-%m-%d %H:%M:%S')
    
    def format(self, record):
        # Add support for SUCCESS level
        if record.levelname == 'SUCCESS':
            record.levelno = 25  # Between INFO (20) and WARNING (30)
        
        formatted = super().format(record)
        
        if self.use_colors:
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            formatted = f"{color}{formatted}{reset}"
        
        return formatted


class Logger:
    """Enhanced logger for credfinder-linux based on standard logging"""
    
    def __init__(self, name="credfinder", minimal_logging=False, 
                 log_file: Optional[str] = None, log_level="INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Всегда DEBUG на уровне логгера
        
        # Очищаем существующие обработчики
        self.logger.handlers.clear()
        
        # Добавляем SUCCESS уровень
        logging.addLevelName(25, 'SUCCESS')
        
        # Настраиваем уровень логирования
        if minimal_logging:
            console_level = logging.ERROR
        else:
            console_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(console_level)
        console_formatter = CredFinderFormatter(use_colors=True, minimal=minimal_logging)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Файловый обработчик
        if log_file:
            self._setup_file_logging(log_file)
        
        # Флаги для контроля поведения
        self.minimal_logging = minimal_logging
        self.log_file = log_file
    
    def _setup_file_logging(self, log_file: str):
        """Configure file logging with rotation"""
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use RotatingFileHandler for automatic rotation
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, 
                maxBytes=10*1024*1024,  # 10MB
                backupCount=3,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            
            # JSON formatter for files
            file_formatter = JsonFormatter()
            file_handler.setFormatter(file_formatter)
            
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            # If file logging cannot be set up, continue without it
            self.logger.warning(f"Failed to setup file logging: {e}")
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Informational message"""
        self.logger.info(message, extra=self._prepare_extra(extra))
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Warning"""
        self.logger.warning(message, extra=self._prepare_extra(extra))
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Error"""
        self.logger.error(message, extra=self._prepare_extra(extra))
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Critical error"""
        self.logger.critical(message, extra=self._prepare_extra(extra))
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Debug message"""
        self.logger.debug(message, extra=self._prepare_extra(extra))
    
    def success(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Success message"""
        self.logger.log(25, message, extra=self._prepare_extra(extra))
    
    def exception(self, message: str, exc_info=True, extra: Optional[Dict[str, Any]] = None):
        """Exception logging with stack trace"""
        self.logger.error(message, exc_info=exc_info, extra=self._prepare_extra(extra))
    
    def log_module_start(self, module_name: str):
        """Special method for logging the start of module execution"""
        self.info(f"Starting module: {module_name}", {"module_name": module_name, "event": "start"})
    
    def log_module_success(self, module_name: str, execution_time: float, findings_count: int = 0):
        """Special method for logging successful module completion"""
        self.success(
            f"Module {module_name} completed successfully in {execution_time:.2f}s",
            {
                "module_name": module_name,
                "event": "success",
                "execution_time": execution_time,
                "findings_count": findings_count
            }
        )
    
    def log_module_error(self, module_name: str, error: Exception, execution_time: float = 0):
        """Special method for logging module error"""
        self.error(
            f"Module {module_name} failed: {str(error)}",
            {
                "module_name": module_name,
                "event": "error",
                "error_type": type(error).__name__,
                "error_message": str(error),
                "execution_time": execution_time
            }
        )
        
        # Log full stack trace in debug mode
        if not self.minimal_logging:
            self.exception(f"Full traceback for {module_name}")
    
    def log_module_skip(self, module_name: str, reason: str):
        """Special method for logging module skip"""
        self.warning(
            f"Module {module_name} skipped: {reason}",
            {
                "module_name": module_name,
                "event": "skip",
                "reason": reason
            }
        )
    
    def log_module_timeout(self, module_name: str, timeout: int):
        """Special method for logging module timeout"""
        self.error(
            f"Module {module_name} timed out after {timeout}s",
            {
                "module_name": module_name,
                "event": "timeout",
                "timeout": timeout
            }
        )
    
    def _prepare_extra(self, extra: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Prepares extra data for logging"""
        if extra is None:
            return None
        
        # Add timestamp for structured logging
        prepared = extra.copy()
        prepared['timestamp'] = datetime.now().isoformat()
        
        return prepared
    
    def set_level(self, level: str):
        """Dynamically change logging level"""
        log_level = getattr(logging, level.upper(), logging.INFO)
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stderr:
                handler.setLevel(log_level)
    
    def enable_debug(self):
        """Enable debug mode"""
        self.set_level("DEBUG")
        self.minimal_logging = False
    
    def enable_minimal(self):
        """Enable minimal logging mode"""
        self.set_level("ERROR")
        self.minimal_logging = True


class JsonFormatter(logging.Formatter):
    """JSON formatter for file logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module_name': getattr(record, 'module_name', record.module) if hasattr(record, 'module_name') else None,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Добавляем дополнительные поля если есть
        if hasattr(record, 'extra') and record.extra:
            log_entry.update(record.extra)
        
        # Добавляем информацию об исключении если есть
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


def get_logger(name="credfinder", **kwargs) -> Logger:
    """Factory function for creating a logger"""
    return Logger(name, **kwargs) 