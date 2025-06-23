#!/usr/bin/env python3
"""
credfinder-linux — Main Entry Point
Linux Credential & Secret Hunting Toolkit
"""

import argparse
import json
import os
import sys
import threading
import concurrent.futures
import shutil
import stat
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import traceback

# Import modules
from modules.ssh_scanner import SSHScanner
from modules.browser_extractor import BrowserExtractor
from modules.keyring_dump import KeyringDump
from modules.memory_grepper import MemoryGrepper
from modules.dotfile_scanner import DotfileScanner
from modules.history_parser import HistoryParser
from modules.report_generator import ReportGenerator
from modules.utils.logger import Logger, get_logger
from modules.utils.config_loader import ConfigLoader


class ExecutionStrategy:
    """Стратегии выполнения модулей"""
    PRIORITY_BASED = "priority"
    CUSTOM_ORDER = "custom"
    TIME_OPTIMIZED = "time_optimized"
    DEPENDENCY_AWARE = "dependency_aware"


class ModuleResult:
    """Структурированный результат выполнения модуля"""
    def __init__(self, module_name: str, status: str, data: Any = None, 
                 error: str = None, execution_time: float = 0.0, 
                 skipped_reason: str = None):
        self.module_name = module_name
        self.status = status  # success, failed, skipped, timeout
        self.data = data if data is not None else {}
        self.error = error
        self.execution_time = execution_time
        self.skipped_reason = skipped_reason
        self.timestamp = datetime.now()
    
    def is_successful(self) -> bool:
        return self.status == 'success' and self.data is not None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'module_name': self.module_name,
            'status': self.status,
            'data': self.data,
            'error': self.error,
            'execution_time': self.execution_time,
            'skipped_reason': self.skipped_reason,
            'timestamp': self.timestamp.isoformat()
        }


class SafeFileSystemManager:
    """Безопасное управление файловой системой"""
    
    @staticmethod
    def validate_output_path(output_path: str, allowed_dirs: List[str] = None) -> Path:
        """Валидация пути для записи с проверками безопасности"""
        try:
            path = Path(output_path).resolve()
            
            # Проверяем разрешенные директории
            if allowed_dirs:
                allowed = False
                for allowed_dir in allowed_dirs:
                    allowed_path = Path(allowed_dir).resolve()
                    try:
                        path.relative_to(allowed_path)
                        allowed = True
                        break
                    except ValueError:
                        continue
                
                if not allowed:
                    raise ValueError(f"Output path {path} not in allowed directories: {allowed_dirs}")
            
            # Проверяем существующий путь
            if path.exists():
                # Не симлинк
                if path.is_symlink():
                    raise ValueError(f"Output path {path} is a symbolic link")
                
                # Не устройство
                if path.is_block_device() or path.is_char_device():
                    raise ValueError(f"Output path {path} is a device")
                
                # Если файл - проверяем, что это обычный файл
                if path.is_file():
                    st = path.stat()
                    if not stat.S_ISREG(st.st_mode):
                        raise ValueError(f"Output path {path} is not a regular file")
                
                # Если директория - проверяем права
                if path.is_dir():
                    if not os.access(path, os.W_OK):
                        raise PermissionError(f"No write permission for directory {path}")
            
            return path
            
        except Exception as e:
            raise ValueError(f"Invalid output path {output_path}: {e}")
    
    @staticmethod
    def check_disk_space(path: Path, min_space_mb: int = 100) -> bool:
        """Проверка свободного места на диске"""
        try:
            statvfs = os.statvfs(path.parent if path.is_file() else path)
            free_space = statvfs.f_frsize * statvfs.f_bavail
            free_space_mb = free_space / (1024 * 1024)
            
            if free_space_mb < min_space_mb:
                raise OSError(f"Insufficient disk space: {free_space_mb:.1f}MB available, {min_space_mb}MB required")
            
            return True
        except Exception as e:
            raise OSError(f"Failed to check disk space: {e}")
    
    @staticmethod
    def safe_create_directory(path: Path, mode: int = 0o750) -> Path:
        """Безопасное создание директории"""
        try:
            path.mkdir(parents=True, exist_ok=True, mode=mode)
            
            # Устанавливаем права явно (на случай umask)
            os.chmod(path, mode)
            
            return path
        except Exception as e:
            raise OSError(f"Failed to create directory {path}: {e}")
    
    @staticmethod
    def atomic_write(file_path: Path, data: str, mode: int = 0o640) -> Path:
        """Атомарная запись файла"""
        try:
            temp_path = file_path.with_suffix(f'{file_path.suffix}.tmp')
            
            # Записываем во временный файл
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(data)
            
            # Атомарное переименование
            temp_path.rename(file_path)
            
            # Устанавливаем права доступа
            os.chmod(file_path, mode)
            
            return file_path
        except Exception as e:
            # Очищаем временный файл при ошибке
            if temp_path.exists():
                temp_path.unlink()
            raise OSError(f"Failed to write file {file_path}: {e}")


class ModuleRunner:
    """Управляет выполнением модулей с расширенными возможностями"""
    
    def __init__(self, config, logger: Logger):
        self.config = config
        self.logger = logger
        self.results = {}
        self.lock = threading.Lock()
        
        # Определение модулей с расширенными метаданными
        self.modules = {
            'ssh': {
                'class': SSHScanner,
                'method': 'scan',
                'priority': 1,
                'requires_privileges': False,
                'estimated_time': 'fast',
                'parallel_safe': True,
                'timeout': 60,
                'dependencies': [],
                'resource_intensive': False
            },
            'dotfiles': {
                'class': DotfileScanner,
                'method': 'scan',
                'priority': 2,
                'requires_privileges': False,
                'estimated_time': 'fast',
                'parallel_safe': True,
                'timeout': 120,
                'dependencies': [],
                'resource_intensive': False
            },
            'history': {
                'class': HistoryParser,
                'method': 'parse',
                'priority': 3,
                'requires_privileges': False,
                'estimated_time': 'fast',
                'parallel_safe': True,
                'timeout': 60,
                'dependencies': [],
                'resource_intensive': False
            },
            'browser': {
                'class': BrowserExtractor,
                'method': 'extract_all',
                'priority': 4,
                'requires_privileges': False,
                'estimated_time': 'medium',
                'parallel_safe': False,  # Из-за file locking
                'timeout': 180,
                'dependencies': [],
                'resource_intensive': True
            },
            'memory': {
                'class': MemoryGrepper,
                'method': 'scan',
                'priority': 5,
                'requires_privileges': True,
                'estimated_time': 'slow',
                'parallel_safe': True,
                'timeout': 600,
                'dependencies': [],
                'resource_intensive': True
            },
            'keyring': {
                'class': KeyringDump,
                'method': 'dump',
                'priority': 6,
                'requires_privileges': False,
                'estimated_time': 'slow',
                'parallel_safe': False,  # Из-за D-Bus
                'timeout': 300,
                'dependencies': [],
                'resource_intensive': False
            }
        }
    
    def validate_module_result(self, result: Any, module_name: str) -> Tuple[bool, str]:
        """Валидация результата модуля"""
        if result is None:
            return False, "Module returned None"
        
        if isinstance(result, dict):
            if not result:  # Пустой dict - нормально
                return True, ""
            # Проверяем, что это не dict с ошибкой
            if 'error' in result and result.get('error'):
                return False, f"Module returned error: {result['error']}"
        
        elif isinstance(result, list):
            if not result:  # Пустой список - нормально
                return True, ""
        
        else:
            # Неожиданный тип результата
            self.logger.warning(f"Module {module_name} returned unexpected type: {type(result)}")
        
        return True, ""
    
    def run_module_safe(self, module_name: str) -> ModuleResult:
        """Безопасное выполнение модуля с расширенной обработкой ошибок"""
        start_time = datetime.now()
        
        try:
            self.logger.log_module_start(module_name)
            
            if module_name not in self.modules:
                error_msg = f"Unknown module: {module_name}"
                self.logger.error(error_msg)
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            module_info = self.modules[module_name]
            
            # Проверка привилегий
            if module_info['requires_privileges'] and os.geteuid() != 0:
                reason = 'requires_root_privileges'
                self.logger.log_module_skip(module_name, reason)
                return ModuleResult(module_name, 'skipped', skipped_reason=reason)
            
            # Инициализация модуля с обработкой ошибок
            try:
                module_class = module_info['class']
                module_instance = module_class(self.config)
                method = getattr(module_instance, module_info['method'])
            except Exception as e:
                error_msg = f"Initialization failed: {str(e)}"
                self.logger.log_module_error(module_name, e)
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            # Выполнение с обработкой ошибок
            try:
                if module_info['parallel_safe']:
                    # Для parallel_safe модулей используем простой вызов
                    result = method()
                else:
                    # Для небезопасных модулей добавляем дополнительную защиту
                    with self.lock:
                        result = method()
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Валидация результата
                is_valid, validation_error = self.validate_module_result(result, module_name)
                
                if not is_valid:
                    error_msg = f"Validation failed: {validation_error}"
                    self.logger.error(f"Module {module_name} validation failed: {validation_error}")
                    return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
                
                # Подсчитываем количество находок для логирования
                findings_count = 0
                if isinstance(result, list):
                    findings_count = len(result)
                elif isinstance(result, dict):
                    findings_count = sum(len(v) if isinstance(v, list) else 1 for v in result.values() if v)
                
                self.logger.log_module_success(module_name, execution_time, findings_count)
                return ModuleResult(module_name, 'success', data=result, execution_time=execution_time)
                
            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                error_msg = f"Execution failed: {str(e)}"
                self.logger.log_module_error(module_name, e, execution_time)
                return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
                
        except Exception as e:
            # Критическая ошибка на уровне runner'а
            execution_time = (datetime.now() - start_time).total_seconds()
            error_msg = f"Critical error in module runner: {str(e)}"
            self.logger.critical(f"Critical error in module runner for {module_name}: {e}")
            self.logger.exception("Full traceback of critical error")
            return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
    
    def get_execution_order(self, module_names: List[str], strategy: str = ExecutionStrategy.PRIORITY_BASED, 
                           custom_order: List[str] = None) -> List[str]:
        """Определение порядка выполнения модулей"""
        valid_modules = [name for name in module_names if name in self.modules]
        
        if strategy == ExecutionStrategy.CUSTOM_ORDER and custom_order:
            # Пользовательский порядок
            ordered = []
            for module in custom_order:
                if module in valid_modules:
                    ordered.append(module)
            
            # Добавляем оставшиеся модули
            for module in valid_modules:
                if module not in ordered:
                    ordered.append(module)
            
            return ordered
        
        elif strategy == ExecutionStrategy.TIME_OPTIMIZED:
            # Сначала быстрые, потом медленные
            fast_modules = [m for m in valid_modules if self.modules[m]['estimated_time'] == 'fast']
            medium_modules = [m for m in valid_modules if self.modules[m]['estimated_time'] == 'medium']
            slow_modules = [m for m in valid_modules if self.modules[m]['estimated_time'] == 'slow']
            
            return fast_modules + medium_modules + slow_modules
        
        elif strategy == ExecutionStrategy.DEPENDENCY_AWARE:
            # Учитываем зависимости (пока простая реализация)
            return sorted(valid_modules, key=lambda x: (
                len(self.modules[x].get('dependencies', [])),
                self.modules[x]['priority']
            ))
        
        else:  # PRIORITY_BASED (по умолчанию)
            return sorted(valid_modules, key=lambda x: self.modules[x]['priority'])
    
    def run_modules_parallel(self, module_names: List[str], max_workers: int = 3) -> Dict[str, ModuleResult]:
        """Параллельное выполнение модулей с улучшенной обработкой"""
        results = {}
        
        # Разделяем модули на parallel_safe и sequential
        parallel_modules = []
        sequential_modules = []
        
        for name in module_names:
            if name in self.modules:
                if self.modules[name]['parallel_safe']:
                    parallel_modules.append(name)
                else:
                    sequential_modules.append(name)
        
        # Выполняем parallel_safe модули параллельно
        if parallel_modules:
            self.logger.info(f"Running parallel modules: {', '.join(parallel_modules)}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_module = {
                    executor.submit(self.run_module_safe, module): module 
                    for module in parallel_modules
                }
                
                for future in concurrent.futures.as_completed(future_to_module):
                    module_name = future_to_module[future]
                    try:
                        timeout = self.modules[module_name].get('timeout', 300)
                        result = future.result(timeout=timeout)
                        results[module_name] = result
                        
                    except concurrent.futures.TimeoutError:
                        timeout = self.modules[module_name].get('timeout', 300)
                        self.logger.log_module_timeout(module_name, timeout)
                        results[module_name] = ModuleResult(
                            module_name, 'timeout',
                            error=f"Module timed out after {timeout} seconds"
                        )
                        
                    except Exception as e:
                        self.logger.error(f"Unexpected error in parallel execution for {module_name}: {e}")
                        self.logger.exception(f"Full traceback for parallel execution error in {module_name}")
                        results[module_name] = ModuleResult(
                            module_name, 'failed',
                            error=f"Parallel execution error: {str(e)}"
                        )
        
        # Выполняем sequential модули последовательно
        for module_name in sequential_modules:
            self.logger.info(f"Running sequential module: {module_name}")
            results[module_name] = self.run_module_safe(module_name)
        
        return results
    
    def run_modules_sequential(self, module_names: List[str]) -> Dict[str, ModuleResult]:
        """Последовательное выполнение модулей"""
        results = {}
        
        for module_name in module_names:
            if module_name in self.modules:
                self.logger.info(f"Running module: {module_name}")
                results[module_name] = self.run_module_safe(module_name)
            else:
                error_msg = f"Unknown module: {module_name}"
                self.logger.error(error_msg)
                results[module_name] = ModuleResult(module_name, 'failed', error=error_msg)
        
        return results


class CredFinder:
    def __init__(self, config_path="config.json"):
        self.config = ConfigLoader(config_path)
        
        # Настраиваем логгер на основе конфигурации
        log_config = self.config.get("logging", {})
        opsec_config = self.config.get("opsec", {})
        
        log_file = None
        if log_config.get("file_logging", False) or opsec_config.get("log_to_file", False):
            log_file = opsec_config.get("log_file", "./logs/credfinder.log")
        
        self.logger = get_logger(
            name="credfinder",
            minimal_logging=opsec_config.get("minimal_logging", False),
            log_file=log_file,
            log_level=log_config.get("level", "INFO")
        )
        
        self.module_runner = ModuleRunner(self.config, self.logger)
        self.fs_manager = SafeFileSystemManager()
        self.results = {}
        self.execution_stats = {}
        
    def run_scan(self, modules: List[str], parallel: bool = True, 
                 execution_strategy: str = ExecutionStrategy.PRIORITY_BASED,
                 custom_order: List[str] = None, max_workers: int = 3) -> Dict[str, Any]:
        """Главный метод сканирования с гибким управлением"""
        
        # Определяем порядок выполнения
        execution_order = self.module_runner.get_execution_order(
            modules, execution_strategy, custom_order
        )
        
        self.logger.info(f"Execution order: {', '.join(execution_order)}")
        self.logger.info(f"Execution mode: {'parallel' if parallel else 'sequential'}")
        
        # Выполняем модули
        if parallel:
            module_results = self.module_runner.run_modules_parallel(execution_order, max_workers)
        else:
            module_results = self.module_runner.run_modules_sequential(execution_order)
        
        # Обрабатываем результаты
        self.results = {}
        self.execution_stats = {
            'total_modules': len(modules),
            'successful_modules': 0,
            'failed_modules': 0,
            'skipped_modules': 0,
            'timeout_modules': 0,
            'total_execution_time': 0.0,
            'module_details': {}
        }
        
        for module_name, result in module_results.items():
            # Сохраняем статистику
            self.execution_stats['module_details'][module_name] = result.to_dict()
            self.execution_stats['total_execution_time'] += result.execution_time
            
            if result.status == 'success':
                self.execution_stats['successful_modules'] += 1
                self.results[module_name] = result.data
            elif result.status == 'failed':
                self.execution_stats['failed_modules'] += 1
                self.results[module_name] = {}
                # Ошибка уже залогирована в run_module_safe
            elif result.status == 'skipped':
                self.execution_stats['skipped_modules'] += 1
                self.results[module_name] = {}
                # Пропуск уже залогирован в run_module_safe
            elif result.status == 'timeout':
                self.execution_stats['timeout_modules'] += 1
                self.results[module_name] = {}
                # Таймаут уже залогирован в run_module_safe
        
        return self.results
    
    def generate_report(self, format_type="json"):
        """Generate report in specified format"""
        self.logger.info(f"Generating {format_type} report...")
        try:
            generator = ReportGenerator(self.config)
            result = generator.generate(self.results, format_type, self.execution_stats)
            self.logger.success(f"Report generated successfully: {format_type}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to generate {format_type} report: {e}")
            self.logger.exception("Full traceback for report generation error")
            raise
    
    def save_results(self, output_dir="./reports"):
        """Безопасное сохранение результатов с расширенными проверками"""
        try:
            self.logger.info(f"Saving results to {output_dir}")
            
            # Валидация пути
            allowed_dirs = self.config.get("security", {}).get("allowed_output_dirs", ["./reports"])
            output_path = self.fs_manager.validate_output_path(output_dir, allowed_dirs)
            
            # Проверка свободного места
            min_space_mb = self.config.get("security", {}).get("min_free_space", 100) // (1024 * 1024)
            self.fs_manager.check_disk_space(output_path, min_space_mb)
            
            # Создание директории
            if not output_path.exists():
                dir_mode = int(self.config.get("security", {}).get("safe_dir_permissions", "0o750"), 8)
                self.fs_manager.safe_create_directory(output_path, dir_mode)
            
            # Генерация имени файла
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = output_path / f"credfinder_results_{timestamp}.json"
            
            # Подготовка данных для сохранения
            save_data = {
                'metadata': {
                    'timestamp': timestamp,
                    'version': '1.0',
                    'execution_stats': self.execution_stats
                },
                'results': self.results
            }
            
            # Атомарная запись
            file_mode = int(self.config.get("security", {}).get("safe_file_permissions", "0o640"), 8)
            json_content = json.dumps(save_data, indent=2, default=str, ensure_ascii=False)
            
            final_path = self.fs_manager.atomic_write(json_path, json_content, file_mode)
            
            self.logger.success(f"Results saved successfully to {final_path}")
            return str(final_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            self.logger.exception("Full traceback for save results error")
            raise


def main():
    parser = argparse.ArgumentParser(
        description="credfinder-linux — Linux Credential & Secret Hunting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --modules ssh browser --parallel          # Параллельное выполнение
  python3 main.py --modules ssh browser --sequential        # Последовательное выполнение
  python3 main.py --modules ssh browser --order ssh,browser # Пользовательский порядок
  python3 main.py --all --max-workers 5                     # Все модули, 5 потоков
  python3 main.py --fast-only --strategy time-optimized     # Быстрые модули оптимально
        """
    )
    
    # Выбор модулей
    parser.add_argument("--all", action="store_true", help="Run all available modules")
    parser.add_argument("--modules", nargs='+', 
                       choices=['ssh', 'browser', 'keyring', 'memory', 'dotfiles', 'history'],
                       help="Specific modules to run")
    parser.add_argument("--fast-only", action="store_true", 
                       help="Run only fast modules (ssh, dotfiles, history)")
    
    # Управление выполнением
    parser.add_argument("--parallel", action="store_true", default=True,
                       help="Run modules in parallel (default)")
    parser.add_argument("--sequential", action="store_true",
                       help="Run modules sequentially")
    parser.add_argument("--order", type=str,
                       help="Custom module execution order (comma-separated)")
    parser.add_argument("--strategy", choices=['priority', 'custom', 'time-optimized', 'dependency-aware'],
                       default='priority', help="Execution strategy")
    parser.add_argument("--max-workers", type=int, default=3,
                       help="Maximum number of parallel workers")
    
    # Остальные опции
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    parser.add_argument("--target", help="Target directory to scan")
    parser.add_argument("--report", choices=["json", "html", "csv", "console"], 
                       default="json", help="Report format")
    parser.add_argument("--opsec", action="store_true", help="Enable OPSEC mode")
    parser.add_argument("--output-dir", default="./reports", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--continue-on-error", action="store_true", default=True,
                       help="Continue execution even if some modules fail")
    
    args = parser.parse_args()
    
    # Validate config file exists
    if not os.path.exists(args.config):
        logging.error(f"Config file '{args.config}' not found.")
        print("Please ensure the config.json file exists in the current directory.", file=sys.stderr)
        sys.exit(1)
    
    # Initialize CredFinder
    try:
        credfinder = CredFinder(args.config)
        
        # Настраиваем уровень логирования на основе аргументов
        if args.debug:
            credfinder.logger.enable_debug()
        elif args.verbose:
            credfinder.logger.set_level("INFO")
        elif args.opsec:
            credfinder.logger.enable_minimal()
            
    except Exception as e:
        logging.error(f"Failed to initialize CredFinder: {e}")
        if args.verbose or args.debug:
            logging.exception("Full traceback:")
        sys.exit(1)
    
    # Override config with command line arguments
    if args.target:
        credfinder.config.set_scan_paths(args.target)
    
    if args.opsec:
        credfinder.config.set_opsec_mode(True)
    
    # Определяем модули для запуска
    if args.all:
        modules_to_run = ['ssh', 'browser', 'keyring', 'memory', 'dotfiles', 'history']
    elif args.fast_only:
        modules_to_run = ['ssh', 'dotfiles', 'history']
    elif args.modules:
        modules_to_run = args.modules
    else:
        credfinder.logger.error("No modules selected. Use --all, --fast-only, or --modules.")
        sys.exit(1)
    
    # Определяем параметры выполнения
    parallel = not args.sequential
    custom_order = args.order.split(',') if args.order else None
    
    # Маппинг стратегий
    strategy_map = {
        'priority': ExecutionStrategy.PRIORITY_BASED,
        'custom': ExecutionStrategy.CUSTOM_ORDER,
        'time-optimized': ExecutionStrategy.TIME_OPTIMIZED,
        'dependency-aware': ExecutionStrategy.DEPENDENCY_AWARE
    }
    execution_strategy = strategy_map.get(args.strategy, ExecutionStrategy.PRIORITY_BASED)
    
    try:
        # Запускаем сканирование
        credfinder.logger.info(f"Starting scan with modules: {', '.join(modules_to_run)}")
        credfinder.logger.info(f"Strategy: {args.strategy}, Parallel: {parallel}")
        
        start_time = datetime.now()
        results = credfinder.run_scan(
            modules_to_run, 
            parallel=parallel,
            execution_strategy=execution_strategy,
            custom_order=custom_order,
            max_workers=args.max_workers
        )
        end_time = datetime.now()
        
        total_execution_time = (end_time - start_time).total_seconds()
        
        # Сохраняем результаты
        try:
            result_path = credfinder.save_results(args.output_dir)
            
            if args.report != "json":
                report_path = credfinder.generate_report(args.report)
                credfinder.logger.info(f"Report generated: {report_path}")
        
        except Exception as e:
            credfinder.logger.error(f"Failed to save results: {e}")
            if not args.continue_on_error:
                sys.exit(1)
        
        # Выводим статистику
        stats = credfinder.execution_stats
        successful = stats['successful_modules']
        failed = stats['failed_modules']
        skipped = stats['skipped_modules']
        timeout = stats['timeout_modules']
        total = stats['total_modules']
        
        print(f"\n=== Execution Summary ===")
        print(f"Total modules: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        print(f"Timeout: {timeout}")
        print(f"Total execution time: {total_execution_time:.2f}s")
        
        if results:
            total_findings = 0
            for module, data in results.items():
                if data:
                    if isinstance(data, list):
                        total_findings += len(data)
                    elif isinstance(data, dict):
                        total_findings += sum(len(v) if isinstance(v, list) else 1 for v in data.values() if v)
            
            print(f"Total findings: {total_findings}")
            
            if 'result_path' in locals():
                print(f"Results saved to: {result_path}")
        
        if args.verbose and stats['module_details']:
            print(f"\n=== Module Details ===")
            for module, details in stats['module_details'].items():
                status = details['status']
                exec_time = details['execution_time']
                print(f"{module}: {status} ({exec_time:.2f}s)")
                if details['error']:
                    print(f"  Error: {details['error']}")
        
        # Определяем код выхода
        if failed > 0 and not args.continue_on_error:
            credfinder.logger.error("Some modules failed and --continue-on-error is disabled")
            sys.exit(1)
        elif successful == 0:
            credfinder.logger.warning("No modules completed successfully")
            print("Warning: No modules completed successfully")
            sys.exit(2)
        else:
            credfinder.logger.success("Scan completed successfully!")
            print("Scan completed successfully!")
            
    except KeyboardInterrupt:
        credfinder.logger.warning("Scan interrupted by user")
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        credfinder.logger.critical(f"Scan failed with critical error: {e}")
        credfinder.logger.exception("Full traceback of critical error")
        print(f"Scan failed: {e}")
        if args.verbose or args.debug:
            print(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main() 