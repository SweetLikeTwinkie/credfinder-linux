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
import heapq
import zipfile
import tempfile

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
    """Module execution strategies"""
    PRIORITY_BASED = "priority"
    CUSTOM_ORDER = "custom"
    TIME_OPTIMIZED = "time_optimized"
    DEPENDENCY_AWARE = "dependency_aware"


class ModuleResult:
    """Structured result of module execution"""
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
        """Return True if the module execution was successful and data is present."""
        return self.status == 'success' and self.data is not None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
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
    """Safe file system management."""
    
    @staticmethod
    def validate_output_path(output_path: str, allowed_dirs: List[str] = None) -> Path:
        """Validate output path for writing with security checks."""
        try:
            # Check if the provided path is actually a file (not directory/device)
            if os.path.exists(output_path):
                if not os.path.isfile(output_path) and not os.path.isdir(output_path):
                    raise ValueError(f"Output path {output_path} is not a regular file or directory")
                
                # Check for symlinks BEFORE resolving them
                if os.path.islink(output_path):
                    raise ValueError(f"Output path {output_path} is a symbolic link")
            
            path = Path(output_path).resolve()
            
            # Check allowed directories
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
            
            # Check existing path
            if path.exists():
                # Not a device
                if path.is_block_device() or path.is_char_device():
                    raise ValueError(f"Output path {path} is a device")
                
                # If file, check it's a regular file
                if path.is_file():
                    st = path.stat()
                    if not stat.S_ISREG(st.st_mode):
                        raise ValueError(f"Output path {path} is not a regular file")
                
                # If directory, check permissions
                if path.is_dir():
                    if not os.access(path, os.W_OK):
                        raise PermissionError(f"No write permission for directory {path}")
            
            return path
            
        except Exception as e:
            raise ValueError(f"Invalid output path {output_path}: {e}")
    
    @staticmethod
    def check_disk_space(path: Path, min_space_bytes: int = 104857600) -> bool:
        """Check free disk space in bytes."""
        try:
            # Ensure the directory exists for the statvfs call
            check_path = path.parent if path.is_file() or not path.exists() else path
            if not check_path.exists():
                check_path = check_path.parent
                
            statvfs = os.statvfs(check_path)
            free_space = statvfs.f_frsize * statvfs.f_bavail
            
            if free_space < min_space_bytes:
                raise OSError(f"Insufficient disk space: {free_space} bytes available, {min_space_bytes} bytes required")
            
            return True
        except Exception as e:
            raise OSError(f"Failed to check disk space: {e}")
    
    @staticmethod
    def safe_create_directory(path: Path, mode: int = 0o750) -> Path:
        """Safely create a directory with the given mode."""
        try:
            path.mkdir(parents=True, exist_ok=True, mode=mode)
            
            # Set permissions explicitly (in case of umask)
            os.chmod(path, mode)
            
            return path
        except Exception as e:
            raise OSError(f"Failed to create directory {path}: {e}")
    
    @staticmethod
    def atomic_write(file_path: Path, data: str, mode: int = 0o640) -> Path:
        """Atomically write a file using secure temporary file creation."""
        logger = get_logger("credfinder.atomicwrite")
        
        try:
            # Create secure temporary file in the same directory as target
            # This prevents cross-filesystem moves and maintains security context
            target_dir = file_path.parent
            
            # Ensure target directory exists
            if not target_dir.exists():
                target_dir.mkdir(parents=True, exist_ok=True)
            
            # Create secure temporary file with proper permissions
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                dir=target_dir,
                prefix=f'.{file_path.name}.tmp.',
                suffix='.credfinder',
                delete=False
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(data)
                temp_file.flush()
                os.fsync(temp_file.fileno())  # Force write to disk
            
            # Set proper permissions on temp file
            os.chmod(temp_path, mode)
            
            try:
                # Try atomic rename first (works on same filesystem)
                temp_path.rename(file_path)
            except OSError as e:
                # Fallback to shutil.move for cross-filesystem
                logger.warning(f"Atomic rename failed ({e}), using shutil.move fallback for {file_path}")
                shutil.move(str(temp_path), str(file_path))
                # Ensure final permissions are correct
                os.chmod(file_path, mode)
            
            return file_path
            
        except Exception as e:
            # Clean up temporary file on error
            if 'temp_path' in locals() and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp file {temp_path}: {cleanup_error}")
            raise OSError(f"Failed to write file {file_path}: {e}")


class ModuleRunner:
    """Manages module execution with advanced features."""
    
    def __init__(self, config, logger: Logger):
        self.config = config
        self.logger = logger
        self.results = {}
        self.lock = threading.Lock()
        self.results_lock = threading.Lock()  # Separate lock for results
        
        # Map module names to their classes and methods
        module_classes = {
            'ssh': {'class': SSHScanner, 'method': 'scan'},
            'dotfiles': {'class': DotfileScanner, 'method': 'scan'},
            'history': {'class': HistoryParser, 'method': 'parse'},
            'browser': {'class': BrowserExtractor, 'method': 'extract_all'},
            'memory': {'class': MemoryGrepper, 'method': 'scan'},
            'keyring': {'class': KeyringDump, 'method': 'dump'}
        }
        
        # Required fields for module config
        required_fields = [
            'priority', 'timeout', 'parallel_safe', 'requires_privileges',
            'estimated_time', 'resource_intensive', 'dependencies', 'enabled'
        ]
        
        # Load module metadata from config
        config_modules = self.config.get('modules', {})
        self.modules = {}
        
        for name, meta in config_modules.items():
            if name in module_classes:
                missing = [f for f in required_fields if f not in meta]
                if missing:
                    self.logger.warning(f"Module '{name}' is missing required config fields: {missing}. This module will be skipped.")
                    continue
                    
                # Validate field types and values
                if not self._validate_module_config(name, meta):
                    self.logger.warning(f"Module '{name}' has invalid configuration. This module will be skipped.")
                    continue
                    
                self.modules[name] = {
                    **meta,
                    'class': module_classes[name]['class'],
                    'method': module_classes[name]['method']
                }
                
        if not self.modules:
            self.logger.critical("No valid modules found in configuration. Aborting initialization.")
            raise RuntimeError("No valid modules found in configuration.")
    
    def _validate_module_config(self, module_name: str, config: dict) -> bool:
        """Validate module configuration values"""
        try:
            # Validate enabled field
            if not isinstance(config.get('enabled'), bool):
                self.logger.warning(f"Module '{module_name}': 'enabled' must be boolean")
                return False
            
            # Validate priority field
            priority = config.get('priority')
            if not isinstance(priority, int) or priority < 1 or priority > 100:
                self.logger.warning(f"Module '{module_name}': 'priority' must be integer 1-100")
                return False
            
            # Validate timeout field
            timeout = config.get('timeout')
            if not isinstance(timeout, int) or timeout < 1 or timeout > 3600:
                self.logger.warning(f"Module '{module_name}': 'timeout' must be integer 1-3600 seconds")
                return False
            
            # Validate parallel_safe field
            if not isinstance(config.get('parallel_safe'), bool):
                self.logger.warning(f"Module '{module_name}': 'parallel_safe' must be boolean")
                return False
            
            # Validate requires_privileges field
            if not isinstance(config.get('requires_privileges'), bool):
                self.logger.warning(f"Module '{module_name}': 'requires_privileges' must be boolean")
                return False
            
            # Validate estimated_time field
            estimated_time = config.get('estimated_time')
            if estimated_time not in ['fast', 'medium', 'slow']:
                self.logger.warning(f"Module '{module_name}': 'estimated_time' must be 'fast', 'medium', or 'slow'")
                return False
            
            # Validate resource_intensive field
            if not isinstance(config.get('resource_intensive'), bool):
                self.logger.warning(f"Module '{module_name}': 'resource_intensive' must be boolean")
                return False
            
            # Validate dependencies field
            dependencies = config.get('dependencies')
            if not isinstance(dependencies, list):
                self.logger.warning(f"Module '{module_name}': 'dependencies' must be a list")
                return False
            
            # Check for invalid dependencies
            for dep in dependencies:
                if not isinstance(dep, str):
                    self.logger.warning(f"Module '{module_name}': dependency '{dep}' must be a string")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Error validating module '{module_name}' config: {e}")
            return False
    
    def validate_module_result(self, result: Any, module_name: str) -> Tuple[bool, str]:
        """Validate module result with improved checks"""
        try:
            if result is None:
                return False, "Module returned None"
            
            if isinstance(result, dict):
                if not result:  # Empty dict is acceptable
                    return True, ""
                    
                # Check for error indicators
                if 'error' in result and result.get('error'):
                    return False, f"Module returned error: {result['error']}"
                
                # Check for status indicators
                status = result.get('_status')
                if status in ['failed', 'error']:
                    error_msg = result.get('_error', 'Unknown error')
                    return False, f"Module status failed: {error_msg}"
                
                # Validate data structure for known modules
                return self._validate_module_data_structure(result, module_name)
            
            elif isinstance(result, list):
                if not result:  # Empty list is acceptable
                    return True, ""
                # Lists are generally acceptable for module results
                return True, ""
            
            else:
                # Other types might be valid depending on the module
                self.logger.debug(f"Module {module_name} returned unexpected type: {type(result)}")
                return True, f"Unexpected result type: {type(result)}"
                
        except Exception as e:
            return False, f"Error validating result: {e}"
    
    def _validate_module_data_structure(self, result: dict, module_name: str) -> Tuple[bool, str]:
        """Validate data structure for specific modules"""
        try:
            if module_name == 'ssh':
                expected_keys = ['private_keys', 'public_keys', 'ssh_agent', 'known_hosts', 'config_files', 'authorized_keys']
                missing_keys = [key for key in expected_keys if key not in result]
                if missing_keys:
                    return False, f"SSH module missing keys: {missing_keys}"
                    
            elif module_name == 'browser':
                expected_browsers = ['chrome', 'firefox', 'brave', 'chromium']
                missing_browsers = [browser for browser in expected_browsers if browser not in result]
                if missing_browsers:
                    self.logger.debug(f"Browser module missing browsers: {missing_browsers}")
                    
            elif module_name == 'keyring':
                expected_keys = ['gnome_keyring', 'kwallet', 'secret_tool', 'available_keyrings']
                missing_keys = [key for key in expected_keys if key not in result]
                if missing_keys:
                    return False, f"Keyring module missing keys: {missing_keys}"
            
            return True, ""
            
        except Exception as e:
            return True, f"Validation error: {e}"  # Don't fail on validation errors
    
    def run_module_safe(self, module_name: str) -> ModuleResult:
        """Safely execute a module with extended error handling and thread safety."""
        start_time = datetime.now()
        
        try:
            self.logger.log_module_start(module_name)
            
            if module_name not in self.modules:
                error_msg = f"Unknown module: {module_name}"
                self.logger.error(error_msg)
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            module_info = self.modules[module_name]
            
            # Check if module is enabled
            if not module_info.get('enabled', True):
                reason = 'module_disabled_in_config'
                self.logger.log_module_skip(module_name, reason)
                return ModuleResult(module_name, 'skipped', skipped_reason=reason)
            
            # Check privileges
            if module_info['requires_privileges'] and os.geteuid() != 0:
                reason = 'requires_root_privileges'
                self.logger.log_module_skip(module_name, reason)
                return ModuleResult(module_name, 'skipped', skipped_reason=reason)
            
            # Initialize module with error handling
            try:
                module_class = module_info['class']
                module_instance = module_class(self.config)
                method = getattr(module_instance, module_info['method'])
            except Exception as e:
                error_msg = f"Initialization failed: {str(e)}"
                self.logger.log_module_error(module_name, e)
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            # Execute with appropriate locking and timeout
            try:
                timeout = module_info.get('timeout', 300)
                
                if module_info['parallel_safe']:
                    # For parallel_safe modules, use simple execution
                    result = method()
                else:
                    # For non-parallel-safe modules, use locking
                    with self.lock:
                        result = method()
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Validate result
                is_valid, validation_error = self.validate_module_result(result, module_name)
                
                if not is_valid:
                    error_msg = f"Validation failed: {validation_error}"
                    self.logger.error(f"Module {module_name} validation failed: {validation_error}")
                    return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
                
                # Count findings for logging
                findings_count = self._count_findings(result)
                
                # Store result with thread safety
                with self.results_lock:
                    self.results[module_name] = result
                
                self.logger.log_module_success(module_name, execution_time, findings_count)
                return ModuleResult(module_name, 'success', data=result, execution_time=execution_time)
                
            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                error_msg = f"Execution failed: {str(e)}"
                self.logger.log_module_error(module_name, e, execution_time)
                return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
                
        except Exception as e:
            # Critical error at runner level
            execution_time = (datetime.now() - start_time).total_seconds()
            error_msg = f"Critical error in module runner: {str(e)}"
            self.logger.critical(f"Critical error in module runner for {module_name}: {e}")
            self.logger.exception("Full traceback of critical error")
            return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
    
    def _count_findings(self, result) -> int:
        """Count findings in module result"""
        try:
            if isinstance(result, list):
                return len(result)
            elif isinstance(result, dict):
                count = 0
                for value in result.values():
                    if isinstance(value, list):
                        count += len(value)
                    elif isinstance(value, dict) and 'items' in value:
                        if isinstance(value['items'], list):
                            count += len(value['items'])
                    elif value:
                        count += 1
                return count
            else:
                return 1 if result else 0
        except Exception:
            return 0
    
    def _topological_sort(self, module_names: List[str]) -> List[str]:
        """Perform topological sort on modules based on dependencies with improved error handling."""
        modules = self.modules
        graph = {name: set(modules[name]['dependencies']) for name in module_names}
        in_degree = {name: 0 for name in module_names}
        
        # Calculate in-degree and validate dependencies
        for module_name in module_names:
            for dep in modules[module_name]['dependencies']:
                if dep not in module_names:
                    # Check if dependency exists at all in our module registry
                    if dep not in modules:
                        raise ValueError(f"Missing dependency module '{dep}' required by '{module_name}'. Available modules: {list(modules.keys())}")
                    # If the dependency exists but is not in the current run, skip it
                    # This allows running partial sets of modules
                    self.logger.debug(f"Dependency '{dep}' for module '{module_name}' not in current execution set")
                    continue
                # Increment in_degree for the module that has the dependency
                in_degree[module_name] += 1
        
        # Start with modules that have no dependencies
        queue = [name for name, deg in in_degree.items() if deg == 0]
        order = []
        
        while queue:
            node = queue.pop(0)
            order.append(node)
            
            # For each module that depends on the current node, decrement its in_degree
            for module_name in module_names:
                if node in graph[module_name]:
                    graph[module_name].remove(node)
                    in_degree[module_name] -= 1
                    if in_degree[module_name] == 0:
                        queue.append(module_name)
        
        if len(order) != len(module_names):
            remaining = set(module_names) - set(order)
            unsatisfied_deps = {}
            for module in remaining:
                unsatisfied_deps[module] = [dep for dep in modules[module]['dependencies'] if dep in module_names and dep not in order]
            raise ValueError(f"Dependency cycle detected or unsatisfied dependencies. Remaining modules: {remaining}. Unsatisfied dependencies: {unsatisfied_deps}")
        
        return order

    def get_execution_order(self, module_names: List[str], strategy: str = ExecutionStrategy.PRIORITY_BASED, 
                           custom_order: List[str] = None) -> List[str]:
        """Get module execution order based on strategy with improved validation"""
        valid_modules = [name for name in module_names if name in self.modules]
        
        if not valid_modules:
            raise ValueError(f"No valid modules found in request: {module_names}. Available: {list(self.modules.keys())}")
        
        # Log any invalid modules
        invalid_modules = [name for name in module_names if name not in self.modules]
        if invalid_modules:
            self.logger.warning(f"Invalid modules requested (will be skipped): {invalid_modules}")
        
        if strategy == ExecutionStrategy.CUSTOM_ORDER and custom_order:
            ordered = []
            for module in custom_order:
                if module in valid_modules:
                    ordered.append(module)
            # Add any remaining modules not in custom order
            for module in valid_modules:
                if module not in ordered:
                    ordered.append(module)
            return ordered
            
        elif strategy == ExecutionStrategy.TIME_OPTIMIZED:
            # Use dependency graph, but prioritize fast modules when possible
            try:
                order = self._topological_sort(valid_modules)
            except Exception as e:
                self.logger.error(f"Dependency error: {e}")
                raise
            # Group by ready modules and prioritize fast
            ready = set()
            completed = set()
            remaining = set(order)
            result = []
            while remaining:
                # Find all modules whose deps are completed
                ready = [m for m in remaining if all(dep in completed or dep not in valid_modules for dep in self.modules[m]['dependencies'])]
                if not ready:
                    raise ValueError("No modules ready to run, but not all completed. Possible dependency cycle.")
                # Prioritize fast, then medium, then slow
                time_priority_map = {'fast': 0, 'medium': 1, 'slow': 2}
                ready.sort(key=lambda m: (time_priority_map.get(self.modules[m]['estimated_time'], 1), order.index(m)))
                for m in ready:
                    result.append(m)
                    completed.add(m)
                    remaining.remove(m)
            return result
            
        elif strategy == ExecutionStrategy.DEPENDENCY_AWARE:
            try:
                return self._topological_sort(valid_modules)
            except Exception as e:
                self.logger.error(f"Dependency error: {e}")
                raise
        else:
            # PRIORITY_BASED - default
            return sorted(valid_modules, key=lambda x: self.modules[x]['priority'])
    
    def run_modules_parallel(self, module_names: List[str], max_workers: int = 3, strategy: str = None) -> Dict[str, ModuleResult]:
        """Parallel execution with dependency and time optimization support and improved error handling."""
        results = {}
        modules = self.modules
        
        # Build dependency graph
        deps = {m: set(modules[m]['dependencies']) for m in module_names if m in modules}
        dependents = {m: set() for m in module_names if m in modules}
        
        for m in module_names:
            if m not in modules:
                continue
            for d in deps[m]:
                if d in dependents:
                    dependents[d].add(m)
        
        # Track ready and running modules
        completed = set()
        running = set()
        futures = {}
        heap = []  # (priority, module_name) for time-optimized
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try:
            while len(completed) < len([m for m in module_names if m in modules]):
                # Find ready modules (deps met, not running or done)
                ready = [m for m in module_names if m in modules and m not in completed and m not in running 
                        and all(d in completed or d not in module_names for d in deps[m])]
                
                if not ready and not running:
                    break  # Deadlock or done
                
                # For time-optimized, prioritize fast modules
                if strategy == ExecutionStrategy.TIME_OPTIMIZED:
                    for m in ready:
                        # Convert string priorities to numeric for proper heap ordering
                        time_priority = {'fast': 0, 'medium': 1, 'slow': 2}.get(modules[m]['estimated_time'], 1)
                        heapq.heappush(heap, (time_priority, m))
                    
                    while heap and len(running) < max_workers:
                        _, m = heapq.heappop(heap)
                        f = executor.submit(self.run_module_safe, m)
                        futures[f] = m
                        running.add(m)
                else:
                    for m in ready:
                        if len(running) < max_workers:
                            f = executor.submit(self.run_module_safe, m)
                            futures[f] = m
                            running.add(m)
                
                # Wait for any module to finish with a reasonable timeout
                if futures:
                    try:
                        done, running_futures = concurrent.futures.wait(
                            futures, 
                            return_when=concurrent.futures.FIRST_COMPLETED,
                            timeout=30  # 30 second check interval
                        )
                        
                        # Handle completed modules
                        for f in done:
                            m = futures[f]
                            try:
                                result = f.result()
                            except Exception as e:
                                self.logger.error(f"Parallel execution error for {m}: {e}")
                                result = ModuleResult(m, 'failed', error=f"Parallel execution error: {str(e)}")
                            results[m] = result
                            completed.add(m)
                            running.remove(m)
                            del futures[f]
                        
                        # Check for modules that have exceeded their individual timeouts
                        current_time = datetime.now()
                        for f in list(running_futures):
                            m = futures[f]
                            module_timeout = modules[m]['timeout']
                            # Note: This is a simplified timeout check. In a production system,
                            # you'd want to track the start time of each future
                            # For now, we rely on the module's internal timeout handling
                            
                    except concurrent.futures.TimeoutError:
                        # This shouldn't happen with our setup, but handle it gracefully
                        self.logger.debug("Wait timeout in parallel execution (this is normal)")
                        continue
                else:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in parallel execution: {e}")
        finally:
            executor.shutdown(wait=True)
        
        # Run any sequential modules (not parallel_safe) with proper dependency ordering
        sequential_modules = [m for m in module_names if m in modules and not modules[m]['parallel_safe'] and m not in results]
        if sequential_modules:
            # Get proper dependency order for sequential modules
            try:
                sequential_order = self._topological_sort(sequential_modules)
                for m in sequential_order:
                    # Check if dependencies have been satisfied
                    deps_satisfied = all(dep in results or dep not in module_names for dep in modules[m]['dependencies'])
                    if deps_satisfied:
                        results[m] = self.run_module_safe(m)
                    else:
                        missing_deps = [dep for dep in modules[m]['dependencies'] if dep in module_names and dep not in results]
                        error_msg = f"Sequential module {m} has unsatisfied dependencies: {missing_deps}"
                        self.logger.error(error_msg)
                        results[m] = ModuleResult(m, 'failed', error=error_msg)
            except Exception as e:
                # If dependency sorting fails, run them in config order but log the issue
                self.logger.warning(f"Failed to sort sequential modules by dependencies: {e}. Running in config order.")
                for m in sequential_modules:
                    results[m] = self.run_module_safe(m)
        
        # Handle any modules that were invalid/not found
        for m in module_names:
            if m not in modules and m not in results:
                error_msg = f"Unknown module: {m}"
                self.logger.error(error_msg)
                results[m] = ModuleResult(m, 'failed', error=error_msg)
        
        return results
    
    def run_modules_sequential(self, module_names: List[str]) -> Dict[str, ModuleResult]:
        """Sequential execution of modules with improved error handling"""
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
    """Main class for credfinder-linux application."""
    
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
        """Main scan method with flexible management."""
        
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
                # Preserve partial data if available
                if result.data:
                    self.results[module_name] = {
                        '_partial_data': result.data,
                        '_status': 'failed',
                        '_error': result.error
                    }
                else:
                    self.results[module_name] = {
                        '_status': 'failed',
                        '_error': result.error
                    }
                # Ошибка уже залогирована в run_module_safe
            elif result.status == 'skipped':
                self.execution_stats['skipped_modules'] += 1
                self.results[module_name] = {
                    '_status': 'skipped',
                    '_reason': result.skipped_reason
                }
                # Пропуск уже залогирован в run_module_safe
            elif result.status == 'timeout':
                self.execution_stats['timeout_modules'] += 1
                # Preserve partial data if available from timeout
                if result.data:
                    self.results[module_name] = {
                        '_partial_data': result.data,
                        '_status': 'timeout',
                        '_error': 'Module execution timed out'
                    }
                else:
                    self.results[module_name] = {
                        '_status': 'timeout',
                        '_error': 'Module execution timed out'
                    }
                # Таймаут уже залогирован в run_module_safe
        
        return self.results
    
    def generate_report(self, format_type="json"):
        """Generate report in specified format"""
        self.logger.info(f"Generating {format_type} report...")
        try:
            generator = ReportGenerator(self.config)
            result_paths = generator.generate_reports(self.results, [format_type])
            if result_paths:
                result = result_paths[0]  # Return the first (and only) generated report path
                self.logger.success(f"Report generated successfully: {format_type}")
                return result
            else:
                raise Exception(f"No {format_type} report was generated")
        except Exception as e:
            self.logger.error(f"Failed to generate {format_type} report: {e}")
            self.logger.exception("Full traceback for report generation error")
            raise
    
    def compress_output_dir(self, output_dir: str) -> str:
        """Compress the output directory into a zip archive and return the archive path."""
        base_dir = os.path.abspath(output_dir)
        archive_path = base_dir + ".zip"
        shutil.make_archive(base_dir, 'zip', base_dir)
        self.logger.success(f"Output directory compressed to: {archive_path}")
        return archive_path
    
    def save_results(self, output_dir="./reports"):
        """Safely save results with extended checks. Compress if enabled in config."""
        try:
            self.logger.info(f"Saving results to {output_dir}")
            
            # Валидация пути
            allowed_dirs = self.config.get("security", {}).get("allowed_output_dirs", ["./reports"])
            output_path = self.fs_manager.validate_output_path(output_dir, allowed_dirs)
            
            # Создание директории (move this up before disk space check)
            if not output_path.exists():
                dir_mode = int(self.config.get("security", {}).get("safe_dir_permissions", "0o750"), 8)
                self.fs_manager.safe_create_directory(output_path, dir_mode)
            
            # Проверка свободного места (after directory exists)
            min_free_space_bytes = self.config.get("security", {}).get("min_free_space", 104857600)
            self.fs_manager.check_disk_space(output_path, min_free_space_bytes)
            
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
            # Optionally compress output directory
            compress = self.config.get("output", {}).get("compress_results", False)
            archive_path = None
            if compress:
                archive_path = self.compress_output_dir(str(output_path))
            return str(final_path) if not archive_path else archive_path
            
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
    
    # Маппинг стратегий (нормализуем дефисы в подчеркивания)
    strategy_map = {
        'priority': ExecutionStrategy.PRIORITY_BASED,
        'custom': ExecutionStrategy.CUSTOM_ORDER,
        'time-optimized': ExecutionStrategy.TIME_OPTIMIZED,
        'time_optimized': ExecutionStrategy.TIME_OPTIMIZED,  # Support both formats
        'dependency-aware': ExecutionStrategy.DEPENDENCY_AWARE,
        'dependency_aware': ExecutionStrategy.DEPENDENCY_AWARE  # Support both formats
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