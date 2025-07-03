#!/usr/bin/env python3
"""
credfinder-linux — Main Entry Point
Linux Credential & Secret Hunting Toolkit
"""

import argparse
import json
import os
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import traceback

# Import modules
from modules.ssh_scanner import SSHScanner
from modules.browser_extractor import BrowserExtractor
from modules.keyring_dump import KeyringDump
from modules.file_grepper import FileGrepper
from modules.dotfile_scanner import DotfileScanner
from modules.history_parser import HistoryParser
from modules.git_scanner import GitScanner
from modules.reporting import ReportOrchestrator
from modules.utils.logger import Logger, get_logger
from modules.utils.config_loader import ConfigLoader


class ModuleResult:
    """Structured result of module execution"""
    def __init__(self, module_name: str, status: str, data: Any = None, 
                 error: str = None, execution_time: float = 0.0):
        self.module_name = module_name
        self.status = status  # success, failed, skipped
        self.data = data if data is not None else {}
        self.error = error
        self.execution_time = execution_time
        self.timestamp = datetime.now()
    

    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'module_name': self.module_name,
            'status': self.status,
            'data': self.data,
            'error': self.error,
            'execution_time': self.execution_time,
            'timestamp': self.timestamp.isoformat()
        }


class ModuleRunner:
    """Simplified module execution manager."""
    
    def __init__(self, config, logger: Logger):
        self.config = config
        self.logger = logger
        self.results = {}
        
        # Map module names to their classes and methods
        self.module_classes = {
            'ssh': {'class': SSHScanner, 'method': 'scan'},
            'dotfiles': {'class': DotfileScanner, 'method': 'scan'},
            'history': {'class': HistoryParser, 'method': 'parse'},
            'browser': {'class': BrowserExtractor, 'method': 'extract_all'},
            'file_grep': {'class': FileGrepper, 'method': 'scan'},
            'keyring': {'class': KeyringDump, 'method': 'extract_credentials'},
            'git': {'class': GitScanner, 'method': 'scan'}
        }
        
    def run_module_safe(self, module_name: str) -> ModuleResult:
        """Safely execute a module with error handling."""
        start_time = datetime.now()
        
        try:
            self.logger.info(f"Starting module: {module_name}")
            
            if module_name not in self.module_classes:
                error_msg = f"Unknown module: {module_name}"
                self.logger.error(error_msg)
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            module_info = self.module_classes[module_name]
            
            # Initialize module
            try:
                module_class = module_info['class']
                module_instance = module_class(self.config)
                method = getattr(module_instance, module_info['method'])
            except Exception as e:
                error_msg = f"Initialization failed: {str(e)}"
                self.logger.error(f"Module {module_name} init error: {e}")
                return ModuleResult(module_name, 'failed', error=error_msg)
            
            # Execute module
            try:
                result = method()
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Store result - REMOVED: Race condition fix
                # Results are now passed via ModuleResult.data instead of shared dictionary
                
                findings_count = self._count_findings(result)
                self.logger.info(f"Module {module_name} completed successfully in {execution_time:.2f}s with {findings_count} findings")
                return ModuleResult(module_name, 'success', data=result, execution_time=execution_time)
                
            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                error_msg = f"Execution failed: {str(e)}"
                self.logger.error(f"Module {module_name} execution error: {e}")
                return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
                
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            error_msg = f"Critical error: {str(e)}"
            self.logger.error(f"Critical error in module {module_name}: {e}")
            return ModuleResult(module_name, 'failed', error=error_msg, execution_time=execution_time)
    
    def _count_findings(self, result) -> int:
        """Count findings in module result with consistent logic"""
        try:
            if isinstance(result, list):
                return len(result)
            elif isinstance(result, dict):
                count = 0
                for key, value in result.items():
                    # Skip internal status keys
                    if key.startswith('_') or key in ['scan_stats', 'metadata']:
                        continue
                    
                    if isinstance(value, list):
                        count += len(value)
                    elif isinstance(value, dict):
                        # Check for items pattern (keyring module)
                        if 'items' in value and isinstance(value['items'], list):
                            count += len(value['items'])
                        # Check for nested findings
                        else:
                            nested_count = self._count_findings(value)
                            if nested_count > 0:
                                count += nested_count
                    # BUGFIX: Don't count non-list/non-dict values as individual findings
                    # These are usually metadata or configuration
                return count
            else:
                return 1 if result else 0
        except Exception:
            return 0
    
    def run_modules_parallel(self, module_names: List[str], max_workers: int = 3) -> Dict[str, ModuleResult]:
        """Run modules in parallel"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_module = {executor.submit(self.run_module_safe, module): module 
                              for module in module_names}
            
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    results[module_name] = result
                except Exception as e:
                    self.logger.error(f"Parallel execution error for {module_name}: {e}")
                    results[module_name] = ModuleResult(module_name, 'failed', error=f"Parallel execution error: {str(e)}")
        
        return results
    
    def run_modules_sequential(self, module_names: List[str]) -> Dict[str, ModuleResult]:
        """Run modules sequentially"""
        results = {}
        
        for module_name in module_names:
            self.logger.info(f"Running module: {module_name}")
            results[module_name] = self.run_module_safe(module_name)
        
        return results


class CredFinder:
    """Main class for credfinder-linux application."""
    
    def __init__(self, config_path="config.json"):
        self.config = ConfigLoader(config_path)
        
        # Setup logger
        log_config = self.config.get("logging", {})
        opsec_config = self.config.get("opsec", {})
        
        self.logger = get_logger(
            name="credfinder",
            minimal_logging=opsec_config.get("minimal_logging", False),
            log_level=log_config.get("level", "INFO")
        )
        
        self.module_runner = ModuleRunner(self.config, self.logger)
        self.results = {}
        self.execution_stats = {}
        
    def run_scan(self, modules: List[str], parallel: bool = True, max_workers: int = 3) -> Dict[str, Any]:
        """Main scan method."""
        
        self.logger.info(f"Starting scan with modules: {', '.join(modules)}")
        self.logger.info(f"Execution mode: {'parallel' if parallel else 'sequential'}")
        
        # Execute modules
        if parallel:
            module_results = self.module_runner.run_modules_parallel(modules, max_workers)
        else:
            module_results = self.module_runner.run_modules_sequential(modules)
        
        # Process results
        self.results = {}
        self.execution_stats = {
            'total_modules': len(modules),
            'successful_modules': 0,
            'failed_modules': 0,
            'total_execution_time': 0.0,
            'module_details': {}
        }
        
        # Check if we should include execution data
        include_execution_data = self.config.get("output", {}).get("include_execution_data", True)
        
        for module_name, result in module_results.items():
            # Save statistics (with or without raw data)
            if include_execution_data:
                self.execution_stats['module_details'][module_name] = result.to_dict()
            else:
                # Only include basic stats, not the full data
                self.execution_stats['module_details'][module_name] = {
                    'module_name': result.module_name,
                    'status': result.status,
                    'error': result.error,
                    'execution_time': result.execution_time,
                    'timestamp': result.timestamp.isoformat()
                }
            
            self.execution_stats['total_execution_time'] += result.execution_time
            
            if result.status == 'success':
                self.execution_stats['successful_modules'] += 1
                self.results[module_name] = result.data
            elif result.status == 'failed':
                self.execution_stats['failed_modules'] += 1
                self.results[module_name] = {
                    '_status': 'failed',
                    '_error': result.error
                }
        
        return self.results
    
    def generate_report(self, format_type="json"):
        """Generate report in specified format"""
        self.logger.info(f"Generating {format_type} report...")
        try:
            orchestrator = ReportOrchestrator(self.config)
            result_path = orchestrator.generate_report(self.results, format_type, self.execution_stats)
            self.logger.info(f"Report generated successfully: {result_path}")
            return result_path
        except Exception as e:
            self.logger.error(f"Failed to generate {format_type} report: {e}")
            raise
    



def main():
    parser = argparse.ArgumentParser(
        description="credfinder-linux — Linux Credential & Secret Hunting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --modules ssh browser --parallel
  python3 main.py --modules ssh browser --sequential  
  python3 main.py --all --max-workers 5
  python3 main.py --fast-only
        """
    )
    
    # Module selection
    parser.add_argument("--all", action="store_true", help="Run all available modules")
    parser.add_argument("--modules", nargs='+', 
                       choices=['ssh', 'browser', 'keyring', 'file_grep', 'dotfiles', 'history', 'git'],
                       help="Specific modules to run")
    parser.add_argument("--fast-only", action="store_true", 
                       help="Run only fast modules (ssh, dotfiles, history)")
    
    # Execution control
    parser.add_argument("--parallel", action="store_true", default=True,
                       help="Run modules in parallel (default)")
    parser.add_argument("--sequential", action="store_true",
                       help="Run modules sequentially")
    parser.add_argument("--max-workers", type=int, default=3,
                       help="Maximum number of parallel workers")
    
    # Other options
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    parser.add_argument("--report", choices=["json", "html", "console", "csv", "extend_html"], 
                       default="json", help="Report format")
    parser.add_argument("--output-dir", default="./reports", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Validate config file exists
    if not os.path.exists(args.config):
        print(f"Config file '{args.config}' not found.", file=sys.stderr)
        sys.exit(1)
    
    # Initialize CredFinder
    try:
        credfinder = CredFinder(args.config)
        
        # Set logging level
        if args.debug:
            credfinder.logger.set_level("DEBUG")
        elif args.verbose:
            credfinder.logger.set_level("INFO")
            
    except Exception as e:
        print(f"Failed to initialize CredFinder: {e}", file=sys.stderr)
        if args.verbose or args.debug:
            traceback.print_exc()
        sys.exit(1)
    
    # Determine which modules to run
    if args.all:
        modules_to_run = ['ssh', 'browser', 'keyring', 'file_grep', 'dotfiles', 'history', 'git']
    elif args.fast_only:
        modules_to_run = ['ssh', 'dotfiles', 'history', 'git']
    elif args.modules:
        modules_to_run = args.modules
    else:
        credfinder.logger.error("No modules selected. Use --all, --fast-only, or --modules.")
        sys.exit(1)
    
    # Configure execution
    parallel = not args.sequential
    
    try:
        # Run scan
        credfinder.logger.info(f"Starting scan with modules: {', '.join(modules_to_run)}")
        
        start_time = datetime.now()
        results = credfinder.run_scan(modules_to_run, parallel=parallel, max_workers=args.max_workers)
        end_time = datetime.now()
        
        total_execution_time = (end_time - start_time).total_seconds()
        
        # Generate report using new ReportOrchestrator
        try:
            report_path = credfinder.generate_report(args.report)
            credfinder.logger.info(f"Report generated: {report_path}")
        
        except Exception as e:
            credfinder.logger.error(f"Failed to generate report: {e}")
        
        # Print summary
        stats = credfinder.execution_stats
        successful = stats['successful_modules']
        failed = stats['failed_modules']
        total = stats['total_modules']
        
        print(f"\n=== Execution Summary ===")
        print(f"Total modules: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Total execution time: {total_execution_time:.2f}s")
        
        if results:
            total_findings = 0
            for module, data in results.items():
                if data and not module.startswith('_'):
                    if isinstance(data, list):
                        total_findings += len(data)
                    elif isinstance(data, dict):
                        total_findings += sum(len(v) if isinstance(v, list) else 1 for v in data.values() if v)
            
            print(f"Total findings: {total_findings}")
            if 'report_path' in locals():
                print(f"Report generated: {report_path}")
        
        if args.verbose and stats['module_details']:
            print(f"\n=== Module Details ===")
            for module, details in stats['module_details'].items():
                status = details['status']
                exec_time = details['execution_time']
                print(f"{module}: {status} ({exec_time:.2f}s)")
                if details['error']:
                    print(f"  Error: {details['error']}")
        
        # Exit with appropriate code
        if successful == 0:
            print("Warning: No modules completed successfully")
            sys.exit(2)
        else:
            print("Scan completed successfully!")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        credfinder.logger.error(f"Scan failed: {e}")
        print(f"Scan failed: {e}")
        if args.verbose or args.debug:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 