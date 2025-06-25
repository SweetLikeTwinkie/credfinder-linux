#!/usr/bin/env python3
"""
Report Orchestrator

Main orchestrator that coordinates all specialized reporting modules.
Provides a unified interface for generating different types of reports while
leveraging the JSON reporter as the central data processing engine.

Key Features:
- Unified interface for all report types
- JSON reporter as the core data processor
- Automatic format detection and validation
- Parallel report generation when requested
- Error handling and fallback reporting

Available Report Types:
- json: Machine-readable JSON output (primary data source)
- csv: Spreadsheet-compatible CSV output
- html: Clean, shareable HTML reports
- console: Terminal output for immediate analysis
- dashboard: Advanced interactive HTML dashboard

Usage:
    orchestrator = ReportOrchestrator(config)
    report_path = orchestrator.generate_report(results, "json", execution_stats)
    
    # Generate multiple formats
    paths = orchestrator.generate_multiple_reports(results, ["json", "html", "csv"])
"""

import os
from typing import Any, Dict, List, Optional, Tuple
from .json_reporter import JsonReporter
from .csv_reporter import CsvReporter
from .html_reporter import HtmlReporter
from .console_reporter import ConsoleReporter
from .extend_html_reporter import ExtendHtmlReporter


class ReportOrchestrator:
    """Main orchestrator for all reporting functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Load configuration
        output_config = config.get("output", {})
        self.output_dir = output_config.get("output_dir", "./reports")
        self.default_format = output_config.get("default_format", "json")
        self.auto_timestamp = output_config.get("auto_timestamp", True)
        
        # Initialize all reporters
        self.reporters = {
            'json': JsonReporter(config),
            'csv': CsvReporter(config),
            'html': HtmlReporter(config),
            'console': ConsoleReporter(config),
            'extend_html': ExtendHtmlReporter(config)
        }
        
        # Supported formats
        self.supported_formats = [k for k in self.reporters.keys() if k != 'dashboard']
    
    def generate_report(self, results: Dict[str, Any], 
                       format_type: str = None,
                       execution_stats: Optional[Dict[str, Any]] = None,
                       custom_filename: Optional[str] = None) -> str:
        """
        Generate a single report in the specified format.
        
        Args:
            results: Scan results from all modules
            format_type: Output format (json, csv, html, console, extend_html)
            execution_stats: Optional execution statistics
            custom_filename: Optional custom filename (without extension)
            
        Returns:
            Path to generated report file or "console" for console output
        """
        # Use default format if none specified
        if format_type is None:
            format_type = self.default_format
        
        # Validate format
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format '{format_type}'. "
                           f"Supported formats: {', '.join(self.supported_formats)}")
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        try:
            # Generate report using appropriate reporter
            if format_type == 'extend_html':
                return self.reporters['extend_html'].generate(results, execution_stats, custom_filename)
            elif format_type == 'console':
                return self.reporters['console'].generate(results, execution_stats)
            else:
                return self.reporters[format_type].generate(results, execution_stats, custom_filename)
                
        except Exception as e:
            raise Exception(f"Failed to generate {format_type} report: {e}")
    

    
    def get_report_summary(self, results: Dict[str, Any],
                          execution_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Get a summary of scan results without generating a full report.
        Uses the JSON reporter's processing logic for consistency.
        
        Args:
            results: Scan results from all modules
            execution_stats: Optional execution statistics
            
        Returns:
            Dictionary with summary statistics and metadata
        """
        try:
            # Use JSON reporter to process data and extract summary
            json_reporter = self.reporters['json']
            report_data = json_reporter._build_report_structure(results, execution_stats)
            
            return {
                'scan_summary': report_data.get('scan_summary', {}),
                'report_info': report_data.get('report_info', {}),
                'module_status': {
                    module_name: {
                        'status': module_data.get('status', 'success'),
                        'finding_count': len(module_data.get('findings', [])),
                        'risk_level': module_data.get('risk_assessment', {}).get('level', 'unknown')
                    }
                    for module_name, module_data in report_data.get('findings', {}).items()
                }
            }
        except Exception as e:
            raise Exception(f"Failed to generate report summary: {e}")
    
    def validate_results(self, results: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate scan results for completeness and structure.
        
        Args:
            results: Scan results from all modules
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Check if results is a dictionary
        if not isinstance(results, dict):
            issues.append("Results must be a dictionary")
            return False, issues
        
        # Check if results is empty
        if not results:
            issues.append("Results dictionary is empty")
            return False, issues
        
        # Check individual modules
        for module_name, module_data in results.items():
            # Check for string module names
            if not isinstance(module_name, str):
                issues.append(f"Module name '{module_name}' must be a string")
            
            # Check for None or completely empty modules
            if module_data is None:
                issues.append(f"Module '{module_name}' has None data")
            
            # Check modules with status information
            if isinstance(module_data, dict) and '_status' in module_data:
                status = module_data['_status']
                if status in ['failed', 'skipped', 'timeout'] and '_error' not in module_data:
                    issues.append(f"Module '{module_name}' has status '{status}' but no error message")
        
        # Report is valid if no critical issues found
        is_valid = len(issues) == 0
        
        return is_valid, issues
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported report formats."""
        return self.supported_formats.copy()
    
    def get_format_description(self, format_type: str) -> str:
        """Get description of a specific report format."""
        descriptions = {
            'json': 'Machine-readable JSON output optimized for automation and API integration',
            'csv': 'Spreadsheet-compatible CSV output for data analysis and filtering',
            'html': 'Clean, shareable HTML reports for human consumption',
            'console': 'Colorized terminal output for immediate analysis',
            'extend_html': 'Placeholder for new extend_html report'
        }
        
        return descriptions.get(format_type, f"Unknown format: {format_type}")
    
    def get_reporter_config(self, format_type: str) -> Dict[str, Any]:
        """Get configuration for a specific reporter."""
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format_type}")
        
        reporter = self.reporters[format_type]
        
        # Extract relevant configuration from the reporter
        config_info = {
            'format': format_type,
            'output_dir': getattr(reporter, 'output_dir', 'Unknown'),
            'timestamp_format': getattr(reporter, 'timestamp_format', 'Unknown')
        }
        
        # Add format-specific configuration
        if format_type == 'json':
            config_info.update({
                'json_indent': getattr(reporter, 'json_indent', 2),
                'include_raw_data': getattr(reporter, 'include_raw_data', False)
            })
        elif format_type == 'csv':
            config_info.update({
                'csv_delimiter': getattr(reporter, 'csv_delimiter', ','),
                'include_header_comments': getattr(reporter, 'include_header_comments', True)
            })
        elif format_type == 'console':
            config_info.update({
                'use_colors': getattr(reporter, 'use_colors', True),
                'max_findings_per_module': getattr(reporter, 'max_findings_per_module', 5),
                'show_remediation': getattr(reporter, 'show_remediation', True)
            })
        
        return config_info
    
    def estimate_report_size(self, results: Dict[str, Any], format_type: str) -> Dict[str, Any]:
        """
        Estimate the size and complexity of a report before generation.
        
        Args:
            results: Scan results from all modules
            format_type: Target report format
            
        Returns:
            Dictionary with size estimates and metrics
        """
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format_type}")
        
        # Use JSON reporter to analyze the data
        json_reporter = self.reporters['json']
        processed_findings = json_reporter._process_findings(results)
        
        # Calculate metrics
        total_findings = sum(len(module.get('findings', [])) for module in processed_findings.values())
        total_modules = len(results)
        
        # Estimate file sizes (rough estimates)
        size_estimates = {
            'json': total_findings * 500 + 2000,  # ~500 bytes per finding + metadata
            'csv': total_findings * 200 + 1000,   # ~200 bytes per finding + headers
            'html': total_findings * 300 + 5000,  # ~300 bytes per finding + styling
            'console': 0,  # No file output
            'extend_html': 0  # No file output
        }
        
        return {
            'total_findings': total_findings,
            'total_modules': total_modules,
            'estimated_file_size_bytes': size_estimates.get(format_type, 0),
            'complexity': 'high' if total_findings > 100 else 'medium' if total_findings > 20 else 'low'
        } 