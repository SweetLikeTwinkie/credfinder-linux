#!/usr/bin/env python3
"""
CredFinder Linux - Reporting Module

Modular reporting system with specialized reporters for different output formats.
Each reporter is optimized for its specific use case while maintaining consistency.

Architecture:
- JSON Reporter: Core data processor that categorizes and structures findings
- All other reporters: Use JSON reporter as their data source for consistency
- Report Orchestrator: Unified interface for coordinating all reporters

Available Reporters:
- ReportOrchestrator: Main interface for generating reports (recommended)
- DashboardGenerator: Rich interactive HTML dashboards with visualizations
- JsonReporter: Machine-readable JSON output for automation
- CsvReporter: Spreadsheet-compatible CSV output for analysis  
- HtmlReporter: Simple HTML reports for sharing
- ConsoleReporter: Terminal output for immediate analysis

Usage:
    # Recommended: Use the orchestrator for unified interface
    from modules.reporting import ReportOrchestrator
    
    orchestrator = ReportOrchestrator(config)
    report_path = orchestrator.generate_report(results, "json")
    
    # Or use specific reporters directly
    from modules.reporting import DashboardGenerator, JsonReporter
    
    json_reporter = JsonReporter(config)
    json_path = json_reporter.generate(results)
    
    dashboard = DashboardGenerator(config)
    dashboard_path = dashboard.generate_dashboard(results)
"""

from .report_orchestrator import ReportOrchestrator
from .json_reporter import JsonReporter
from .csv_reporter import CsvReporter
from .html_reporter import HtmlReporter
from .console_reporter import ConsoleReporter

__all__ = [
    'ReportOrchestrator',  # Main interface (recommended)
    'JsonReporter', 
    'CsvReporter',
    'HtmlReporter',
    'ConsoleReporter'
]

# Version and metadata
__version__ = "2.0.0"
__description__ = "Modular reporting system for credential findings"

# Convenience function for quick report generation
def generate_report(results, config, format_type="json", execution_stats=None):
    """
    Convenience function for quick report generation.
    
    Args:
        results: Scan results from all modules
        config: Configuration dictionary
        format_type: Output format (json, csv, html, console, dashboard)
        execution_stats: Optional execution statistics
        
    Returns:
        Path to generated report file or "console" for console output
    """
    orchestrator = ReportOrchestrator(config)
    return orchestrator.generate_report(results, format_type, execution_stats) 