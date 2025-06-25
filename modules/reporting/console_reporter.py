#!/usr/bin/env python3
"""
Console Reporter

Terminal output reporter that provides clean, immediate analysis in the console.
Uses JSON reporter as the data source for consistent processing and categorization.

Key Features:
- Clean, colorized terminal output
- Hierarchical display of findings
- Risk-based prioritization
- Summary statistics
- Uses structured data from JSON reporter

Usage:
    console_reporter = ConsoleReporter(config)
    console_reporter.generate(results, execution_stats)
"""

import sys
from typing import Any, Dict, List, Optional
from .json_reporter import JsonReporter


class ConsoleReporter:
    """Terminal output reporter for immediate analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Load configuration
        output_config = config.get("output", {})
        self.use_colors = output_config.get("use_colors", True)
        self.max_findings_per_module = output_config.get("max_findings_per_module", 5)
        self.show_remediation = output_config.get("show_remediation", True)
        
        # Initialize JSON reporter as data source
        self.json_reporter = JsonReporter(config)
        
        # Color codes (only used if colors are enabled)
        self.colors = {
            'red': '\033[91m',
            'yellow': '\033[93m', 
            'blue': '\033[94m',
            'green': '\033[92m',
            'cyan': '\033[96m',
            'magenta': '\033[95m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'underline': '\033[4m',
            'reset': '\033[0m'
        } if self.use_colors and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() else {
            key: '' for key in ['red', 'yellow', 'blue', 'green', 'cyan', 'magenta', 'white', 'bold', 'underline', 'reset']
        }
    
    def generate(self, results: Dict[str, Any], 
                execution_stats: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate console output using JSON reporter data.
        
        Args:
            results: Scan results from all modules
            execution_stats: Optional execution statistics
            
        Returns:
            "console" to indicate console output was generated
        """
        # Get structured data from JSON reporter
        report_data = self.json_reporter._build_report_structure(results, execution_stats)
        
        # Display console output
        self._display_header(report_data.get('report_info', {}))
        self._display_summary(report_data.get('scan_summary', {}))
        self._display_findings(report_data.get('findings', {}))
        self._display_footer(report_data.get('scan_summary', {}))
        
        return "console"
    
    def _display_header(self, report_info: Dict[str, Any]) -> None:
        """Display header with tool information."""
        c = self.colors
        
        print(f"\n{c['bold']}{c['cyan']}{'='*70}{c['reset']}")
        print(f"{c['bold']}{c['cyan']}🔍 CREDFINDER LINUX - CREDENTIAL SCAN RESULTS{c['reset']}")
        print(f"{c['bold']}{c['cyan']}{'='*70}{c['reset']}")
        
        generated_at = report_info.get('generated_at', 'Unknown')
        if generated_at != 'Unknown':
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                print(f"{c['white']}Scan completed: {formatted_time}{c['reset']}")
            except:
                print(f"{c['white']}Scan completed: {generated_at}{c['reset']}")
        
        print()
    
    def _display_summary(self, scan_summary: Dict[str, Any]) -> None:
        """Display summary statistics."""
        c = self.colors
        
        total_findings = scan_summary.get('total_findings', 0)
        critical_findings = scan_summary.get('critical_findings', 0)
        total_modules = scan_summary.get('total_modules', 0)
        successful_modules = scan_summary.get('successful_modules', 0)
        execution_time = scan_summary.get('execution_time_seconds', 'N/A')
        
        print(f"{c['bold']}{c['blue']}📊 SCAN SUMMARY{c['reset']}")
        print(f"{c['blue']}{'─'*40}{c['reset']}")
        
        # Color-code findings based on criticality
        findings_color = c['red'] if critical_findings > 0 else c['yellow'] if total_findings > 0 else c['green']
        
        print(f"  {c['white']}Total Findings:{c['reset']} {findings_color}{total_findings}{c['reset']}")
        if critical_findings > 0:
            print(f"  {c['white']}Critical Findings:{c['reset']} {c['bold']}{c['red']}⚠️  {critical_findings}{c['reset']}")
        
        print(f"  {c['white']}Modules Executed:{c['reset']} {c['green']}{successful_modules}{c['reset']}/{c['blue']}{total_modules}{c['reset']}")
        
        if execution_time != 'N/A':
            print(f"  {c['white']}Execution Time:{c['reset']} {c['cyan']}{execution_time}s{c['reset']}")
        
        print()
    
    def _display_findings(self, findings: Dict[str, Any]) -> None:
        """Display findings by module."""
        c = self.colors
        
        print(f"{c['bold']}{c['blue']}🔍 FINDINGS BY MODULE{c['reset']}")
        print(f"{c['blue']}{'─'*40}{c['reset']}")
        
        # Sort modules by criticality (modules with critical findings first)
        sorted_modules = sorted(
            findings.items(),
            key=lambda x: (
                -len([f for f in x[1].get('findings', []) if f.get('severity') == 'critical']),
                -len(x[1].get('findings', []))
            )
        )
        
        for module_name, module_data in sorted_modules:
            self._display_module_findings(module_name, module_data)
        
        print()
    
    def _display_module_findings(self, module_name: str, module_data: Dict[str, Any]) -> None:
        """Display findings for a specific module."""
        c = self.colors
        
        module_findings = module_data.get('findings', [])
        finding_count = len(module_findings)
        status = module_data.get('status', 'success')
        risk_assessment = module_data.get('risk_assessment', {})
        
        # Module header with status indicator
        status_indicator = self._get_status_indicator(status, finding_count)
        print(f"\n{c['bold']}{c['magenta']}▶ {module_name.upper()} MODULE{c['reset']} {status_indicator}")
        
        if status == 'error':
            error_msg = module_data.get('error_message', 'Unknown error')
            print(f"  {c['red']}❌ Error: {error_msg}{c['reset']}")
            return
        
        if not module_findings:
            print(f"  {c['green']}✅ No credential findings detected{c['reset']}")
            return
        
        # Show risk assessment
        risk_level = risk_assessment.get('level', 'unknown')
        risk_color = self._get_risk_color(risk_level)
        print(f"  {c['white']}Risk Level:{c['reset']} {risk_color}{risk_level.upper()}{c['reset']} "
              f"({finding_count} findings)")
        
        # Show top findings (limited for readability)
        displayed_findings = 0
        critical_findings = [f for f in module_findings if f.get('severity') == 'critical']
        other_findings = [f for f in module_findings if f.get('severity') != 'critical']
        
        # Show critical findings first
        for finding in critical_findings:
            if displayed_findings >= self.max_findings_per_module:
                break
            self._display_finding(finding, "  ")
            displayed_findings += 1
        
        # Show other findings
        for finding in other_findings:
            if displayed_findings >= self.max_findings_per_module:
                break
            self._display_finding(finding, "  ")
            displayed_findings += 1
        
        # Show count of remaining findings
        remaining = finding_count - displayed_findings
        if remaining > 0:
            print(f"  {c['cyan']}... and {remaining} more findings (see full report for details){c['reset']}")
    
    def _display_finding(self, finding: Dict[str, Any], indent: str) -> None:
        """Display individual finding."""
        c = self.colors
        
        finding_type = finding.get('type', 'Unknown').replace('_', ' ').title()
        severity = finding.get('severity', 'info')
        details = finding.get('details', {})
        risk_score = finding.get('risk_score', 0)
        
        # Severity indicator and color
        severity_indicator = self._get_severity_indicator(severity)
        severity_color = self._get_severity_color(severity)
        
        print(f"{indent}{severity_indicator} {severity_color}{finding_type}{c['reset']} "
              f"(Risk: {risk_score}/10)")
        
        # Show key details
        key_details = self._extract_key_details(details)
        for detail in key_details:
            print(f"{indent}  {c['white']}• {detail}{c['reset']}")
        
        # Show remediation if enabled and available
        if self.show_remediation and finding.get('remediation'):
            remediation = finding.get('remediation')
            print(f"{indent}  {c['green']}💡 {remediation}{c['reset']}")
    
    def _extract_key_details(self, details: Dict[str, Any]) -> List[str]:
        """Extract key details for display."""
        key_details = []
        
        # Priority order for details
        priority_keys = ['path', 'file', 'url', 'service', 'username', 'encrypted', 'browser']
        
        for key in priority_keys:
            if key in details and details[key] and str(details[key]) != 'Unknown':
                value = details[key]
                if isinstance(value, bool):
                    value = "Yes" if value else "No"
                key_details.append(f"{key.replace('_', ' ').title()}: {value}")
        
        # Add other important details (limit to avoid clutter)
        other_keys = [k for k in details.keys() if k not in priority_keys][:2]
        for key in other_keys:
            if details[key] and str(details[key]) != 'Unknown':
                value = str(details[key])
                if len(value) > 50:
                    value = value[:47] + "..."
                key_details.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return key_details[:4]  # Limit to 4 details for readability
    
    def _display_footer(self, scan_summary: Dict[str, Any]) -> None:
        """Display footer with recommendations."""
        c = self.colors
        
        total_findings = scan_summary.get('total_findings', 0)
        critical_findings = scan_summary.get('critical_findings', 0)
        
        print(f"{c['bold']}{c['cyan']}{'='*70}{c['reset']}")
        
        if critical_findings > 0:
            print(f"{c['bold']}{c['red']}⚠️  CRITICAL: {critical_findings} high-risk findings require immediate attention!{c['reset']}")
        elif total_findings > 0:
            print(f"{c['bold']}{c['yellow']}⚠️  REVIEW: {total_findings} findings detected - review and secure credentials{c['reset']}")
        else:
            print(f"{c['bold']}{c['green']}✅ CLEAN: No credential findings detected{c['reset']}")
        
        print(f"{c['cyan']}{'─'*70}{c['reset']}")
        print(f"{c['white']}💡 For detailed analysis:{c['reset']}")
        print(f"   {c['cyan']}• Use --report json for machine-readable output{c['reset']}")
        print(f"   {c['cyan']}• Use --report extend_html for advanced HTML report{c['reset']}")
        print(f"   {c['cyan']}• Use --report csv for spreadsheet analysis{c['reset']}")
        print(f"{c['bold']}{c['cyan']}{'='*70}{c['reset']}\n")
    
    def _get_status_indicator(self, status: str, finding_count: int) -> str:
        """Get status indicator for module."""
        c = self.colors
        
        if status == 'error':
            return f"({c['red']}❌ ERROR{c['reset']})"
        elif finding_count == 0:
            return f"({c['green']}✅ CLEAN{c['reset']})"
        else:
            return f"({c['yellow']}⚠️  {finding_count} FINDINGS{c['reset']})"
    
    def _get_severity_indicator(self, severity: str) -> str:
        """Get severity indicator."""
        indicators = {
            'critical': '🚨',
            'warning': '⚠️ ',
            'info': 'ℹ️ '
        }
        return indicators.get(severity, 'ℹ️ ')
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'critical': self.colors['red'],
            'warning': self.colors['yellow'],
            'info': self.colors['blue']
        }
        return colors.get(severity, self.colors['white'])
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            'critical': self.colors['red'],
            'high': self.colors['red'],
            'medium': self.colors['yellow'],
            'low': self.colors['green'],
            'none': self.colors['green']
        }
        return colors.get(risk_level, self.colors['white']) 