#!/usr/bin/env python3
"""
Extended HTML Reporter - Professional Security Assessment Report

Generates a modern, professional HTML security assessment report with:
- Responsive sidebar navigation
- Executive summary with statistics
- System information section  
- Module-based findings with expandable details
- Modern UI with professional styling
- Interactive features and animations
- Print-friendly styling
- Mobile responsive design

Usage:
    reporter = ExtendHtmlReporter(config)
    report_path = reporter.generate(results, execution_stats)
"""

import os
from datetime import datetime
from typing import Any, Dict, Optional
from .json_reporter import JsonReporter

class ExtendHtmlReporter:
    """Professional HTML security assessment report generator."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        output_config = config.get("output", {})
        self.output_dir = output_config.get("output_dir", "./reports")
        self.timestamp_format = output_config.get("timestamp_format", "%Y%m%d_%H%M%S")
        self.json_reporter = JsonReporter(config)

    def generate(self, results: Dict[str, Any], execution_stats: Optional[Dict[str, Any]] = None, custom_filename: Optional[str] = None) -> str:
        """Generate professional HTML security assessment report."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            if custom_filename:
                html_path = os.path.join(self.output_dir, f"{custom_filename}.html")
            else:
                timestamp = datetime.now().strftime(self.timestamp_format)
                html_path = os.path.join(self.output_dir, f"credfinder_extend_report_{timestamp}.html")
            
            # Build report data structure
            report_data = self.json_reporter._build_report_structure(results, execution_stats)
            
            # Generate HTML content
            html_content = self._build_html_content(report_data)
            
            # Write to file
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return html_path
            
        except Exception as e:
            raise Exception(f"Failed to generate extend_html report: {str(e)}")

    def _build_html_content(self, report_data: Dict[str, Any]) -> str:
        """Build the complete HTML document."""
        scan_summary = report_data.get('scan_summary', {})
        findings = report_data.get('findings', {})
        metadata = report_data.get('metadata', {})
        
        # Calculate statistics
        total_findings = scan_summary.get('total_findings', 0)
        critical_count = self._count_findings_by_severity(findings, 'critical')
        warning_count = self._count_findings_by_severity(findings, 'warning') 
        info_count = self._count_findings_by_severity(findings, 'info')
        
        # Get system info
        system_info = metadata.get('system_info', {})
        hostname = system_info.get('hostname', 'Unknown')
        os_name = system_info.get('platform', 'Unknown')
        os_version = system_info.get('platform_version', 'Unknown')
        kernel = system_info.get('platform_release', 'Unknown')
        arch = system_info.get('architecture', 'Unknown')
        username = system_info.get('username', 'Unknown')
        
        # Determine execution mode
        exec_mode = 'Root (Administrator)' if username == 'root' else 'Standard User'
        
        # Generate timestamp
        now = datetime.now()
        timestamp_display = now.strftime('%B %d, %Y at %H:%M:%S')
        current_year = now.year
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CredFinder - Security Assessment Report</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {self._get_modern_css()}
    </style>
</head>
<body>
    <div class="report-container">
        
        <nav class="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-logo">
                    <i class="fas fa-shield-alt"></i>
                    CredFinder Report
                </div>
            </div>
            <div class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">Navigation</div>
                    <a href="#summary" class="nav-item active">
                        <i class="fas fa-chart-bar"></i>
                        Executive Summary
                    </a>
                    <a href="#system-info" class="nav-item">
                        <i class="fas fa-server"></i>
                        System Information
                    </a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Findings by Module</div>
                    {self._build_module_navigation(findings)}
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Actions</div>
                    <a href="#" onclick="window.print(); return false;" class="nav-item">
                        <i class="fas fa-print"></i>
                        Print Report
                    </a>
                    <a href="#" onclick="exportJSON(); return false;" class="nav-item">
                        <i class="fas fa-download"></i>
                        Export JSON
                    </a>
                </div>
            </div>
        </nav>
        
        
        <div class="main-content">
            
        <header class="report-header">
            <div class="header-content">
                <h1 class="header-title">Security Assessment Report</h1>
                <div class="header-actions">
                    <button class="btn" onclick="window.print()">
                        <i class="fas fa-print"></i>
                        Print
                    </button>
                    <button class="btn btn-primary" onclick="exportJSON()">
                        <i class="fas fa-download"></i>
                        Export
                    </button>
                </div>
            </div>
        </header>
        
            
            <div class="content-wrapper">
                
        <section id="summary" class="section">
            <div class="section-header">
                <h2 class="section-title">Executive Summary</h2>
                <p class="section-subtitle">
                    Generated on {timestamp_display} | 
                    Host: {hostname}
                </p>
            </div>
            
            <div class="executive-summary">
                <p>This security assessment report provides a comprehensive analysis of discovered credentials, 
                secrets, and sensitive information on the target system. The scan examined {len(findings)} modules 
                and identified {total_findings} total findings requiring attention.</p>
                
                <div class="summary-grid">
                    <div class="summary-stat">
                        <div class="stat-value">{total_findings}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-value critical">{critical_count}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-value warning">{warning_count}</div>
                        <div class="stat-label">Warning</div>
                    </div>
                    <div class="summary-stat">
                        <div class="stat-value info">{info_count}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>
                
                <div class="mt-3">
                    <strong>Key Highlights:</strong>
                    <ul>
                        {self._build_summary_highlights(critical_count, warning_count, info_count)}
                    </ul>
                </div>
            </div>
        </section>
        
                
        <section id="system-info" class="section">
            <div class="section-header">
                <h2 class="section-title">System Information</h2>
            </div>
            
            <div class="system-info">
                <div class="system-info-grid">
                    <div class="system-info-item">
                        <span class="system-info-label">Hostname:</span>
                        <span class="system-info-value">{hostname}</span>
                    </div>
                    <div class="system-info-item">
                        <span class="system-info-label">Operating System:</span>
                        <span class="system-info-value">{os_name} {os_version}</span>
                    </div>
                    <div class="system-info-item">
                        <span class="system-info-label">Kernel Version:</span>
                        <span class="system-info-value">{kernel}</span>
                    </div>
                    <div class="system-info-item">
                        <span class="system-info-label">Architecture:</span>
                        <span class="system-info-value">{arch}</span>
                    </div>
                    <div class="system-info-item">
                        <span class="system-info-label">Current User:</span>
                        <span class="system-info-value">{username}</span>
                    </div>
                    <div class="system-info-item">
                        <span class="system-info-label">Execution Mode:</span>
                        <span class="system-info-value">{exec_mode}</span>
                    </div>
                </div>
            </div>
        </section>
        
                
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Limited Access Mode:</strong> Running as a standard user limits access to some system resources.
                    For comprehensive assessment, consider running with administrator privileges: <code>sudo python3 main.py</code>
                </div>
            </div>
            
                
            {self._build_findings_sections(findings)}
                </div>
            </div>
        </div>

    <script>
        {self._get_modern_javascript()}
    </script>
</body>
</html>"""

    def _count_findings_by_severity(self, findings: Dict[str, Any], severity: str) -> int:
        """Count findings by severity level across all modules."""
        count = 0
        for module_data in findings.values():
            if isinstance(module_data, dict) and 'findings' in module_data:
                for finding in module_data['findings']:
                    if isinstance(finding, dict) and finding.get('severity') == severity:
                        count += 1
        return count

    def _build_summary_highlights(self, critical: int, warning: int, info: int) -> str:
        """Build summary highlights list."""
        highlights = []
        if critical:
            highlights.append(f"<li><strong>{critical} critical findings</strong> require immediate remediation</li>")
        if warning:
            highlights.append(f"<li><strong>{warning} warning findings</strong> pose potential security risks</li>")
        if info:
            highlights.append(f"<li><strong>{info} informational findings</strong> for security awareness</li>")
        
        if not (critical or warning or info):
            highlights.append("<li>No security findings detected</li>")
        else:
            highlights.append("<li>Scan executed with <strong>limited privileges</strong> - some areas may be inaccessible</li>")
            
        return '\n'.join(highlights)

    def _build_module_navigation(self, findings: Dict[str, Any]) -> str:
        """Build navigation links for each module."""
        module_info = {
            'dotfiles': {'icon': 'fas fa-folder', 'title': 'Configuration Files'},
            'ssh': {'icon': 'fas fa-key', 'title': 'SSH Analysis'},
            'history': {'icon': 'fas fa-scroll', 'title': 'Command History'},
            'browser': {'icon': 'fas fa-globe', 'title': 'Browser Data'},
            'memory': {'icon': 'fas fa-brain', 'title': 'Memory Analysis'},
            'keyring': {'icon': 'fas fa-lock', 'title': 'Keyring Store'},
            'file_grep': {'icon': 'fas fa-search', 'title': 'File Pattern Search'}
        }
        
        nav_items = []
        for module_name in findings.keys():
            info = module_info.get(module_name, {'icon': 'fas fa-folder', 'title': module_name.title()})
            nav_items.append(f"""
                    <a href="#module-{module_name}" class="nav-item">
                        <i class="{info['icon']}"></i>
                        {info['title']}
                    </a>""")
        
        return '\n'.join(nav_items)

    def _build_findings_sections(self, findings: Dict[str, Any]) -> str:
        """Build findings sections for each module."""
        module_info = {
            'dotfiles': {'icon': 'fas fa-folder', 'title': 'Configuration Files'},
            'ssh': {'icon': 'fas fa-key', 'title': 'SSH Analysis'},
            'history': {'icon': 'fas fa-scroll', 'title': 'Command History'},
            'browser': {'icon': 'fas fa-globe', 'title': 'Browser Data'},
            'memory': {'icon': 'fas fa-brain', 'title': 'Memory Analysis'},
            'keyring': {'icon': 'fas fa-lock', 'title': 'Keyring Store'},
            'file_grep': {'icon': 'fas fa-search', 'title': 'File Pattern Search'}
        }
        
        sections = []
        for module_name, module_data in findings.items():
            info = module_info.get(module_name, {'icon': 'fas fa-folder', 'title': module_name.title()})
            
            # Handle module data structure
            if isinstance(module_data, dict):
                findings_list = module_data.get('findings', [])
                status = module_data.get('status', 'success')
                error_message = module_data.get('error_message', '')
            else:
                findings_list = []
                status = 'error'
                error_message = 'Invalid data structure'
            
            section = f"""
            <section id="module-{module_name}" class="section">
                <div class="module-section">
                    <div class="module-header">
                        <div class="module-title">
                            <i class="{info['icon']}"></i>
                            {info['title']}
                        </div>
                        <span class="module-count">{len(findings_list)} findings</span>
                    </div>
                    <div class="module-content">
                        {self._build_module_content(findings_list, status, error_message)}
                    </div>
                </div>
            </section>
            """
            sections.append(section)
        
        return '\n'.join(sections)

    def _build_module_content(self, findings_list: list, status: str, error_message: str) -> str:
        """Build content for a specific module."""
        if status == 'error':
            return f"""
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Module Error:</strong> {error_message}
                </div>
            </div>
            """
        elif status == 'skipped':
            return f"""
            <div class="alert alert-info">
                <i class="fas fa-forward"></i>
                <div>
                    <strong>Module Skipped:</strong> {error_message}
                </div>
            </div>
            """
        elif not findings_list:
            return """
            <div class="alert alert-info">
                <i class="fas fa-check-circle"></i>
                <div>
                    <strong>No findings detected:</strong> This module completed successfully but found no credentials or sensitive data.
                </div>
            </div>
            """
        else:
            return f"""
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width: 40px;"></th>
                    <th>Finding</th>
                    <th style="width: 100px;">Severity</th>
                    <th style="width: 150px;">Type</th>
                    <th style="width: 200px;">Location</th>
                </tr>
            </thead>
            <tbody>
                {self._build_finding_rows(findings_list)}
            </tbody>
        </table>
        """

    def _build_finding_rows(self, findings_list: list) -> str:
        """Build table rows for findings."""
        rows = []
        for finding in findings_list:
            if not isinstance(finding, dict):
                continue
                
            # Extract finding data
            finding_type = finding.get('type', 'Unknown')
            severity = finding.get('severity', 'info')
            details = finding.get('details', {})
            
            # Get location
            location = 'Unknown'
            if isinstance(details, dict):
                location = details.get('file', details.get('location', details.get('path', 'Unknown')))
            
            # Build finding title
            title = self._get_finding_title(finding_type, details)
            
            # Create severity badge
            severity_class = f"severity-{severity}"
            
            # Build details content
            details_html = self._build_finding_details(details)
            
            row = f"""
            <tr class="finding-row" onclick="toggleDetails(this)">
                <td><i class="fas fa-chevron-right expand-icon"></i></td>
                <td>{title}</td>
                <td><span class="severity {severity_class}">{severity.upper()}</span></td>
                <td>{finding_type}</td>
                <td class="text-truncate" title="{location}">{location}</td>
            </tr>
            <tr class="finding-details">
                <td colspan="5">
                    <div class="details-content">
                    {details_html}
                    </div>
                </td>
            </tr>
            """
            rows.append(row)
        
        return '\n'.join(rows)

    def _get_finding_title(self, finding_type: str, details: dict) -> str:
        """Generate a descriptive title for the finding."""
        if finding_type == 'Private Key':
            filename = details.get('file', '').split('/')[-1] if details.get('file') else 'private key'
            return f"SSH Private Key: {filename}"
        elif finding_type == 'Public Key':
            filename = details.get('file', '').split('/')[-1] if details.get('file') else 'public key'
            return f"SSH Public Key: {filename}"
        elif finding_type == 'Agent Identity':
            return "SSH Agent Identity"
        elif 'password' in finding_type.lower():
            return "Command History Secret"
        elif 'api' in finding_type.lower() or 'token' in finding_type.lower():
            return "Configuration File Secret"
        else:
            return finding_type.replace('_', ' ').title()

    def _build_finding_details(self, details: dict) -> str:
        """Build details content for a finding."""
        if not isinstance(details, dict):
            return ""
        
        detail_groups = []
        for key, value in details.items():
            if value is not None and str(value).strip():
                label = key.replace('_', ' ').title()
                
                # Format pattern matches nicely
                if key.lower() == 'pattern_matches':
                    formatted_value = self._format_pattern_matches(value)
                else:
                    formatted_value = str(value)
                
                detail_groups.append(f"""
                    <div class="detail-group">
                        <div class="detail-label">{label}</div>
                        <div class="detail-value">{formatted_value}</div>
                    </div>""")
        
        return '\n'.join(detail_groups)
    
    def _format_pattern_matches(self, pattern_matches) -> str:
        """Format pattern matches for display."""
        if not pattern_matches:
            return "None"
        
        # Handle different input formats
        if isinstance(pattern_matches, str):
            try:
                # Try to parse if it's a string representation of a list
                import ast
                pattern_matches = ast.literal_eval(pattern_matches)
            except:
                return pattern_matches
        
        if isinstance(pattern_matches, list):
            formatted_matches = []
            for match in pattern_matches:
                if isinstance(match, dict):
                    match_type = match.get('type', 'unknown')
                    match_pattern = match.get('match', match.get('pattern', 'N/A'))
                    context = match.get('context', '')
                    
                    # Create a clean, readable format
                    formatted_match = f"""
                    <div class="pattern-match">
                        <strong>{match_type.title()}:</strong> <code>{match_pattern}</code>
                        {f'<br><small>Context: {context[:100]}...</small>' if context else ''}
                    </div>"""
                    formatted_matches.append(formatted_match.strip())
                else:
                    formatted_matches.append(f"<div class=\"pattern-match\">{str(match)}</div>")
            
            return '<div class="pattern-matches-container">' + ''.join(formatted_matches) + '</div>'
        else:
            return str(pattern_matches)

    def _get_modern_css(self) -> str:
        """Get the modern CSS styles."""
        return """
        /* ===== PROFESSIONAL REPORT STYLES ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            /* Professional color palette */
            --primary-color: #1a365d;
            --secondary-color: #2d3748;
            --accent-color: #e53e3e;
            --success-color: #38a169;
            --warning-color: #d69e2e;
            --danger-color: #e53e3e;
            --info-color: #3182ce;
            
            /* Grays */
            --gray-50: #f7fafc;
            --gray-100: #edf2f7;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e0;
            --gray-400: #a0aec0;
            --gray-500: #718096;
            --gray-600: #4a5568;
            --gray-700: #2d3748;
            --gray-800: #1a202c;
            --gray-900: #171923;
            
            /* Typography */
            --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            --font-mono: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            
            /* Spacing */
            --spacing-xs: 0.25rem;
            --spacing-sm: 0.5rem;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;
            --spacing-2xl: 3rem;
            
            /* Layout */
            --max-width: 1200px;
            --sidebar-width: 260px;
            
            /* Shadows */
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        body {
            font-family: var(--font-sans);
            font-size: 14px;
            line-height: 1.6;
            color: var(--gray-800);
            background-color: var(--gray-50);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* ===== LAYOUT ===== */
        .report-container {
            display: flex;
            min-height: 100vh;
        }

        /* ===== SIDEBAR NAVIGATION ===== */
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: var(--sidebar-width);
            height: 100vh;
            background-color: var(--gray-900);
            color: var(--gray-300);
            overflow-y: auto;
            z-index: 100;
            box-shadow: 2px 0 4px rgba(0, 0, 0, 0.1);
        }

        .sidebar-header {
            padding: var(--spacing-xl);
            border-bottom: 1px solid var(--gray-800);
        }

        .sidebar-logo {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            color: white;
            font-size: 1.25rem;
            font-weight: 600;
        }

        .sidebar-logo i {
            color: var(--info-color);
        }

        .sidebar-nav {
            padding: var(--spacing-lg) 0;
        }

        .nav-section {
            margin-bottom: var(--spacing-lg);
        }

        .nav-section-title {
            padding: var(--spacing-sm) var(--spacing-xl);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--gray-500);
        }

        .nav-item {
            display: block;
            padding: var(--spacing-sm) var(--spacing-xl);
            color: var(--gray-300);
            text-decoration: none;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background-color: var(--gray-800);
            color: white;
            border-left-color: var(--info-color);
        }

        .nav-item.active {
            background-color: var(--gray-800);
            color: white;
            border-left-color: var(--info-color);
        }

        .nav-item i {
            width: 20px;
            margin-right: var(--spacing-sm);
            text-align: center;
        }

        /* ===== MAIN CONTENT ===== */
        .main-content {
            flex: 1;
            margin-left: var(--sidebar-width);
            background-color: white;
            min-height: 100vh;
        }

        /* ===== HEADER ===== */
        .report-header {
            background-color: white;
            border-bottom: 1px solid var(--gray-200);
            padding: var(--spacing-xl);
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: var(--shadow-sm);
        }

        .header-content {
            max-width: var(--max-width);
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--gray-900);
        }

        .header-actions {
            display: flex;
            gap: var(--spacing-sm);
        }

        .btn {
            padding: var(--spacing-sm) var(--spacing-md);
            border: 1px solid var(--gray-300);
            background-color: white;
            color: var(--gray-700);
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: var(--spacing-xs);
        }

        .btn:hover {
            background-color: var(--gray-50);
            border-color: var(--gray-400);
        }

        .btn-primary {
            background-color: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: #2c5282;
            border-color: #2c5282;
        }

        /* ===== CONTENT SECTIONS ===== */
        .content-wrapper {
            max-width: var(--max-width);
            margin: 0 auto;
            padding: var(--spacing-2xl);
        }

        .section {
            margin-bottom: var(--spacing-2xl);
        }

        .section-header {
            margin-bottom: var(--spacing-lg);
            padding-bottom: var(--spacing-md);
            border-bottom: 2px solid var(--gray-200);
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--gray-900);
            margin-bottom: var(--spacing-xs);
        }

        .section-subtitle {
            font-size: 0.875rem;
            color: var(--gray-600);
        }

        /* ===== EXECUTIVE SUMMARY ===== */
        .executive-summary {
            background-color: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: 6px;
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-2xl);
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: var(--spacing-lg);
            margin-top: var(--spacing-lg);
        }

        .summary-stat {
            background-color: white;
            border: 1px solid var(--gray-200);
            border-radius: 4px;
            padding: var(--spacing-lg);
            text-align: center;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--gray-900);
            line-height: 1;
        }

        .stat-value.critical {
            color: var(--danger-color);
        }

        .stat-value.warning {
            color: var(--warning-color);
        }

        .stat-value.info {
            color: var(--info-color);
        }

        .stat-label {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--gray-600);
            margin-top: var(--spacing-xs);
        }

        /* ===== SYSTEM INFO ===== */
        .system-info {
            background-color: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: 6px;
            padding: var(--spacing-lg);
            margin-bottom: var(--spacing-xl);
        }

        .system-info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: var(--spacing-md);
        }

        .system-info-item {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        .system-info-label {
            font-weight: 600;
            color: var(--gray-600);
            min-width: 120px;
        }

        .system-info-value {
            color: var(--gray-800);
            font-family: var(--font-mono);
        }

        /* ===== ALERTS ===== */
        .alert {
            padding: var(--spacing-md) var(--spacing-lg);
            border-radius: 4px;
            margin-bottom: var(--spacing-lg);
            border-left: 4px solid;
            display: flex;
            align-items: flex-start;
            gap: var(--spacing-md);
        }

        .alert-info {
            background-color: #eff6ff;
            border-left-color: var(--info-color);
            color: #1e40af;
        }

        .alert-warning {
            background-color: #fefce8;
            border-left-color: var(--warning-color);
            color: #854d0e;
        }

        .alert-danger {
            background-color: #fef2f2;
            border-left-color: var(--danger-color);
            color: #991b1b;
        }

        .alert i {
            font-size: 1.25rem;
            flex-shrink: 0;
        }

        /* ===== MODULE SECTIONS ===== */
        .module-section {
            background-color: white;
            border: 1px solid var(--gray-200);
            border-radius: 6px;
            margin-bottom: var(--spacing-xl);
            overflow: hidden;
        }

        .module-header {
            background-color: var(--gray-50);
            padding: var(--spacing-md) var(--spacing-lg);
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .module-title {
            font-weight: 600;
            color: var(--gray-800);
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        .module-count {
            background-color: var(--gray-200);
            color: var(--gray-700);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .module-content {
            padding: 0;
        }

        /* ===== DATA TABLES ===== */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
            background-color: white;
        }

        .data-table thead {
            background-color: var(--gray-50);
            border-bottom: 2px solid var(--gray-200);
        }

        .data-table th {
            padding: var(--spacing-md);
            text-align: left;
            font-weight: 600;
            color: var(--gray-700);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .data-table tbody tr {
            border-bottom: 1px solid var(--gray-200);
            transition: background-color 0.15s ease;
        }

        .data-table tbody tr:hover {
            background-color: var(--gray-50);
        }

        .data-table tbody tr:last-child {
            border-bottom: none;
        }

        .data-table td {
            padding: var(--spacing-md);
            color: var(--gray-700);
        }

        /* ===== FINDING ROWS ===== */
        .finding-row {
            cursor: pointer;
        }

        .finding-row.expanded {
            background-color: var(--gray-50);
        }

        .finding-details {
            display: none;
            background-color: var(--gray-50);
            border-top: 1px solid var(--gray-200);
        }

        .finding-details.active {
            display: table-row;
        }

        .finding-details td {
            padding: var(--spacing-lg);
        }

        .details-content {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: var(--spacing-lg);
        }

        .detail-group {
            background-color: white;
            border: 1px solid var(--gray-200);
            border-radius: 4px;
            padding: var(--spacing-md);
        }

        .detail-label {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--gray-600);
            margin-bottom: var(--spacing-xs);
        }

        .detail-value {
            font-family: var(--font-mono);
            font-size: 0.875rem;
            color: var(--gray-800);
            word-break: break-all;
        }

        /* ===== PATTERN MATCHES ===== */
        .pattern-matches-container {
            display: flex;
            flex-direction: column;
            gap: var(--spacing-sm);
        }

        .pattern-match {
            background-color: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: 4px;
            padding: var(--spacing-sm);
            font-size: 0.875rem;
        }

        .pattern-match code {
            background-color: var(--gray-100);
            padding: 2px 4px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--danger-color);
        }

        .pattern-match small {
            color: var(--gray-600);
            font-style: italic;
        }

        /* ===== SEVERITY BADGES ===== */
        .severity {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-critical {
            background-color: #fee;
            color: var(--danger-color);
            border: 1px solid #fcc;
        }

        .severity-warning {
            background-color: #fefce8;
            color: var(--warning-color);
            border: 1px solid #fef3c7;
        }

        .severity-info {
            background-color: #eff6ff;
            color: var(--info-color);
            border: 1px solid #dbeafe;
        }

        /* ===== EXPANDABLE ROWS ===== */
        .expand-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            color: var(--gray-500);
            transition: transform 0.2s ease;
        }

        .expand-icon.expanded {
            transform: rotate(90deg);
        }

        /* ===== UTILITIES ===== */
        .text-truncate {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .mt-3 { margin-top: var(--spacing-lg); }

        /* ===== PRINT STYLES ===== */
        @media print {
            .sidebar {
                display: none;
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .header-actions {
                display: none;
            }

            .report-header {
                position: static;
                box-shadow: none;
            }

            .finding-row {
                cursor: default;
            }

            .expand-icon {
                display: none;
            }
            
            .finding-details {
                display: table-row !important;
            }
        }

        /* ===== RESPONSIVE ===== */
        @media (max-width: 1024px) {
            .sidebar {
                transform: translateX(-100%);
                transition: transform 0.3s ease;
            }

            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .details-content {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 640px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }

            .system-info-grid {
                grid-template-columns: 1fr;
            }

            .header-content {
                flex-direction: column;
                gap: var(--spacing-md);
            }
        }
        """

    def _get_modern_javascript(self) -> str:
        """Get the modern JavaScript functionality."""
        return """
        // Professional Report JavaScript
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            initializeNavigation();
        });
        
        function initializeNavigation() {
            // Smooth scrolling for navigation
            document.querySelectorAll('.nav-item').forEach(link => {
                link.addEventListener('click', function(e) {
                    if (this.getAttribute('href').startsWith('#')) {
                        e.preventDefault();
                        const target = document.querySelector(this.getAttribute('href'));
                        if (target) {
                            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            
                            // Update active state
                            document.querySelectorAll('.nav-item').forEach(item => {
                                item.classList.remove('active');
                            });
                            this.classList.add('active');
                        }
                    }
                });
            });
            
            // Highlight section on scroll
            const sections = document.querySelectorAll('section');
            const navItems = document.querySelectorAll('.nav-item');
            
            window.addEventListener('scroll', () => {
                let current = '';
                sections.forEach(section => {
                    const sectionTop = section.offsetTop;
                    if (pageYOffset >= sectionTop - 100) {
                        current = section.getAttribute('id');
                    }
                });
                
                navItems.forEach(item => {
                    item.classList.remove('active');
                    if (item.getAttribute('href') === `#${current}`) {
                        item.classList.add('active');
                    }
                });
            });
        }
        
        function toggleDetails(row) {
            const detailsRow = row.nextElementSibling;
            const icon = row.querySelector('.expand-icon');
            
            if (detailsRow && detailsRow.classList.contains('finding-details')) {
                detailsRow.classList.toggle('active');
                icon.classList.toggle('expanded');
                row.classList.toggle('expanded');
            }
        }
        
        function exportJSON() {
            const reportData = {
                timestamp: new Date().toISOString(),
                note: "This is a simplified export. For full JSON data, run: python3 main.py --report json"
            };
            
            const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `credfinder_report_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // Mobile sidebar toggle
        function toggleSidebar() {
            document.querySelector('.sidebar').classList.toggle('active');
        }
        """