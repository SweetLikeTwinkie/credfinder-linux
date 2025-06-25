#!/usr/bin/env python3
"""
HTML Reporter

Simple HTML report generator that creates clean, shareable reports for findings.
Uses JSON reporter as the data source for consistent processing and categorization.

Key Features:
- Clean, professional HTML output for sharing
- Mobile-responsive design
- Uses structured data from JSON reporter
- Print-friendly formatting
- Link to advanced dashboard when available

Usage:
    html_reporter = HtmlReporter(config)
    report_path = html_reporter.generate(results, execution_stats)
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from .json_reporter import JsonReporter


class HtmlReporter:
    """Simple HTML report generator for sharing findings."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Load configuration
        output_config = config.get("output", {})
        self.output_dir = output_config.get("output_dir", "./reports")
        self.timestamp_format = output_config.get("timestamp_format", "%Y%m%d_%H%M%S")
        
        # Initialize JSON reporter as data source
        self.json_reporter = JsonReporter(config)
    
    def generate(self, results: Dict[str, Any], 
                execution_stats: Optional[Dict[str, Any]] = None,
                custom_filename: Optional[str] = None) -> str:
        """
        Generate simple HTML report using JSON reporter data.
        
        Args:
            results: Scan results from all modules
            execution_stats: Optional execution statistics
            custom_filename: Optional custom filename (without extension)
            
        Returns:
            Path to generated HTML report file
        """
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Generate filename
        if custom_filename:
            html_path = os.path.join(self.output_dir, f"{custom_filename}.html")
        else:
            timestamp = datetime.now().strftime(self.timestamp_format)
            html_path = os.path.join(self.output_dir, f"credfinder_report_{timestamp}.html")
        
        # Get structured data from JSON reporter
        report_data = self.json_reporter._build_report_structure(results, execution_stats)
        
        # Build HTML content
        html_content = self._build_html_content(report_data)
        
        # Write HTML report
        try:
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return html_path
            
        except Exception as e:
            raise Exception(f"Failed to generate HTML report: {e}")
    
    def _build_html_content(self, report_data: Dict[str, Any]) -> str:
        """Build complete HTML content."""
        
        scan_summary = report_data.get('scan_summary', {})
        findings = report_data.get('findings', {})
        metadata = report_data.get('metadata', {})
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CredFinder Linux Report</title>
    {self._get_css_styles()}
</head>
<body>
    <div class="container">
        {self._build_header(report_data.get('report_info', {}))}
        {self._build_summary_section(scan_summary)}
        {self._build_findings_section(findings)}
        {self._build_metadata_section(metadata) if metadata else ''}
        {self._build_footer()}
    </div>
</body>
</html>"""
        
        return html_content
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the HTML report."""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 20px auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        
        .summary-card.critical {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        
        .summary-card.warning {
            border-left-color: #f39c12;
            background: #fefaf0;
        }
        
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .summary-card.critical .summary-number {
            color: #e74c3c;
        }
        
        .summary-card.warning .summary-number {
            color: #f39c12;
        }
        
        .summary-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .module {
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .module-header {
            background: #34495e;
            color: white;
            padding: 15px 20px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .module-content {
            padding: 20px;
        }
        
        .finding {
            background: #f8f9fa;
            margin: 15px 0;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        
        .finding.critical {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        
        .finding.warning {
            border-left-color: #f39c12;
            background: #fefaf0;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-type {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #e74c3c;
            color: white;
        }
        
        .severity-warning {
            background: #f39c12;
            color: white;
        }
        
        .severity-info {
            background: #3498db;
            color: white;
        }
        
        .finding-details {
            margin: 10px 0;
        }
        
        .finding-details strong {
            color: #2c3e50;
        }
        
        .remediation {
            background: #e8f5e8;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            border-left: 3px solid #27ae60;
        }
        
        .remediation strong {
            color: #27ae60;
        }
        
        .no-findings {
            text-align: center;
            color: #27ae60;
            font-style: italic;
            padding: 20px;
        }
        
        .error {
            background: #ffebee;
            color: #c62828;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .metadata-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
        }
        
        .metadata-card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .metadata-item {
            margin: 5px 0;
        }
        
        .metadata-item strong {
            color: #555;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px 30px;
            text-align: center;
        }
        
        .csv-link {
            display: inline-block;
            background: #27ae60;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin: 10px 5px;
            transition: background 0.3s;
        }
        
        .csv-link:hover {
            background: #229954;
        }
        
        @media print {
            .container {
                box-shadow: none;
                margin: 0;
            }
            
            .csv-link {
                display: none;
            }
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 0;
            }
            
            .header, .section {
                padding: 20px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>"""
    
    def _build_header(self, report_info: Dict[str, Any]) -> str:
        """Build HTML header section."""
        generated_at = report_info.get('generated_at', datetime.now().isoformat())
        formatted_date = datetime.fromisoformat(generated_at.replace('Z', '+00:00')).strftime('%B %d, %Y at %H:%M')
        
        return f"""
    <div class="header">
        <h1>🔍 CredFinder Linux</h1>
        <div class="subtitle">Credential & Secret Hunting Report</div>
        <div style="margin-top: 10px; font-size: 0.9em; opacity: 0.8;">
            Generated on {formatted_date}
        </div>
    </div>"""
    
    def _build_summary_section(self, scan_summary: Dict[str, Any]) -> str:
        """Build summary section with key statistics."""
        
        total_findings = scan_summary.get('total_findings', 0)
        critical_findings = scan_summary.get('critical_findings', 0)
        total_modules = scan_summary.get('total_modules', 0)
        successful_modules = scan_summary.get('successful_modules', 0)
        
        return f"""
    <div class="section">
        <h2>📊 Scan Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-number">{total_findings}</div>
                <div class="summary-label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-number">{critical_findings}</div>
                <div class="summary-label">Critical Findings</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{successful_modules}/{total_modules}</div>
                <div class="summary-label">Modules Executed</div>
            </div>
            <div class="summary-card warning">
                <div class="summary-number">{scan_summary.get('execution_time_seconds', 'N/A')}</div>
                <div class="summary-label">Execution Time (s)</div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <a href="#" class="csv-link">📊 Export to CSV</a>
        </div>
    </div>"""
    
    def _build_findings_section(self, findings: Dict[str, Any]) -> str:
        """Build findings section with all module results."""
        
        findings_html = """
    <div class="section">
        <h2>🔍 Detailed Findings</h2>"""
        
        for module_name, module_data in findings.items():
            module_findings = module_data.get('findings', [])
            finding_count = len(module_findings)
            status = module_data.get('status', 'success')
            
            findings_html += f"""
        <div class="module">
            <div class="module-header">
                <span>{module_name.upper()} MODULE</span>
                <span>{finding_count} findings</span>
            </div>
            <div class="module-content">"""
            
            if status == 'error':
                findings_html += f"""
                <div class="error">
                    <strong>Module Error:</strong> {module_data.get('error_message', 'Unknown error')}
                </div>"""
            elif not module_findings:
                findings_html += '<div class="no-findings">✅ No credential findings detected</div>'
            else:
                for finding in module_findings:
                    findings_html += self._build_finding_card(finding)
            
            findings_html += """
            </div>
        </div>"""
        
        findings_html += """
    </div>"""
        
        return findings_html
    
    def _build_finding_card(self, finding: Dict[str, Any]) -> str:
        """Build individual finding card."""
        
        finding_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 'info')
        details = finding.get('details', {})
        remediation = finding.get('remediation', 'Review finding for security implications')
        risk_score = finding.get('risk_score', 0)
        
        # Build details section
        details_html = ""
        for key, value in details.items():
            if value and str(value) != 'Unknown':
                details_html += f"<div><strong>{key.replace('_', ' ').title()}:</strong> {value}</div>"
        
        return f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <div class="finding-type">{finding_type.replace('_', ' ').title()}</div>
                <div class="severity-badge severity-{severity}">{severity}</div>
            </div>
            
            {f'<div class="finding-details">{details_html}</div>' if details_html else ''}
            
            <div style="margin: 10px 0;">
                <strong>Risk Score:</strong> {risk_score}/10
            </div>
            
            <div class="remediation">
                <strong>Remediation:</strong> {remediation}
            </div>
        </div>"""
    
    def _build_metadata_section(self, metadata: Dict[str, Any]) -> str:
        """Build metadata section."""
        
        system_info = metadata.get('system_info', {})
        tool_info = metadata.get('tool_info', {})
        scan_env = metadata.get('scan_environment', {})
        
        return f"""
    <div class="section">
        <h2>ℹ️ Scan Metadata</h2>
        <div class="metadata-grid">
            <div class="metadata-card">
                <h3>System Information</h3>
                <div class="metadata-item"><strong>Hostname:</strong> {system_info.get('hostname', 'Unknown')}</div>
                <div class="metadata-item"><strong>User:</strong> {system_info.get('username', 'Unknown')}</div>
                <div class="metadata-item"><strong>Platform:</strong> {system_info.get('platform', 'Unknown')}</div>
                <div class="metadata-item"><strong>Architecture:</strong> {system_info.get('architecture', 'Unknown')}</div>
            </div>
            
            <div class="metadata-card">
                <h3>Tool Information</h3>
                <div class="metadata-item"><strong>Tool:</strong> {tool_info.get('name', 'CredFinder Linux')}</div>
                <div class="metadata-item"><strong>Version:</strong> {tool_info.get('version', '2.0.0')}</div>
                <div class="metadata-item"><strong>Component:</strong> {tool_info.get('component', 'HTML Reporter')}</div>
            </div>
            
            <div class="metadata-card">
                <h3>Scan Environment</h3>
                <div class="metadata-item"><strong>Working Dir:</strong> {scan_env.get('working_directory', 'Unknown')}</div>
                <div class="metadata-item"><strong>Output Dir:</strong> {scan_env.get('output_directory', 'Unknown')}</div>
                <div class="metadata-item"><strong>Config:</strong> {scan_env.get('config_source', 'Unknown')}</div>
            </div>
        </div>
    </div>"""
    
    def _build_footer(self) -> str:
        """Build footer section."""
        return f"""
    <div class="footer">
        <p>Generated by CredFinder Linux v2.0.0 • {datetime.now().year}</p>
        <p style="margin-top: 5px; font-size: 0.9em; opacity: 0.8;">
            For advanced analysis, use the extend_html report format
        </p>
    </div>""" 