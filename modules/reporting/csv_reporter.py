#!/usr/bin/env python3
"""
CSV Reporter

Specialized CSV report generator optimized for spreadsheet analysis and data processing.
Generates flat, tabular data suitable for filtering, sorting, and pivot analysis.

Key Features:
- Flat CSV structure with consistent columns across all finding types
- Optimized for Excel/LibreOffice compatibility
- Comprehensive metadata in header comments
- Risk scoring and severity classification
- Custom field mapping for different finding types

Usage:
    csv_reporter = CsvReporter(config)
    report_path = csv_reporter.generate(results, execution_stats)
"""

import os
import csv
import platform
import socket
import getpass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path


class CsvReporter:
    """Specialized CSV report generator for spreadsheet analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Load configuration
        output_config = config.get("output", {})
        self.output_dir = output_config.get("output_dir", "./reports")
        self.include_metadata = output_config.get("include_metadata", True)
        self.timestamp_format = output_config.get("timestamp_format", "%Y%m%d_%H%M%S")
        self.csv_delimiter = output_config.get("csv_delimiter", ",")
        self.include_header_comments = output_config.get("include_header_comments", True)
        
        # Define standard CSV columns
        self.csv_columns = [
            'timestamp',
            'module',
            'finding_type',
            'severity',
            'category',
            'risk_score',
            'description',
            'location',
            'details',
            'remediation',
            'file_path',
            'line_number',
            'username',
            'service',
            'url',
            'encrypted',
            'key_type',
            'permissions',
            'size_bytes',
            'hostname',
            'platform'
        ]
    
    def generate(self, results: Dict[str, Any], 
                execution_stats: Optional[Dict[str, Any]] = None,
                custom_filename: Optional[str] = None) -> str:
        """
        Generate comprehensive CSV report.
        
        Args:
            results: Scan results from all modules
            execution_stats: Optional execution statistics
            custom_filename: Optional custom filename (without extension)
            
        Returns:
            Path to generated CSV report file
        """
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Generate filename
        if custom_filename:
            csv_path = os.path.join(self.output_dir, f"{custom_filename}.csv")
        else:
            timestamp = datetime.now().strftime(self.timestamp_format)
            csv_path = os.path.join(self.output_dir, f"credfinder_report_{timestamp}.csv")
        
        # Generate CSV content
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=self.csv_delimiter)
                
                # Write header comments if enabled
                if self.include_header_comments:
                    self._write_header_comments(writer, execution_stats)
                
                # Write column headers
                writer.writerow(self.csv_columns)
                
                # Process and write findings
                self._write_findings_rows(writer, results)
            
            return csv_path
            
        except Exception as e:
            raise Exception(f"Failed to generate CSV report: {e}")
    
    def _write_header_comments(self, writer: csv.writer, 
                              execution_stats: Optional[Dict[str, Any]]) -> None:
        """Write metadata header comments."""
        metadata_comments = [
            f"# CredFinder Linux - CSV Report",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Hostname: {socket.gethostname()}",
            f"# User: {getpass.getuser()}",
            f"# Platform: {platform.system()} {platform.release()}",
            f"# Tool Version: 2.0.0",
            ""
        ]
        
        # Add execution stats if available
        if execution_stats:
            metadata_comments.extend([
                f"# Execution Time: {execution_stats.get('total_time', 'Unknown')} seconds",
                f"# Modules Executed: {execution_stats.get('total_modules', 'Unknown')}",
                ""
            ])
        
        metadata_comments.extend([
            "# Column Descriptions:",
            "# timestamp - When the finding was detected",
            "# module - CredFinder module that detected the finding",
            "# finding_type - Specific type of credential/secret found",
            "# severity - Risk severity (critical/warning/info)",
            "# category - General category of the finding",
            "# risk_score - Numerical risk score (1-10)",
            "# description - Human-readable description",
            "# location - Primary location/path of the finding",
            "# details - Additional technical details",
            "# remediation - Recommended remediation steps",
            "# file_path - Specific file path (if applicable)",
            "# line_number - Line number in file (if applicable)",
            "# username - Associated username (if applicable)",
            "# service - Associated service name (if applicable)",
            "# url - Associated URL (if applicable)",
            "# encrypted - Whether credential is encrypted (if applicable)",
            "# key_type - Type of cryptographic key (if applicable)",
            "# permissions - File permissions (if applicable)",
            "# size_bytes - File size in bytes (if applicable)",
            "# hostname - System hostname",
            "# platform - Operating system platform",
            ""
        ])
        
        # Write comments as rows starting with #
        for comment in metadata_comments:
            if comment.strip():
                writer.writerow([comment])
            else:
                writer.writerow([""])
    
    def _write_findings_rows(self, writer: csv.writer, results: Dict[str, Any]) -> None:
        """Process findings and write CSV rows."""
        scan_timestamp = datetime.now().isoformat()
        hostname = socket.gethostname()
        platform_info = f"{platform.system()} {platform.release()}"
        
        for module_name, module_data in results.items():
            # Handle modules with errors
            if isinstance(module_data, dict) and '_status' in module_data:
                status = module_data['_status']
                if status in ['failed', 'skipped', 'timeout']:
                    error_row = self._create_error_row(
                        scan_timestamp, module_name, status, 
                        module_data.get('_error', 'Unknown error'),
                        hostname, platform_info
                    )
                    writer.writerow(error_row)
                    continue
            
            # Process normal findings
            rows = self._extract_module_rows(
                module_name, module_data, scan_timestamp, hostname, platform_info
            )
            for row in rows:
                writer.writerow(row)
    
    def _create_error_row(self, timestamp: str, module_name: str, status: str, 
                         error_msg: str, hostname: str, platform_info: str) -> List[str]:
        """Create CSV row for module errors."""
        return [
            timestamp,                      # timestamp
            module_name,                    # module
            f"module_{status}",             # finding_type
            "info",                         # severity
            "execution_error",              # category
            "1",                           # risk_score
            f"Module {status}: {error_msg}", # description
            "N/A",                         # location
            f"Status: {status}",           # details
            "Check module configuration",   # remediation
            "",                            # file_path
            "",                            # line_number
            "",                            # username
            "",                            # service
            "",                            # url
            "",                            # encrypted
            "",                            # key_type
            "",                            # permissions
            "",                            # size_bytes
            hostname,                      # hostname
            platform_info                  # platform
        ]
    
    def _extract_module_rows(self, module_name: str, module_data: Any,
                            timestamp: str, hostname: str, platform_info: str) -> List[List[str]]:
        """Extract CSV rows for a specific module."""
        rows = []
        
        if module_name == "ssh":
            rows.extend(self._extract_ssh_rows(module_data, timestamp, hostname, platform_info))
        elif module_name == "browser":
            rows.extend(self._extract_browser_rows(module_data, timestamp, hostname, platform_info))
        elif module_name == "keyring":
            rows.extend(self._extract_keyring_rows(module_data, timestamp, hostname, platform_info))
        elif module_name == "history":
            rows.extend(self._extract_history_rows(module_data, timestamp, hostname, platform_info))
        elif module_name == "dotfiles":
            rows.extend(self._extract_dotfile_rows(module_data, timestamp, hostname, platform_info))
        elif module_name == "file_grep":
            rows.extend(self._extract_file_grep_rows(module_data, timestamp, hostname, platform_info))
        else:
            # Generic handling for unknown modules
            rows.extend(self._extract_generic_rows(module_name, module_data, timestamp, hostname, platform_info))
        
        return rows
    
    def _extract_ssh_rows(self, ssh_data: Dict[str, Any], timestamp: str, 
                         hostname: str, platform_info: str) -> List[List[str]]:
        """Extract SSH finding rows."""
        rows = []
        
        # Process private keys
        if 'private_keys' in ssh_data and ssh_data['private_keys']:
            for key in ssh_data['private_keys']:
                severity = "critical" if not key.get('encrypted', True) else "warning"
                risk_score = "9" if not key.get('encrypted', True) else "6"
                
                rows.append([
                    timestamp,
                    "ssh",
                    "ssh_private_key",
                    severity,
                    "authentication_credential",
                    risk_score,
                    f"SSH private key {'(unencrypted)' if not key.get('encrypted', True) else '(encrypted)'}",
                    key.get('path', 'Unknown'),
                    f"Encrypted: {key.get('encrypted', False)}, Owner: {key.get('owner', 'Unknown')}",
                    "Encrypt key and set permissions to 600" if not key.get('encrypted', True) else "Review key usage",
                    key.get('path', ''),
                    "",
                    key.get('owner', ''),
                    "ssh",
                    "",
                    str(key.get('encrypted', False)).lower(),
                    "rsa/dsa/ecdsa/ed25519",
                    key.get('permissions', ''),
                    str(key.get('size', 0)),
                    hostname,
                    platform_info
                ])
        
        # Process SSH agent identities
        if 'ssh_agent' in ssh_data and ssh_data['ssh_agent'].get('running'):
            agent = ssh_data['ssh_agent']
            if agent.get('identities'):
                for identity in agent['identities']:
                    rows.append([
                        timestamp,
                        "ssh",
                        "ssh_agent_identity",
                        "critical",
                        "active_credential",
                        "8",
                        f"SSH agent identity loaded",
                        f"SSH Agent ({identity.get('key_type', 'Unknown')})",
                        f"Fingerprint: {identity.get('fingerprint', 'Unknown')}",
                        "Review SSH agent usage and remove unnecessary identities",
                        "",
                        "",
                        "",
                        "ssh_agent",
                        "",
                        "false",
                        identity.get('key_type', ''),
                        "",
                        "",
                        hostname,
                        platform_info
                    ])
        
        # Process authorized keys
        if 'authorized_keys' in ssh_data and ssh_data['authorized_keys']:
            for auth_key in ssh_data['authorized_keys']:
                rows.append([
                    timestamp,
                    "ssh",
                    "ssh_authorized_key",
                    "info",
                    "access_control",
                    "3",
                    "SSH authorized key entry",
                    auth_key.get('file', 'Unknown'),
                    f"Type: {auth_key.get('key_type', 'Unknown')}, Comment: {auth_key.get('comment', '')}",
                    "Review authorized keys for unauthorized access",
                    auth_key.get('file', ''),
                    "",
                    "",
                    "ssh",
                    "",
                    "",
                    auth_key.get('key_type', ''),
                    "",
                    "",
                    hostname,
                    platform_info
                ])
        
        return rows
    
    def _extract_browser_rows(self, browser_data: Dict[str, Any], timestamp: str,
                             hostname: str, platform_info: str) -> List[List[str]]:
        """Extract browser finding rows."""
        rows = []
        
        for browser_type, browser_info in browser_data.items():
            if not isinstance(browser_info, dict):
                continue
                
            # Process passwords
            if 'passwords' in browser_info and browser_info['passwords']:
                for entry in browser_info['passwords']:
                    if isinstance(entry, dict):
                        severity = "critical"
                        risk_score = "9" if entry.get('decrypted', False) else "7"
                        
                        rows.append([
                            timestamp,
                            "browser",
                            "browser_credential",
                            severity,
                            "stored_credential",
                            risk_score,
                            f"Browser stored credential for {entry.get('url', 'Unknown site')}",
                            f"{browser_type}: {entry.get('url', 'Unknown')}",
                            f"Username: {entry.get('username', 'Unknown')}, Profile: {entry.get('profile_path', 'Unknown')}",
                            "Use password manager and clear browser-stored credentials",
                            entry.get('profile_path', ''),
                            "",
                            entry.get('username', ''),
                            browser_type,
                            entry.get('url', ''),
                            str(entry.get('encrypted', True)).lower(),
                            "",
                            "",
                            "",
                            hostname,
                            platform_info
                        ])
        
        return rows
    
    def _extract_keyring_rows(self, keyring_data: Dict[str, Any], timestamp: str,
                             hostname: str, platform_info: str) -> List[List[str]]:
        """Extract keyring finding rows."""
        rows = []
        
        for keyring_type, keyring_info in keyring_data.items():
            if isinstance(keyring_info, dict) and keyring_info.get("items"):
                for item in keyring_info["items"]:
                    attributes = item.get('attributes', {})
                    service = attributes.get('service', attributes.get('application', 'Unknown'))
                    
                    rows.append([
                        timestamp,
                        "keyring",
                        "keyring_item",
                        "critical",
                        "stored_credential",
                        "8",
                        f"Keyring secret for {service}",
                        f"{keyring_type} keyring",
                        f"Service: {service}, Has secret: {bool(item.get('secret'))}",
                        "Review keyring contents and remove unnecessary secrets",
                        "",
                        "",
                        attributes.get('username', ''),
                        service,
                        "",
                        "",
                        "",
                        "",
                        "",
                        hostname,
                        platform_info
                    ])
        
        return rows
    
    def _extract_history_rows(self, history_data: Any, timestamp: str,
                             hostname: str, platform_info: str) -> List[List[str]]:
        """Extract command history finding rows."""
        rows = []
        
        if isinstance(history_data, list):
            for entry in history_data:
                if isinstance(entry, dict):
                    risk_level = entry.get('risk_level', 'low')
                    severity = self._map_risk_to_severity(risk_level)
                    risk_score = str(self._calculate_risk_score(risk_level))
                    
                    rows.append([
                        timestamp,
                        "history",
                        "command_history_credential",
                        severity,
                        "exposed_credential",
                        risk_score,
                        f"Sensitive command in history",
                        entry.get('file', 'Unknown'),
                        f"Patterns: {', '.join(entry.get('pattern_matches', []))}",
                        "Remove sensitive commands from history and use environment variables",
                        entry.get('file', ''),
                        str(entry.get('line_number', 0)),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        hostname,
                        platform_info
                    ])
        
        return rows
    
    def _extract_dotfile_rows(self, dotfile_data: Dict[str, Any], timestamp: str,
                             hostname: str, platform_info: str) -> List[List[str]]:
        """Extract dotfile finding rows."""
        rows = []
        
        for file_type, file_list in dotfile_data.items():
            if isinstance(file_list, list):
                for file_entry in file_list:
                    if isinstance(file_entry, dict):
                        rows.append([
                            timestamp,
                            "dotfiles",
                            "dotfile_credential",
                            "warning",
                            "configuration_credential",
                            "5",
                            f"Potential credential in {file_type} configuration",
                            file_entry.get('file', 'Unknown'),
                            f"Patterns: {', '.join(file_entry.get('pattern_matches', []))}",
                            "Move credentials to secure configuration management",
                            file_entry.get('file', ''),
                            "",
                            "",
                            file_type,
                            "",
                            "",
                            "",
                            "",
                            "",
                            hostname,
                            platform_info
                        ])
        
        return rows
    
    def _extract_file_grep_rows(self, file_grep_data: Dict[str, Any], timestamp: str,
                               hostname: str, platform_info: str) -> List[List[str]]:
        """Extract file grep finding rows."""
        rows = []
        
        file_matches = file_grep_data.get('file_matches', [])
        for match in file_matches:
            if isinstance(match, dict):
                rows.append([
                    timestamp,
                    "file_grep",
                    "file_pattern_match",
                    "warning",
                    "potential_credential",
                    "4",
                    "File contains potential credential patterns",
                    match.get('file', 'Unknown'),
                    f"Patterns: {', '.join(match.get('pattern_matches', []))}",
                    "Review file contents and secure any credentials found",
                    match.get('file', ''),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    str(match.get('file_size', 0)),
                    hostname,
                    platform_info
                ])
        
        return rows
    
    def _extract_generic_rows(self, module_name: str, module_data: Any, timestamp: str,
                             hostname: str, platform_info: str) -> List[List[str]]:
        """Extract rows for unknown module types."""
        rows = []
        
        if isinstance(module_data, list):
            for i, item in enumerate(module_data):
                rows.append([
                    timestamp,
                    module_name,
                    "generic_finding",
                    "info",
                    "unknown",
                    "2",
                    f"Generic finding #{i+1}",
                    str(item)[:100] + "..." if len(str(item)) > 100 else str(item),
                    f"Item {i+1} from {module_name}",
                    "Review finding for potential security implications",
                    "",
                    "",
                    "",
                    module_name,
                    "",
                    "",
                    "",
                    "",
                    "",
                    hostname,
                    platform_info
                ])
        elif isinstance(module_data, dict) and module_data:
            for key, value in module_data.items():
                if key.startswith('_'):  # Skip metadata
                    continue
                    
                rows.append([
                    timestamp,
                    module_name,
                    "generic_data",
                    "info",
                    "unknown",
                    "2",
                    f"Data found in {key}",
                    str(value)[:100] + "..." if len(str(value)) > 100 else str(value),
                    f"Key: {key}",
                    "Review data for potential security implications",
                    "",
                    "",
                    "",
                    module_name,
                    "",
                    "",
                    "",
                    "",
                    "",
                    hostname,
                    platform_info
                ])
        
        return rows
    
    def _map_risk_to_severity(self, risk_level: str) -> str:
        """Map risk level to severity."""
        risk_mapping = {
            'critical': 'critical',
            'high': 'critical',
            'medium': 'warning',
            'low': 'info'
        }
        return risk_mapping.get(risk_level.lower(), 'info')
    
    def _calculate_risk_score(self, risk_level: str) -> int:
        """Calculate numerical risk score."""
        score_mapping = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3
        }
        return score_mapping.get(risk_level.lower(), 3) 