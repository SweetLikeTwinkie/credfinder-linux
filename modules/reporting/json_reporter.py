#!/usr/bin/env python3
"""
JSON Reporter

Specialized JSON report generator optimized for automation and API integration.
Generates structured, machine-readable output with comprehensive metadata.

Key Features:
- Clean JSON structure optimized for programmatic consumption
- Comprehensive metadata including system information and execution stats
- Detailed finding categorization and risk scoring
- Schema validation and error handling
- Support for custom JSON serialization

Usage:
    json_reporter = JsonReporter(config)
    report_path = json_reporter.generate(results, execution_stats)
"""

import os
import json
import platform
import socket
import getpass
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


class JsonReporter:
    """Specialized JSON report generator for automation and tool integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Load configuration
        output_config = config.get("output", {})
        self.output_dir = output_config.get("output_dir", "./reports")
        self.include_metadata = output_config.get("include_metadata", True)
        self.timestamp_format = output_config.get("timestamp_format", "%Y%m%d_%H%M%S")
        self.json_indent = output_config.get("json_indent", 2)
        self.include_raw_data = output_config.get("include_raw_data", False)
        
    def generate(self, results: Dict[str, Any], 
                execution_stats: Optional[Dict[str, Any]] = None,
                custom_filename: Optional[str] = None) -> str:
        """
        Generate comprehensive JSON report.
        
        Args:
            results: Scan results from all modules
            execution_stats: Optional execution statistics
            custom_filename: Optional custom filename (without extension)
            
        Returns:
            Path to generated JSON report file
        """
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Generate filename
        if custom_filename:
            json_path = os.path.join(self.output_dir, f"{custom_filename}.json")
        else:
            timestamp = datetime.now().strftime(self.timestamp_format)
            json_path = os.path.join(self.output_dir, f"credfinder_report_{timestamp}.json")
        
        # Build comprehensive report structure
        report_data = self._build_report_structure(results, execution_stats)
        
        # Write JSON report with error handling
        try:
            # Estimate JSON size before writing
            import json as json_module
            json_str = json_module.dumps(report_data, indent=self.json_indent, 
                                       default=self._json_serializer, ensure_ascii=False)
            estimated_size_mb = len(json_str.encode('utf-8')) / (1024 * 1024)
            
            # Warn if the JSON will be very large
            if estimated_size_mb > 50:
                print(f"WARNING: JSON report will be very large ({estimated_size_mb:.1f}MB). "
                      f"Consider reducing scan scope in config.json")
            elif estimated_size_mb > 10:
                print(f"INFO: JSON report size: {estimated_size_mb:.1f}MB")
            
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            
            return json_path
            
        except Exception as e:
            raise Exception(f"Failed to generate JSON report: {e}")
    
    def _build_report_structure(self, results: Dict[str, Any], 
                               execution_stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Build comprehensive JSON report structure."""
        
        # Process and categorize findings
        processed_results = self._process_findings(results)
        
        # Build report structure
        report_data = {
            "report_info": {
                "format": "json",
                "version": "2.0",
                "generated_at": datetime.now().isoformat(),
                "generator": "credfinder-linux-json-reporter"
            },
            "scan_summary": self._build_scan_summary(results, execution_stats),
            "findings": processed_results
        }
        
        # Add metadata if enabled
        if self.include_metadata:
            report_data["metadata"] = self._build_metadata(execution_stats)
        
        # Add raw data if enabled
        if self.include_raw_data:
            report_data["raw_data"] = results
            
        return report_data
    
    def _process_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process findings into structured format with categorization."""
        processed_findings = {}
        
        for module_name, module_data in results.items():
            try:
                processed_findings[module_name] = self._process_module_findings(module_name, module_data)
            except Exception as e:
                processed_findings[module_name] = {
                    "status": "error",
                    "error_message": str(e),
                    "findings": []
                }
        
        return processed_findings
    
    def _process_module_findings(self, module_name: str, module_data: Any) -> Dict[str, Any]:
        """Process findings for a specific module."""
        
        # Handle modules with status information (failed/skipped/timeout)
        if isinstance(module_data, dict) and '_status' in module_data:
            status = module_data['_status']
            return {
                "status": status,
                "error_message": module_data.get('_error', 'Unknown error'),
                "findings": [],
                "finding_count": 0
            }
        
        # Process normal module findings
        findings = []
        
        if module_name == "ssh":
            findings = self._categorize_ssh_findings(module_data)
        elif module_name == "browser":
            findings = self._categorize_browser_findings(module_data)
        elif module_name == "keyring":
            findings = self._categorize_keyring_findings(module_data)
        elif module_name == "history":
            findings = self._categorize_history_findings(module_data)
        elif module_name == "dotfiles":
            findings = self._categorize_dotfile_findings(module_data)
        elif module_name == "file_grep":
            findings = self._categorize_file_grep_findings(module_data)
        else:
            # Generic processing for unknown modules
            findings = self._categorize_generic_findings(module_data)
        
        return {
            "status": "success",
            "findings": findings,
            "finding_count": len(findings),
            "risk_assessment": self._assess_module_risk(findings)
        }
    
    def _categorize_ssh_findings(self, ssh_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize SSH module findings."""
        findings = []
        
        # Process private keys
        if 'private_keys' in ssh_data and ssh_data['private_keys']:
            for key in ssh_data['private_keys']:
                findings.append({
                    "type": "ssh_private_key",
                    "severity": "critical" if not key.get('encrypted', True) else "warning",
                    "category": "authentication_credential",
                    "details": {
                        "path": key.get('path', 'Unknown'),
                        "encrypted": key.get('encrypted', False),
                        "permissions": key.get('permissions', 'Unknown'),
                        "secure_permissions": key.get('secure_permissions', False),
                        "size_bytes": key.get('size', 0),
                        "owner": key.get('owner', 'Unknown')
                    },
                    "risk_score": 9 if not key.get('encrypted', True) else 6,
                    "remediation": "Encrypt private key and set proper permissions (600)" if not key.get('encrypted', True) else "Verify key usage and consider encryption"
                })
        
        # Process SSH agent identities
        if 'ssh_agent' in ssh_data and ssh_data['ssh_agent'].get('running'):
            agent = ssh_data['ssh_agent']
            if agent.get('identities'):
                for identity in agent['identities']:
                    findings.append({
                        "type": "ssh_agent_identity",
                        "severity": "critical",
                        "category": "active_credential",
                        "details": {
                            "fingerprint": identity.get('fingerprint', 'Unknown'),
                            "key_type": identity.get('key_type', 'Unknown'),
                            "comment": identity.get('comment', '')
                        },
                        "risk_score": 8,
                        "remediation": "Review SSH agent usage and remove unnecessary identities"
                    })
        
        # Process authorized keys
        if 'authorized_keys' in ssh_data and ssh_data['authorized_keys']:
            for auth_key in ssh_data['authorized_keys']:
                findings.append({
                    "type": "ssh_authorized_key",
                    "severity": "info",
                    "category": "access_control",
                    "details": {
                        "file": auth_key.get('file', 'Unknown'),
                        "key_type": auth_key.get('key_type', 'Unknown'),
                        "comment": auth_key.get('comment', '')
                    },
                    "risk_score": 3,
                    "remediation": "Review authorized keys for unauthorized access"
                })
        
        return findings
    
    def _categorize_browser_findings(self, browser_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize browser module findings."""
        findings = []
        
        for browser_type, browser_info in browser_data.items():
            if not isinstance(browser_info, dict):
                continue
                
            # Process passwords
            if 'passwords' in browser_info and browser_info['passwords']:
                for entry in browser_info['passwords']:
                    if isinstance(entry, dict):
                        findings.append({
                            "type": "browser_credential",
                            "severity": "critical",
                            "category": "stored_credential",
                            "details": {
                                "browser": browser_type,
                                "url": entry.get('url', 'Unknown'),
                                "username": entry.get('username', 'Unknown'),
                                "encrypted": entry.get('encrypted', True),
                                "decrypted": entry.get('decrypted', False),
                                "profile_path": entry.get('profile_path', 'Unknown')
                            },
                            "risk_score": 9 if entry.get('decrypted', False) else 7,
                            "remediation": "Use password manager and clear browser-stored credentials"
                        })
        
        return findings
    
    def _categorize_keyring_findings(self, keyring_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize keyring module findings."""
        findings = []
        
        for keyring_type, keyring_info in keyring_data.items():
            if isinstance(keyring_info, dict) and keyring_info.get("items"):
                for item in keyring_info["items"]:
                    findings.append({
                        "type": "keyring_item",
                        "severity": "critical",
                        "category": "stored_credential",
                        "details": {
                            "keyring_type": keyring_type,
                            "attributes": item.get('attributes', {}),
                            "has_secret": bool(item.get('secret')),
                            "service": item.get('attributes', {}).get('service', 'Unknown')
                        },
                        "risk_score": 8,
                        "remediation": "Review keyring contents and remove unnecessary secrets"
                    })
        
        return findings
    
    def _categorize_history_findings(self, history_data: Any) -> List[Dict[str, Any]]:
        """Categorize command history findings."""
        findings = []
        
        if isinstance(history_data, list):
            for entry in history_data:
                if isinstance(entry, dict):
                    findings.append({
                        "type": "command_history_credential",
                        "severity": self._map_risk_to_severity(entry.get('risk_level', 'low')),
                        "category": "exposed_credential",
                        "details": {
                            "file": entry.get('file', 'Unknown'),
                            "line_number": entry.get('line_number', 0),
                            "command_snippet": entry.get('command', '')[:100],
                            "pattern_matches": entry.get('pattern_matches', [])
                        },
                        "risk_score": self._calculate_risk_score(entry.get('risk_level', 'low')),
                        "remediation": "Remove sensitive commands from history and use environment variables"
                    })
        
        return findings
    
    def _categorize_dotfile_findings(self, dotfile_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize dotfile findings."""
        findings = []
        
        for file_type, file_list in dotfile_data.items():
            if isinstance(file_list, list):
                for file_entry in file_list:
                    if isinstance(file_entry, dict):
                        findings.append({
                            "type": "dotfile_credential",
                            "severity": "warning",
                            "category": "configuration_credential",
                            "details": {
                                "file": file_entry.get('file', 'Unknown'),
                                "file_type": file_type,
                                "pattern_matches": file_entry.get('pattern_matches', [])
                            },
                            "risk_score": 5,
                            "remediation": "Move credentials to secure configuration management"
                        })
        
        return findings
    
    def _categorize_file_grep_findings(self, file_grep_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize file grep findings."""
        findings = []
        
        file_matches = file_grep_data.get('file_matches', [])
        for match in file_matches:
            if isinstance(match, dict):
                findings.append({
                    "type": "file_pattern_match",
                    "severity": "warning",
                    "category": "potential_credential",
                    "details": {
                        "file": match.get('file', 'Unknown'),
                        "pattern_matches": match.get('pattern_matches', []),
                        "file_size_bytes": match.get('file_size', 0)
                    },
                    "risk_score": 4,
                    "remediation": "Review file contents and secure any credentials found"
                })
        
        return findings
    
    def _categorize_generic_findings(self, module_data: Any) -> List[Dict[str, Any]]:
        """Generic categorization for unknown module types."""
        findings = []
        
        if isinstance(module_data, list):
            for i, item in enumerate(module_data):
                findings.append({
                    "type": "generic_finding",
                    "severity": "info",
                    "category": "unknown",
                    "details": {
                        "item_index": i,
                        "data": item
                    },
                    "risk_score": 2,
                    "remediation": "Review finding for potential security implications"
                })
        elif isinstance(module_data, dict) and module_data:
            findings.append({
                "type": "generic_data",
                "severity": "info", 
                "category": "unknown",
                "details": module_data,
                "risk_score": 2,
                "remediation": "Review data for potential security implications"
            })
        
        return findings
    
    def _assess_module_risk(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk for a module's findings."""
        if not findings:
            return {"level": "none", "score": 0, "critical_count": 0}
        
        total_score = sum(finding.get('risk_score', 0) for finding in findings)
        avg_score = total_score / len(findings) if findings else 0
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        
        if avg_score >= 8 or critical_count >= 3:
            level = "critical"
        elif avg_score >= 6 or critical_count >= 1:
            level = "high"
        elif avg_score >= 4:
            level = "medium" 
        else:
            level = "low"
        
        return {
            "level": level,
            "score": round(avg_score, 2),
            "critical_count": critical_count,
            "total_findings": len(findings)
        }
    
    def _build_scan_summary(self, results: Dict[str, Any], 
                           execution_stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Build scan summary statistics."""
        total_modules = len(results)
        successful_modules = 0
        failed_modules = 0
        total_findings = 0
        critical_findings = 0
        
        for module_name, module_data in results.items():
            if isinstance(module_data, dict) and '_status' in module_data:
                if module_data['_status'] in ['failed', 'skipped', 'timeout']:
                    failed_modules += 1
                else:
                    successful_modules += 1
            else:
                successful_modules += 1
                findings = self._process_module_findings(module_name, module_data)
                finding_count = findings.get('finding_count', 0)
                total_findings += finding_count
                
                # Count critical findings
                critical_findings += sum(1 for f in findings.get('findings', []) 
                                       if f.get('severity') == 'critical')
        
        summary = {
            "total_modules": total_modules,
            "successful_modules": successful_modules,
            "failed_modules": failed_modules,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "scan_status": "completed"
        }
        
        # Add execution stats if available
        if execution_stats:
            summary["execution_time_seconds"] = execution_stats.get('total_time', 0)
            summary["start_time"] = execution_stats.get('start_time', '')
            summary["end_time"] = execution_stats.get('end_time', '')
        
        return summary
    
    def _build_metadata(self, execution_stats: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Build comprehensive metadata."""
        return {
            "tool_info": {
                "name": "credfinder-linux",
                "version": "2.0.0",
                "component": "json-reporter",
                "description": "Linux Credential & Secret Hunting Toolkit"
            },
            "system_info": {
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "python_version": platform.python_version()
            },
            "scan_environment": {
                "working_directory": os.getcwd(),
                "output_directory": self.output_dir,
                "config_source": "config.json"
            },
            "execution_stats": execution_stats or {}
        }
    
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
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj) 