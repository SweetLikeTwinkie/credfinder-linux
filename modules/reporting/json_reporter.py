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
                module_result = self._process_module_findings(module_name, module_data)
                
                # Only include modules that have actual findings or errors
                if (module_result.get("status") == "error" or 
                    (module_result.get("findings") and len(module_result["findings"]) > 0)):
                    processed_findings[module_name] = module_result
                    
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
        elif module_name == "git":
            findings = self._categorize_git_findings(module_data)
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
                            "remediation": self._get_remediation_message("dotfile_credential")
                        })
        
        return findings
    
    def _categorize_file_grep_findings(self, file_grep_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize file grep findings."""
        findings = []
        
        file_matches = file_grep_data.get('file_matches', [])
        for match in file_matches:
            if isinstance(match, dict):
                # Filter out false positives from pattern matches
                filtered_matches = self._filter_false_positive_matches(match.get('pattern_matches', []))
                
                if filtered_matches:  # Only create finding if there are real matches
                    findings.append({
                        "type": "file_pattern_match",
                        "severity": "warning",
                        "category": "potential_credential",
                        "details": {
                            "file": match.get('file', 'Unknown'),
                            "pattern_matches": filtered_matches,
                            "file_size_bytes": match.get('file_size', 0)
                        },
                        "risk_score": 4,
                        "remediation": self._get_remediation_message("file_pattern_match")
                    })
        
        return findings
    
    def _categorize_git_findings(self, git_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Categorize git findings - only actual credential discoveries, not repository metadata."""
        findings = []
        
        # Process commit history findings (actual credentials found in commits)
        commit_history = git_data.get('commit_history', [])
        for commit_finding in commit_history:
            if isinstance(commit_finding, dict) and commit_finding.get('matches'):
                # Filter out obvious false positives
                filtered_matches = self._filter_false_positive_matches(commit_finding.get('matches', []))
                
                if filtered_matches:  # Only create finding if there are real matches
                    findings.append({
                        "type": "git_commit_credential",
                        "severity": "critical",
                        "category": "version_control_credential",
                        "details": {
                            "repository": commit_finding.get('repository', 'Unknown'),
                            "commit_hash": commit_finding.get('commit', {}).get('hash', 'Unknown'),
                            "commit_message": commit_finding.get('commit', {}).get('message', 'Unknown'),
                            "author": commit_finding.get('commit', {}).get('author', 'Unknown'),
                            "date": commit_finding.get('commit', {}).get('date', 'Unknown'),
                            "pattern_matches": filtered_matches
                        },
                        "risk_score": 9,
                        "remediation": self._get_remediation_message("git_commit_credential")
                    })
        
        # Process git config credentials
        config_credentials = git_data.get('config_credentials', [])
        for config_finding in config_credentials:
            if isinstance(config_finding, dict) and config_finding.get('matches'):
                filtered_matches = self._filter_false_positive_matches(config_finding.get('matches', []))
                
                if filtered_matches:
                    findings.append({
                        "type": "git_config_credential",
                        "severity": "critical",
                        "category": "configuration_credential",
                        "details": {
                            "repository": config_finding.get('repository', 'Unknown'),
                            "config_file": config_finding.get('config_file', 'Unknown'),
                            "config_type": config_finding.get('type', 'Unknown'),
                            "pattern_matches": filtered_matches
                        },
                        "risk_score": 8,
                        "remediation": self._get_remediation_message("git_config_credential")
                    })
        
        # Process remote URLs with embedded credentials
        remote_urls = git_data.get('remote_urls', [])
        for remote_finding in remote_urls:
            if isinstance(remote_finding, dict):
                findings.append({
                    "type": "git_remote_credential",
                    "severity": "critical",
                    "category": "url_credential",
                    "details": {
                        "repository": remote_finding.get('repository', 'Unknown'),
                        "remote_name": remote_finding.get('remote_name', 'Unknown'),
                        "url": remote_finding.get('url', 'Unknown'),
                        "credential_type": remote_finding.get('credential_type', 'Unknown')
                    },
                    "risk_score": 9,
                    "remediation": self._get_remediation_message("git_remote_credential")
                })
        
        # Process sensitive files with credential content
        sensitive_files = git_data.get('sensitive_files', [])
        for file_finding in sensitive_files:
            if isinstance(file_finding, dict) and file_finding.get('content_matches'):
                filtered_matches = self._filter_false_positive_matches(file_finding.get('content_matches', []))
                
                if filtered_matches:
                    findings.append({
                        "type": "git_sensitive_file",
                        "severity": "warning",
                        "category": "file_credential",
                        "details": {
                            "repository": file_finding.get('repository', 'Unknown'),
                            "file_path": file_finding.get('file_path', 'Unknown'),
                            "exists": file_finding.get('exists', False),
                            "pattern_matched": file_finding.get('pattern_matched', 'Unknown'),
                            "content_matches": filtered_matches
                        },
                        "risk_score": 6,
                        "remediation": self._get_remediation_message("git_sensitive_file")
                    })
        
        # Process recently deleted files (potential credential cleanup attempts)
        recent_deletions = git_data.get('recent_deletions', [])
        for deletion_finding in recent_deletions:
            if isinstance(deletion_finding, dict):
                findings.append({
                    "type": "git_deleted_credential",
                    "severity": "info",
                    "category": "historical_credential",
                    "details": {
                        "repository": deletion_finding.get('repository', 'Unknown'),
                        "deleted_file": deletion_finding.get('deleted_file', 'Unknown'),
                        "commit_info": deletion_finding.get('commit_info', {}),
                        "pattern_matched": deletion_finding.get('pattern_matched', 'Unknown')
                    },
                    "risk_score": 4,
                    "remediation": self._get_remediation_message("git_deleted_credential")
                })
        
        # NOTE: We explicitly do NOT include 'repositories' data as findings
        # That's just metadata about discovered repositories, not credential findings
        
        return findings
    
    def _filter_false_positive_matches(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out obvious false positives from pattern matches."""
        if not matches:
            return []
        
        filtered_matches = []
        
        for match in matches:
            if not isinstance(match, dict):
                continue
                
            match_text = match.get('match', '').lower()
            context = match.get('context', '').lower()
            pattern_type = match.get('pattern_type', '')
            
            # Skip obvious false positives
            if self._is_false_positive_match(match_text, context, pattern_type):
                continue
                
            filtered_matches.append(match)
        
        return filtered_matches
    
    def _is_false_positive_match(self, match_text: str, context: str, pattern_type: str) -> bool:
        """Check if a match is likely a false positive."""
        
        # Get patterns from config
        false_positive_filters = self.config.get('reporting', {}).get('false_positive_filters', {})
        
        programming_patterns = false_positive_filters.get('programming_patterns', [])
        dotnet_patterns = false_positive_filters.get('dotnet_patterns', [])
        comment_patterns = false_positive_filters.get('comment_patterns', [])
        test_patterns = false_positive_filters.get('test_patterns', [])
        path_patterns = false_positive_filters.get('path_patterns', [])
        git_diff_patterns = false_positive_filters.get('git_diff_patterns', [])
        config_regex_patterns = false_positive_filters.get('config_regex_patterns', [])
        doc_patterns = false_positive_filters.get('documentation_patterns', [])
        env_doc_patterns = false_positive_filters.get('env_documentation_patterns', [])
        library_api_patterns = false_positive_filters.get('library_api_patterns', [])
        vendor_dependency_patterns = false_positive_filters.get('vendor_dependency_patterns', [])
        
        # Check if match contains any false positive patterns
        all_patterns = (programming_patterns + dotnet_patterns + comment_patterns + 
                       test_patterns + path_patterns + git_diff_patterns + 
                       config_regex_patterns + doc_patterns + env_doc_patterns +
                       library_api_patterns + vendor_dependency_patterns)
        
        for pattern in all_patterns:
            if pattern in match_text or pattern in context:
                return True
        
        # Special checks for database URLs that are just regex patterns
        if pattern_type == 'database_urls':
            if any(x in match_text for x in ['[^\\s', '^\\s', ']\\"', '\"+', '\"],', '\",', '\\" ]']):
                return True
            if 'user:pass@host/db' in match_text:
                return True
            # Check if this is a regex pattern in config files
            if any(x in context for x in ['url_credential_patterns', '"^', '\\"^', 'config.json']):
                return True
            # Check for regex escape patterns
            if '\\\\s' in match_text or '\\\\' in match_text:
                return True
        
        # Special checks for private key patterns that are just comments or partial matches
        if pattern_type == 'private_keys':
            if any(x in context for x in ['# -*-', 'signature primitive', 'written in', 'copyright', ':parameters:']):
                return True
            # Empty matches or just spaces/punctuation
            if not match_text.strip() or match_text.strip().lower() in ['rsa ', 'dsa ', 'ec ', 'openssh ', 'rsa', 'dsa', 'ec', 'openssh']:
                return True
            # Code that mentions key types but isn't actual keys
            if any(x in context for x in ['return pem.encode', 'key object', 'if a private']):
                return True
        
        # Check for environment variable patterns that are just function parameters or documentation
        if pattern_type == 'environment_vars':
            if any(x in match_text for x in ['=self.', '=args.', '(', ')', ',', '"', "'", 'backend=', 'frozenset']):
                return True
            # Documentation patterns
            if 'python_keyring_backend=' in match_text.lower() and '``' in context:
                return True
        
        # Password patterns that are just user prompts or documentation
        if pattern_type == 'passwords':
            if any(x in match_text for x in ['getpass(\"', 'password:\")', 'new password:', 'current password:', 'retype']):
                return True
            if any(x in context for x in ['getpass', 'import getpass', 'logging.', 'try:', 'except:']):
                return True
            # Documentation patterns
            if any(x in context for x in ['.md\'', 'password.md', 'get-', 'set-', 'privesc/']):
                return True
            # Standard attribute names and certificate OIDs
            if any(x in match_text.lower() for x in ['challenge_password', 'challengepassword']):
                return True
            if any(x in context for x in ['attributeoid', 'oid.', 'certificate', 'x509']):
                return True
            # String formatting templates (Python, Go, etc.)
            if any(x in match_text for x in ['%s', '{0}', '{1}', '{2}', '{3}', '{4}']):
                return True
            if any(x in context for x in ['.format(', '% (', 'hexlify(', '.decode(', 'secretsdump']):
                return True
        
        # AWS keys that are clearly examples
        if pattern_type == 'aws_keys':
            if 'example' in match_text or 'akiaiosfodnn7example' in match_text:
                return True
        
        # Check for vendor/dependency files and CI files in context
        if any(x in context.lower() for x in ['vendor/', '.travis.yml', 'appveyor.yml', 'github.com/', 'node_modules/', 'site-packages/']):
            return True
            
        # Check for library/API files that handle credentials but don't contain them
        if any(x in context.lower() for x in ['credentials.go', 'credentials_info.go', 'impacket/examples/', 'secretsdump.py']):
            return True
        
        return False
    
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
        risk_mappings = self.config.get('reporting', {}).get('risk_mappings', {})
        severity_mapping = risk_mappings.get('severity_mapping', {
            'critical': 'critical',
            'high': 'critical', 
            'medium': 'warning',
            'low': 'info'
        })
        return severity_mapping.get(risk_level.lower(), 'info')
    
    def _calculate_risk_score(self, risk_level: str) -> int:
        """Calculate numerical risk score."""
        risk_mappings = self.config.get('reporting', {}).get('risk_mappings', {})
        risk_scores = risk_mappings.get('risk_scores', {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3
        })
        return risk_scores.get(risk_level.lower(), 3)

    def _get_remediation_message(self, finding_type: str) -> str:
        """Get remediation message from config."""
        remediation_messages = self.config.get('reporting', {}).get('remediation_messages', {})
        return remediation_messages.get(finding_type, "Review finding for potential security implications")
    
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