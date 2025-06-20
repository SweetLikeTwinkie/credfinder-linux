#!/usr/bin/env python3
"""
Report Generator Module
Generates reports in JSON, HTML, CSV, and console formats
"""

import os
import json
import csv
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Any, Dict, List

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get("output", {}).get("output_dir", "./reports")
        self.template_path = config.get("output", {}).get("report_template", "templates/report.html")

    def generate(self, results: Dict[str, Any], format_type: str = "json") -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        report_path = os.path.join(self.output_dir, f"credfinder_report.{format_type}")
        if format_type == "json":
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif format_type == "csv":
            self._generate_csv(results, report_path)
        elif format_type == "html":
            self._generate_html(results, report_path)
        elif format_type == "console":
            self._generate_console(results)
            report_path = "console"
        return report_path

    def _generate_csv(self, results: Dict[str, Any], report_path: str):
        # Flatten results for CSV output
        with open(report_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Module", "Finding"])
            for module, findings in results.items():
                if isinstance(findings, list):
                    for finding in findings:
                        writer.writerow([module, json.dumps(finding)])
                else:
                    writer.writerow([module, json.dumps(findings)])

    def _generate_html(self, results: Dict[str, Any], report_path: str):
        # Use Jinja2 template for HTML report
        template_dir = os.path.dirname(self.template_path) or '.'
        template_file = os.path.basename(self.template_path)
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        if not os.path.exists(self.template_path):
            # Fallback: simple HTML if template missing
            html = f"<html><body><h1>credfinder Report</h1><pre>{json.dumps(results, indent=2)}</pre></body></html>"
            with open(report_path, 'w') as f:
                f.write(html)
            return
        
        # Process and categorize findings
        processed_results = self._process_findings(results)
        
        # Calculate statistics for the template
        total_findings = 0
        critical_findings = 0
        warning_findings = 0
        modules_run = len(results)
        
        for module, findings in processed_results.items():
            if isinstance(findings, list):
                total_findings += len(findings)
                for finding in findings:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'warning')
                        if severity == 'critical':
                            critical_findings += 1
                        elif severity == 'warning':
                            warning_findings += 1
                    else:
                        warning_findings += 1
            elif findings:
                total_findings += 1
                warning_findings += 1
        
        # Prepare template context
        from datetime import datetime
        template_context = {
            'results': processed_results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'warning_findings': warning_findings,
            'modules_run': modules_run
        }
        
        template = env.get_template(template_file)
        html = template.render(**template_context)
        with open(report_path, 'w') as f:
            f.write(html)
    
    def _process_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        # Pass raw findings directly for all modules
        return results
    
    def _categorize_finding(self, finding: Any, module_name: str) -> Dict[str, Any]:
        """Categorize a finding with severity and type information"""
        if not isinstance(finding, dict):
            return {
                'type': 'raw_data',
                'severity': 'info',
                'data': finding
            }
        
        # Special handling for different modules
        if module_name == 'ssh':
            return self._categorize_ssh_finding(finding)
        elif module_name == 'browser':
            return self._categorize_browser_finding(finding)
        elif module_name == 'keyring':
            return self._categorize_keyring_finding(finding)
        elif module_name == 'memory':
            return self._categorize_memory_finding(finding)
        elif module_name == 'dotfiles':
            return self._categorize_dotfile_finding(finding)
        elif module_name == 'history':
            return self._categorize_history_finding(finding)
        
        # Default categorization for other modules
        severity = 'info'
        finding_type = 'finding'
        
        # Check for critical indicators
        finding_str = str(finding).lower()
        if any(keyword in finding_str for keyword in ['password', 'secret', 'token', 'key', 'credential']):
            severity = 'critical'
            finding_type = 'credential'
        elif any(keyword in finding_str for keyword in ['error', 'failed', 'denied']):
            severity = 'warning'
            finding_type = 'error'
        
        # Add metadata
        processed_finding = {
            'type': finding_type,
            'severity': severity,
            'module': module_name,
            **finding
        }
        
        return processed_finding
    
    def _categorize_ssh_finding(self, ssh_data: Dict[str, Any]) -> Dict[str, Any]:
        """Special categorization for SSH module findings"""
        categorized_findings = []
        
        # Process private keys
        if 'private_keys' in ssh_data and ssh_data['private_keys']:
            for key in ssh_data['private_keys']:
                severity = 'critical' if not key.get('encrypted', True) else 'warning'
                categorized_findings.append({
                    'type': 'ssh_private_key',
                    'severity': severity,
                    'module': 'ssh',
                    'category': 'Private Key',
                    'path': key.get('path', 'Unknown'),
                    'encrypted': key.get('encrypted', False),
                    'permissions': key.get('permissions', 'Unknown'),
                    'secure_permissions': key.get('secure_permissions', False),
                    'size': key.get('size', 0),
                    'owner': key.get('owner', 'Unknown'),
                    'risk_level': 'High' if not key.get('encrypted', True) else 'Medium'
                })
        
        # Process public keys
        if 'public_keys' in ssh_data and ssh_data['public_keys']:
            for key in ssh_data['public_keys']:
                categorized_findings.append({
                    'type': 'ssh_public_key',
                    'severity': 'info',
                    'module': 'ssh',
                    'category': 'Public Key',
                    'path': key.get('path', 'Unknown'),
                    'key_type': key.get('key_type', 'Unknown'),
                    'comment': key.get('comment', ''),
                    'size': key.get('size', 0),
                    'owner': key.get('owner', 'Unknown'),
                    'risk_level': 'Low'
                })
        
        # Process SSH agent
        if 'ssh_agent' in ssh_data and ssh_data['ssh_agent']:
            agent = ssh_data['ssh_agent']
            if agent.get('running', False) and agent.get('identities'):
                for identity in agent['identities']:
                    categorized_findings.append({
                        'type': 'ssh_agent_identity',
                        'severity': 'critical',
                        'module': 'ssh',
                        'category': 'SSH Agent Identity',
                        'fingerprint': identity.get('fingerprint', 'Unknown'),
                        'key_type': identity.get('key_type', 'Unknown'),
                        'comment': identity.get('comment', ''),
                        'risk_level': 'High'
                    })
            elif agent.get('running', False):
                categorized_findings.append({
                    'type': 'ssh_agent_status',
                    'severity': 'info',
                    'module': 'ssh',
                    'category': 'SSH Agent Status',
                    'status': 'Running (no identities loaded)',
                    'socket': agent.get('socket', 'Unknown'),
                    'risk_level': 'Low'
                })
        
        # Process known_hosts
        if 'known_hosts' in ssh_data and ssh_data['known_hosts']:
            for known_host in ssh_data['known_hosts']:
                categorized_findings.append({
                    'type': 'ssh_known_hosts',
                    'severity': 'warning',
                    'module': 'ssh',
                    'category': 'Known Hosts',
                    'path': known_host.get('path', 'Unknown'),
                    'host_count': known_host.get('count', 0),
                    'owner': known_host.get('owner', 'Unknown'),
                    'risk_level': 'Medium'
                })
        
        # Process config files
        if 'config_files' in ssh_data and ssh_data['config_files']:
            for config in ssh_data['config_files']:
                categorized_findings.append({
                    'type': 'ssh_config',
                    'severity': 'info',
                    'module': 'ssh',
                    'category': 'SSH Config',
                    'path': config.get('path', 'Unknown'),
                    'config_count': len(config.get('configs', [])),
                    'owner': config.get('owner', 'Unknown'),
                    'risk_level': 'Low'
                })
        
        return categorized_findings

    def _generate_console(self, results: Dict[str, Any]):
        print("\n===== credfinder Report =====\n")
        for module, findings in results.items():
            print(f"--- {module.upper()} ---")
            if isinstance(findings, list):
                for finding in findings:
                    print(json.dumps(finding, indent=2, default=str))
            else:
                print(json.dumps(findings, indent=2, default=str))
            print()

    def _categorize_browser_finding(self, browser_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for browser module findings"""
        categorized_findings = []
        
        # Process Chrome/Chromium data
        if 'chrome' in browser_data and browser_data['chrome']:
            chrome_data = browser_data['chrome']
            
            # Process passwords
            if 'passwords' in chrome_data and chrome_data['passwords']:
                for entry in chrome_data['passwords']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'critical',
                            'module': 'browser',
                            'category': 'Chrome Password',
                            'browser': 'Chrome/Chromium',
                            'url': entry.get('url', 'Unknown'),
                            'username': entry.get('username', 'Unknown'),
                            'password': '***HIDDEN***' if entry.get('password') else 'Not stored',
                            'encrypted': entry.get('encrypted', False),
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'High'
                        })
            
            # Process cookies
            if 'cookies' in chrome_data and chrome_data['cookies']:
                for entry in chrome_data['cookies']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'warning',
                            'module': 'browser',
                            'category': 'Chrome Cookie',
                            'browser': 'Chrome/Chromium',
                            'host': entry.get('host', 'Unknown'),
                            'name': entry.get('name', 'Unknown'),
                            'value': '***HIDDEN***' if entry.get('value') else 'Not stored',
                            'encrypted': entry.get('encrypted', False),
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'Medium'
                        })
        
        # Process Brave data
        if 'brave' in browser_data and browser_data['brave']:
            brave_data = browser_data['brave']
            
            # Process passwords
            if 'passwords' in brave_data and brave_data['passwords']:
                for entry in brave_data['passwords']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'critical',
                            'module': 'browser',
                            'category': 'Brave Password',
                            'browser': 'Brave',
                            'url': entry.get('url', 'Unknown'),
                            'username': entry.get('username', 'Unknown'),
                            'password': '***HIDDEN***' if entry.get('password') else 'Not stored',
                            'encrypted': entry.get('encrypted', False),
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'High'
                        })
        
        # Process Chromium data
        if 'chromium' in browser_data and browser_data['chromium']:
            chromium_data = browser_data['chromium']
            
            # Process passwords
            if 'passwords' in chromium_data and chromium_data['passwords']:
                for entry in chromium_data['passwords']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'critical',
                            'module': 'browser',
                            'category': 'Chromium Password',
                            'browser': 'Chromium',
                            'url': entry.get('url', 'Unknown'),
                            'username': entry.get('username', 'Unknown'),
                            'password': '***HIDDEN***' if entry.get('password') else 'Not stored',
                            'encrypted': entry.get('encrypted', False),
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'High'
                        })
        
        # Process Firefox data
        if 'firefox' in browser_data and browser_data['firefox']:
            firefox_data = browser_data['firefox']
            
            # Process passwords
            if 'passwords' in firefox_data and firefox_data['passwords']:
                for entry in firefox_data['passwords']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'critical',
                            'module': 'browser',
                            'category': 'Firefox Password',
                            'browser': 'Firefox',
                            'url': entry.get('url', 'Unknown'),
                            'username': entry.get('username', 'Unknown'),
                            'password': '***HIDDEN***' if entry.get('password') else 'Not stored',
                            'encrypted': entry.get('encrypted', False),
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'High'
                        })
            
            # Process cookies
            if 'cookies' in firefox_data and firefox_data['cookies']:
                for entry in firefox_data['cookies']:
                    if isinstance(entry, dict):
                        categorized_findings.append({
                            'type': 'browser_credential',
                            'severity': 'warning',
                            'module': 'browser',
                            'category': 'Firefox Cookie',
                            'browser': 'Firefox',
                            'host': entry.get('host', 'Unknown'),
                            'name': entry.get('name', 'Unknown'),
                            'value': '***HIDDEN***' if entry.get('value') else 'Not stored',
                            'profile_path': entry.get('profile_path', 'Unknown'),
                            'risk_level': 'Medium'
                        })
        
        return categorized_findings
    
    def _categorize_keyring_finding(self, keyring_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for keyring module findings"""
        categorized_findings = []
        
        # Process GNOME Keyring
        if 'gnome_keyring' in keyring_data and keyring_data['gnome_keyring']:
            gnome_data = keyring_data['gnome_keyring']
            if 'items' in gnome_data and gnome_data['items']:
                for item in gnome_data['items']:
                    categorized_findings.append({
                        'type': 'keyring_entry',
                        'severity': 'critical',
                        'module': 'keyring',
                        'category': 'GNOME Keyring Entry',
                        'keyring_type': 'GNOME Keyring',
                        'attributes': item.get('attributes', {}),
                        'secret': '***HIDDEN***' if item.get('secret') else 'Not accessible',
                        'risk_level': 'High'
                    })
        
        # Process KWallet
        if 'kwallet' in keyring_data and keyring_data['kwallet']:
            kwallet_data = keyring_data['kwallet']
            if 'items' in kwallet_data and kwallet_data['items']:
                for item in kwallet_data['items']:
                    categorized_findings.append({
                        'type': 'keyring_entry',
                        'severity': 'critical',
                        'module': 'keyring',
                        'category': 'KWallet Entry',
                        'keyring_type': 'KWallet',
                        'key': item.get('key', 'Unknown'),
                        'value': '***HIDDEN***' if item.get('value') else 'Not accessible',
                        'risk_level': 'High'
                    })
        
        # Process secret-tool
        if 'secret_tool' in keyring_data and keyring_data['secret_tool']:
            secret_data = keyring_data['secret_tool']
            if 'items' in secret_data and secret_data['items']:
                for item in secret_data['items']:
                    categorized_findings.append({
                        'type': 'keyring_entry',
                        'severity': 'critical',
                        'module': 'keyring',
                        'category': 'Secret Tool Entry',
                        'keyring_type': 'Secret Tool',
                        'attributes': item.get('attributes', {}),
                        'secret': '***HIDDEN***' if item.get('secret') else 'Not accessible',
                        'risk_level': 'High'
                    })
        
        return categorized_findings
    
    def _categorize_memory_finding(self, memory_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for memory module findings"""
        categorized_findings = []
        
        if isinstance(memory_data, list):
            for finding in memory_data:
                if isinstance(finding, dict):
                    # Determine severity based on content
                    content = str(finding).lower()
                    severity = 'critical' if any(keyword in content for keyword in ['password', 'secret', 'token', 'key']) else 'warning'
                    
                    categorized_findings.append({
                        'type': 'memory_secret',
                        'severity': severity,
                        'module': 'memory',
                        'category': 'Memory Secret',
                        'source': finding.get('source', 'Unknown'),
                        'pattern': finding.get('pattern', 'Unknown'),
                        'matches': finding.get('matches', []),
                        'risk_level': 'High' if severity == 'critical' else 'Medium'
                    })
        
        return categorized_findings
    
    def _categorize_dotfile_finding(self, dotfile_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for dotfile module findings"""
        categorized_findings = []
        
        if isinstance(dotfile_data, list):
            for finding in dotfile_data:
                if isinstance(finding, dict):
                    # Determine severity based on file type and content
                    file_path = finding.get('file', '')
                    content = str(finding).lower()
                    
                    severity = 'info'
                    finding_type = 'dotfile_config'
                    
                    if any(keyword in content for keyword in ['password', 'secret', 'token', 'key']):
                        severity = 'critical'
                        finding_type = 'dotfile_credential'
                    elif any(keyword in file_path for keyword in ['.env', '.aws', '.git']):
                        severity = 'warning'
                        finding_type = 'dotfile_sensitive'
                    
                    categorized_findings.append({
                        'type': finding_type,
                        'severity': severity,
                        'module': 'dotfiles',
                        'category': 'Dotfile Finding',
                        'file': finding.get('file', 'Unknown'),
                        'line': finding.get('line', 'Unknown'),
                        'content': finding.get('content', 'Unknown'),
                        'risk_level': 'High' if severity == 'critical' else 'Medium' if severity == 'warning' else 'Low'
                    })
        
        return categorized_findings
    
    def _categorize_history_finding(self, history_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for history module findings"""
        categorized_findings = []
        
        if isinstance(history_data, list):
            for finding in history_data:
                if isinstance(finding, dict):
                    # Determine severity based on command content
                    command = finding.get('command', '')
                    content = command.lower()
                    
                    severity = 'info'
                    finding_type = 'history_command'
                    
                    if any(keyword in content for keyword in ['password', 'secret', 'token', 'key', 'ssh', 'mysql', 'psql']):
                        severity = 'critical'
                        finding_type = 'history_credential'
                    elif any(keyword in content for keyword in ['curl', 'wget', 'scp', 'rsync']):
                        severity = 'warning'
                        finding_type = 'history_sensitive'
                    
                    categorized_findings.append({
                        'type': finding_type,
                        'severity': severity,
                        'module': 'history',
                        'category': 'Shell History',
                        'command': command,
                        'file': finding.get('file', 'Unknown'),
                        'line_number': finding.get('line_number', 'Unknown'),
                        'pattern_matches': finding.get('pattern_matches', []),
                        'risk_level': 'High' if severity == 'critical' else 'Medium' if severity == 'warning' else 'Low'
                    })
        
        return categorized_findings 