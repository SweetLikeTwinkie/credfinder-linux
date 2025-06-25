#!/usr/bin/env python3
"""
Report Generator Module
Generates reports in JSON, HTML, CSV, and console formats
"""

import os
import json
import csv
import platform
import socket
import getpass
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Any, Dict, List
import textwrap
from modules.utils.logger import get_logger
from pathlib import Path

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get("output", {}).get("output_dir", "./reports")
        self.template_path = config.get("output", {}).get("report_template", "templates/report.html")
        self.logger = get_logger("credfinder.reportgenerator")

    def generate(self, results: Dict[str, Any], format_type: str = "json", execution_stats: Dict[str, Any] = None) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        report_path = os.path.join(self.output_dir, f"credfinder_report.{format_type}")
        if format_type == "json":
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif format_type == "csv":
            self._generate_csv(results, report_path)
        elif format_type == "html":
            self._generate_html(results, report_path, execution_stats)
        elif format_type == "console":
            self._generate_console(results)
            report_path = "console"
        return report_path

    def _generate_csv(self, results: Dict[str, Any], report_path: str):
        # Flatten results for CSV output with error handling
        try:
            with open(report_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Module", "Finding"])
                for module, findings in results.items():
                    if isinstance(findings, list):
                        for finding in findings:
                            try:
                                writer.writerow([module, json.dumps(finding, default=str)])
                            except (TypeError, ValueError) as e:
                                self.logger.warning(f"Failed to serialize finding for CSV: {e}")
                                writer.writerow([module, str(finding)])
                    else:
                        try:
                            writer.writerow([module, json.dumps(findings, default=str)])
                        except (TypeError, ValueError) as e:
                            self.logger.warning(f"Failed to serialize findings for CSV: {e}")
                            writer.writerow([module, str(findings)])
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            raise

    def _generate_html(self, results: Dict[str, Any], report_path: str, execution_stats: Dict[str, Any] = None):
        """Generate HTML report with improved template path resolution"""
        try:
            # Try multiple template paths
            template_paths = [
                self.template_path,
                os.path.join(os.path.dirname(__file__), '..', 'templates', 'report.html'),
                os.path.join(os.getcwd(), 'templates', 'report.html'),
                'templates/report.html'
            ]
            
            template_found = None
            for path in template_paths:
                if os.path.exists(path):
                    template_found = path
                    break
            
            if not template_found:
                self.logger.warning(f"Template not found in any of these locations: {template_paths}")
                # Fallback: simple HTML if template missing
                html = self._generate_fallback_html(results)
                with open(report_path, 'w') as f:
                    f.write(html)
                return
            
            # Use the found template
            template_dir = os.path.dirname(template_found)
            template_file = os.path.basename(template_found)
            
            env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
            
            # Process and categorize findings
            processed_results = self._process_findings(results)
            
            # Calculate statistics for the template
            total_findings = 0
            critical_findings = 0
            warning_findings = 0
            modules_run = len(results)
            
            # Enhanced statistics calculation with proper handling
            for module_name, module_data in results.items():
                if isinstance(module_data, dict):
                    # Handle nested structures like browser or ssh
                    for key, value in module_data.items():
                        if isinstance(value, list):
                            total_findings += len(value)
                            # Analyze each finding for severity
                            for item in value:
                                if isinstance(item, dict):
                                    severity = item.get('severity', 'info')
                                    if severity == 'critical':
                                        critical_findings += 1
                                    elif severity == 'warning':
                                        warning_findings += 1
                        elif isinstance(value, dict) and 'items' in value:
                            # Handle nested items like keyring
                            if isinstance(value['items'], list):
                                total_findings += len(value['items'])
                                for item in value['items']:
                                    if isinstance(item, dict):
                                        severity = item.get('severity', 'info')
                                        if severity == 'critical':
                                            critical_findings += 1
                                        elif severity == 'warning':
                                            warning_findings += 1
                elif isinstance(module_data, list):
                    total_findings += len(module_data)
                    for finding in module_data:
                        if isinstance(finding, dict):
                            severity = finding.get('severity', 'info')
                            if severity == 'critical':
                                critical_findings += 1
                            elif severity == 'warning':
                                warning_findings += 1
                elif module_data:
                    total_findings += 1
            
            # Collect system information
            system_info = self._collect_system_info()
            
            # Enhanced template context with more metadata
            template_context = {
                'results': results,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_findings': total_findings,
                'critical_findings': critical_findings,
                'warning_findings': warning_findings,
                'modules_run': modules_run,
                'execution_stats': execution_stats or {},
                'system_info': system_info,
                'scan_metadata': {
                    'version': '1.0',
                    'report_type': 'HTML',
                    'generation_time': datetime.now().isoformat()
                }
            }
            
            template = env.get_template(template_file)
            html = template.render(**template_context)
            with open(report_path, 'w') as f:
                f.write(html)
                
        except Exception as e:
            import traceback
            self.logger.error(f"Error generating HTML report: {e}")
            self.logger.error(f"Error type: {type(e)}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            # Fallback to simple HTML
            html = self._generate_fallback_html(results)
            with open(report_path, 'w') as f:
                f.write(html)
    
    def _generate_fallback_html(self, results: Dict[str, Any]) -> str:
        """Generate a simple fallback HTML report"""
        html = textwrap.dedent(f"""
        <html>
        <head>
            <title>credfinder Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .finding {{ margin: 10px 0; padding: 10px; border: 1px solid #ccc; }}
                .critical {{ background-color: #ffebee; border-color: #f44336; }}
                .warning {{ background-color: #fff3e0; border-color: #ff9800; }}
                .info {{ background-color: #e3f2fd; border-color: #2196f3; }}
            </style>
        </head>
        <body>
            <h1>credfinder Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <pre>{json.dumps(results, indent=2, default=str)}</pre>
        </body>
        </html>
        """)
        return html
    
    def _process_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and categorize findings data structure"""
        processed_results = {}
        
        for module_name, module_data in results.items():
            try:
                # Handle special status cases (failed, skipped, timeout modules)
                if isinstance(module_data, dict) and '_status' in module_data:
                    status = module_data['_status']
                    if status in ['failed', 'skipped', 'timeout']:
                        # Check if there's partial data to process
                        if '_partial_data' in module_data and module_data['_partial_data']:
                            # Process partial data but mark as incomplete
                            partial_data = module_data['_partial_data']
                            processed_results[module_name] = {
                                'status': status,
                                'error': module_data.get('_error', 'Unknown error'),
                                'partial_findings': self._process_module_data(module_name, partial_data),
                                'warning': f'Module {status} - findings may be incomplete'
                            }
                        else:
                            processed_results[module_name] = {
                                'status': status,
                                'error': module_data.get('_error', module_data.get('_reason', 'Unknown error')),
                                'findings': []
                            }
                        continue
                
                # Process normal successful module data
                processed_results[module_name] = self._process_module_data(module_name, module_data)
                    
            except Exception as e:
                self.logger.error(f"Error processing {module_name} module data: {e}")
                processed_results[module_name] = {'error': str(e), 'raw_data': module_data}
        
        return processed_results
    
    def _process_module_data(self, module_name: str, module_data: Any) -> Dict[str, Any]:
        """Process data for a specific module"""
        if module_name == 'browser':
            # Browser data is already in the correct nested structure
            # Apply categorization to browser findings
            if isinstance(module_data, dict):
                categorized_browser = {}
                for browser_type, browser_info in module_data.items():
                    if isinstance(browser_info, dict):
                        # Pass the entire browser_info, not wrapped in another dict
                        categorized_browser[browser_type] = self._categorize_browser_finding(browser_info, browser_type)
                    else:
                        categorized_browser[browser_type] = browser_info
                return {
                    'findings': categorized_browser,
                    'raw_data': module_data  # Preserve original data
                }
            else:
                return module_data
        elif module_name == 'ssh':
            # SSH data should be categorized properly
            if isinstance(module_data, dict):
                # Apply SSH categorization
                categorized_ssh = self._categorize_ssh_finding(module_data)
                return {
                    'findings': categorized_ssh,
                    'raw_data': module_data  # Keep original for reference
                }
            else:
                self.logger.warning(f"SSH module returned unexpected data type: {type(module_data)}")
                return {'error': 'Invalid data structure'}
        elif module_name == 'keyring':
            # Apply keyring categorization
            if isinstance(module_data, dict):
                categorized_keyring = self._categorize_keyring_finding(module_data)
                return {
                    'findings': categorized_keyring,
                    'raw_data': module_data
                }
            else:
                return module_data if isinstance(module_data, (list, dict)) else []
        elif module_name == 'memory':
            # Apply memory categorization
            if isinstance(module_data, (list, dict)):
                categorized_memory = self._categorize_memory_finding(module_data)
                return {
                    'findings': categorized_memory,
                    'raw_data': module_data
                }
            else:
                return []
        elif module_name == 'dotfiles':
            # Apply dotfiles categorization
            if isinstance(module_data, (list, dict)):
                categorized_dotfiles = self._categorize_dotfile_finding(module_data)
                return {
                    'findings': categorized_dotfiles,
                    'raw_data': module_data
                }
            else:
                return []
        elif module_name == 'history':
            # Apply history categorization
            if isinstance(module_data, (list, dict)):
                categorized_history = self._categorize_history_finding(module_data)
                return {
                    'findings': categorized_history,
                    'raw_data': module_data
                }
            else:
                return []
        else:
            # Unknown module, pass through as-is
            return module_data
    
    def _categorize_ssh_finding(self, ssh_data: Dict[str, Any]) -> List[Dict[str, Any]]:
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
                # Parse and format host information if available
                formatted_hosts = []
                if 'hosts' in known_host and known_host['hosts']:
                    hosts_data = known_host['hosts']
                    if isinstance(hosts_data, list):
                        for host_entry in hosts_data[:5]:  # Limit to first 5 for display
                            if isinstance(host_entry, dict):
                                hostname = host_entry.get('hostname', 'Unknown')
                                key_type = host_entry.get('key_type', 'Unknown')
                                # Truncate key data for readability
                                key_data = host_entry.get('key_data', '')
                                if key_data and len(key_data) > 50:
                                    key_data = key_data[:47] + "..."
                                
                                formatted_hosts.append({
                                    'hostname': hostname,
                                    'key_type': key_type,
                                    'key_data_preview': key_data,
                                    'key_data_length': len(host_entry.get('key_data', ''))
                                })
                
                categorized_findings.append({
                    'type': 'ssh_known_hosts',
                    'severity': 'warning',
                    'module': 'ssh',
                    'category': 'Known Hosts',
                    'path': known_host.get('path', 'Unknown'),
                    'host_count': known_host.get('count', 0),
                    'hosts_preview': formatted_hosts,
                    'has_more_hosts': known_host.get('count', 0) > 5,
                    'owner': known_host.get('owner', 'Unknown'),
                    'risk_level': 'Medium',
                    'description': f"SSH known_hosts file containing {known_host.get('count', 0)} host(s)"
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
                    'configs': config.get('configs', []),
                    'owner': config.get('owner', 'Unknown'),
                    'risk_level': 'Low'
                })
        
        # Process authorized_keys files (MISSING DATA!)
        if 'authorized_keys' in ssh_data and ssh_data['authorized_keys']:
            for auth_file in ssh_data['authorized_keys']:
                categorized_findings.append({
                    'type': 'ssh_authorized_keys',
                    'severity': 'warning',
                    'module': 'ssh',
                    'category': 'Authorized Keys',
                    'path': auth_file.get('path', 'Unknown'),
                    'key_count': auth_file.get('count', 0),
                    'keys': auth_file.get('keys', []),
                    'permissions': auth_file.get('permissions', 'Unknown'),
                    'owner': auth_file.get('owner', 'Unknown'),
                    'risk_level': 'Medium'
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

    def _categorize_browser_finding(self, browser_data: Dict[str, Any], browser_type: str) -> List[Dict[str, Any]]:
        """Special categorization for browser module findings"""
        categorized_findings = []
        
        # Map browser types to display names
        browser_names = {
            'chrome': 'Chrome',
            'chromium': 'Chromium', 
            'brave': 'Brave',
            'firefox': 'Firefox'
        }
        browser_display_name = browser_names.get(browser_type, browser_type.title())
        
        # Process passwords
        if 'passwords' in browser_data and browser_data['passwords']:
            for entry in browser_data['passwords']:
                if isinstance(entry, dict):
                    categorized_findings.append({
                        'type': 'browser_credential',
                        'severity': 'critical',
                        'module': 'browser',
                        'category': f'{browser_display_name} Password',
                        'browser': browser_display_name,
                        'url': entry.get('url', 'Unknown'),
                        'username': entry.get('username', 'Unknown'),
                        'password': '***HIDDEN***' if entry.get('password') else 'Not stored',
                        'encrypted': entry.get('encrypted', False),
                        'decrypted': entry.get('decrypted', False),
                        'profile_path': entry.get('profile_path', 'Unknown'),
                        'date_created': entry.get('date_created', 'Unknown'),
                        'date_last_used': entry.get('date_last_used', 'Unknown'),
                        'risk_level': 'High'
                    })
        
        # Process cookies
        if 'cookies' in browser_data and browser_data['cookies']:
            for entry in browser_data['cookies']:
                if isinstance(entry, dict):
                    categorized_findings.append({
                        'type': 'browser_cookie',
                        'severity': 'warning',
                        'module': 'browser',
                        'category': f'{browser_display_name} Cookie',
                        'browser': browser_display_name,
                        'host': entry.get('host', 'Unknown'),
                        'name': entry.get('name', 'Unknown'),
                        'value': '***HIDDEN***' if entry.get('value') else 'Not stored',
                        'encrypted': entry.get('encrypted', False),
                        'decrypted': entry.get('decrypted', False),
                        'path': entry.get('path', '/'),
                        'expires': entry.get('expires', 'Session'),
                        'secure': entry.get('secure', False),
                        'httponly': entry.get('httponly', False),
                        'profile_path': entry.get('profile_path', 'Unknown'),
                        'risk_level': 'Medium'
                    })
        
        # Process autofill data (missing from original!)
        if 'autofill' in browser_data and browser_data['autofill']:
            for entry in browser_data['autofill']:
                if isinstance(entry, dict):
                    categorized_findings.append({
                        'type': 'browser_autofill',
                        'severity': 'info',
                        'module': 'browser',
                        'category': f'{browser_display_name} Autofill',
                        'browser': browser_display_name,
                        'field_name': entry.get('field_name', 'Unknown'),
                        'value': entry.get('value', 'Unknown'),
                        'usage_count': entry.get('usage_count', 0),
                        'date_created': entry.get('date_created', 'Unknown'),
                        'date_last_used': entry.get('date_last_used', 'Unknown'),
                        'profile_path': entry.get('profile_path', 'Unknown'),
                        'risk_level': 'Low'
                    })
        
        # Process profile paths (for reference)
        if 'profile_paths' in browser_data and browser_data['profile_paths']:
            for path in browser_data['profile_paths']:
                categorized_findings.append({
                    'type': 'browser_profile',
                    'severity': 'info',
                    'module': 'browser',
                    'category': f'{browser_display_name} Profile',
                    'browser': browser_display_name,
                    'profile_path': path,
                    'risk_level': 'Low'
                })
        
        return categorized_findings
    
    def _categorize_keyring_finding(self, keyring_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for keyring module findings"""
        categorized_findings = []
        
        def is_meaningful_error(error_value):
            """Check if an error value is meaningful (not None, empty, or 'None' string)"""
            if not error_value:
                return False
            error_str = str(error_value).strip().lower()
            return error_str not in ['none', 'null', '', 'no error']
        
        # Process available keyrings
        if 'available_keyrings' in keyring_data and keyring_data['available_keyrings']:
            available_keyrings = keyring_data['available_keyrings']
            if isinstance(available_keyrings, list) and len(available_keyrings) > 0:
                categorized_findings.append({
                    'type': 'keyring_detection',
                    'severity': 'info',
                    'module': 'keyring',
                    'category': 'Available Keyrings',
                    'available_keyrings': available_keyrings,
                    'keyring_count': len(available_keyrings),
                    'risk_level': 'Low',
                    'description': f'Found {len(available_keyrings)} available keyring(s): {", ".join(available_keyrings)}'
                })
        
        # Process GNOME Keyring
        if 'gnome_keyring' in keyring_data and keyring_data['gnome_keyring']:
            gnome_data = keyring_data['gnome_keyring']
            
            # Handle meaningful errors only
            if gnome_data.get('error') and is_meaningful_error(gnome_data['error']):
                categorized_findings.append({
                    'type': 'keyring_error',
                    'severity': 'warning',
                    'module': 'keyring',
                    'category': 'GNOME Keyring Error',
                    'keyring_type': 'GNOME Keyring',
                    'error': gnome_data['error'],
                    'risk_level': 'Low',
                    'description': 'GNOME Keyring encountered an error during access attempt'
                })
            
            # Process collections
            if 'collections' in gnome_data and gnome_data['collections']:
                for collection in gnome_data['collections']:
                    if isinstance(collection, dict) and collection:
                        categorized_findings.append({
                            'type': 'keyring_collection',
                            'severity': 'info',
                            'module': 'keyring',
                            'category': 'GNOME Keyring Collection',
                            'keyring_type': 'GNOME Keyring',
                            'collection_path': collection.get('path', 'Unknown'),
                            'collection_label': collection.get('label', 'Unknown'),
                            'item_count': len(collection.get('items', [])),
                            'risk_level': 'Low',
                            'description': f"Found keyring collection: {collection.get('label', 'Unknown')}"
                        })
            
            # Process items
            if 'items' in gnome_data and gnome_data['items']:
                for item in gnome_data['items']:
                    if isinstance(item, dict) and item:
                        categorized_findings.append({
                            'type': 'keyring_entry',
                            'severity': 'critical',
                            'module': 'keyring',
                            'category': 'GNOME Keyring Entry',
                            'keyring_type': 'GNOME Keyring',
                            'attributes': item.get('attributes', {}),
                            'secret': '***HIDDEN***' if item.get('secret') else 'Not accessible',
                            'risk_level': 'High',
                            'description': 'Stored credential found in GNOME keyring'
                        })
        
        # Process KWallet
        if 'kwallet' in keyring_data and keyring_data['kwallet']:
            kwallet_data = keyring_data['kwallet']
            
            # Handle meaningful errors only
            if kwallet_data.get('error') and is_meaningful_error(kwallet_data['error']):
                categorized_findings.append({
                    'type': 'keyring_error',
                    'severity': 'warning',
                    'module': 'keyring',
                    'category': 'KWallet Error',
                    'keyring_type': 'KWallet',
                    'error': kwallet_data['error'],
                    'risk_level': 'Low',
                    'description': 'KWallet encountered an error during access attempt'
                })
            
            # Process wallets
            if 'wallets' in kwallet_data and kwallet_data['wallets']:
                wallets = kwallet_data['wallets']
                if isinstance(wallets, list) and len(wallets) > 0:
                    categorized_findings.append({
                        'type': 'keyring_wallets',
                        'severity': 'info',
                        'module': 'keyring',
                        'category': 'KWallet Detection',
                        'keyring_type': 'KWallet',
                        'wallets': wallets,
                        'wallet_count': len(wallets),
                        'risk_level': 'Low',
                        'description': f'Found {len(wallets)} KWallet(s): {", ".join(wallets)}'
                    })
            
            # Process items
            if 'items' in kwallet_data and kwallet_data['items']:
                for item in kwallet_data['items']:
                    if isinstance(item, dict) and item:
                        categorized_findings.append({
                            'type': 'keyring_entry',
                            'severity': 'critical',
                            'module': 'keyring',
                            'category': 'KWallet Entry',
                            'keyring_type': 'KWallet',
                            'key': item.get('key', 'Unknown'),
                            'value': '***HIDDEN***' if item.get('value') else 'Not accessible',
                            'risk_level': 'High',
                            'description': 'Stored credential found in KWallet'
                        })
        
        # Process secret-tool
        if 'secret_tool' in keyring_data and keyring_data['secret_tool']:
            secret_data = keyring_data['secret_tool']
            
            # Handle meaningful errors only
            if secret_data.get('error') and is_meaningful_error(secret_data['error']):
                categorized_findings.append({
                    'type': 'keyring_error',
                    'severity': 'warning',
                    'module': 'keyring',
                    'category': 'Secret Tool Error',
                    'keyring_type': 'Secret Tool',
                    'error': secret_data['error'],
                    'risk_level': 'Low',
                    'description': 'Secret Tool encountered an error during credential search'
                })
            
            # Process items
            if 'items' in secret_data and secret_data['items']:
                for item in secret_data['items']:
                    if isinstance(item, dict) and item:
                        categorized_findings.append({
                            'type': 'keyring_entry',
                            'severity': 'critical',
                            'module': 'keyring',
                            'category': 'Secret Tool Entry',
                            'keyring_type': 'Secret Tool',
                            'attributes': item.get('attributes', {}),
                            'secret': '***HIDDEN***' if item.get('secret') else 'Not accessible',
                            'risk_level': 'High',
                            'description': 'Stored credential found via Secret Tool'
                        })
        
        return categorized_findings
    
    def _collect_system_info(self) -> Dict[str, str]:
        """Collect system information for the report"""
        try:
            return {
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'os': f"{platform.system()} {platform.release()}",
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'platform': platform.platform()
            }
        except Exception as e:
            return {
                'error': f"Failed to collect system info: {e}"
            }
    
    def _categorize_memory_finding(self, memory_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for memory module findings"""
        categorized_findings = []
        
        # Handle dict structure from memory module
        if isinstance(memory_data, dict):
            # Process process environment findings
            if 'process_environ' in memory_data and memory_data['process_environ']:
                for finding in memory_data['process_environ']:
                    if isinstance(finding, dict):
                        for secret in finding.get('secrets', []):
                            categorized_findings.append({
                                'type': 'memory_process_env',
                                'severity': 'critical',
                                'module': 'memory',
                                'category': 'Process Environment Variable',
                                'pid': finding.get('pid', 'Unknown'),
                                'process_name': finding.get('name', 'Unknown'),
                                'variable_name': secret.get('name', 'Unknown'),
                                'variable_value': '***HIDDEN***' if secret.get('value') else 'Unknown',
                                'pattern_matched': secret.get('pattern_matched', 'Unknown'),
                                'risk_level': 'High'
                            })
            
            # Process command line findings  
            if 'process_cmdline' in memory_data and memory_data['process_cmdline']:
                for finding in memory_data['process_cmdline']:
                    if isinstance(finding, dict):
                        for secret in finding.get('secrets', []):
                            categorized_findings.append({
                                'type': 'memory_process_cmdline',
                                'severity': 'critical', 
                                'module': 'memory',
                                'category': 'Process Command Line',
                                'pid': finding.get('pid', 'Unknown'),
                                'process_name': finding.get('name', 'Unknown'),
                                'cmdline': finding.get('cmdline', 'Unknown'),
                                'pattern_matches': secret.get('pattern_matches', []),
                                'risk_level': 'High'
                            })
            
            # Process /proc files findings
            if 'proc_files' in memory_data and memory_data['proc_files']:
                for finding in memory_data['proc_files']:
                    if isinstance(finding, dict):
                        for pattern_match in finding.get('pattern_matches', []):
                            categorized_findings.append({
                                'type': 'memory_proc_file',
                                'severity': 'warning',
                                'module': 'memory', 
                                'category': 'Proc File Secret',
                                'file': finding.get('file', 'Unknown'),
                                'pattern_type': pattern_match.get('type', 'Unknown'),
                                'pattern': pattern_match.get('pattern', 'Unknown'),
                                'match': pattern_match.get('match', 'Unknown'),
                                'context': pattern_match.get('context', 'Unknown'),
                                'risk_level': 'Medium'
                            })
            
            # Process volatility results
            if 'volatility_results' in memory_data and memory_data['volatility_results']:
                vol_results = memory_data['volatility_results']
                if isinstance(vol_results, dict):
                    for plugin_name, plugin_data in vol_results.items():
                        if isinstance(plugin_data, dict):
                            # Process secrets found by volatility
                            for secret in plugin_data.get('secrets', []):
                                categorized_findings.append({
                                    'type': 'memory_volatility',
                                    'severity': 'critical',
                                    'module': 'memory',
                                    'category': f'Volatility {plugin_name}',
                                    'plugin': plugin_name,
                                    'pattern_type': secret.get('type', 'Unknown'),
                                    'pattern': secret.get('pattern', 'Unknown'),
                                    'match': secret.get('match', 'Unknown'),
                                    'context': secret.get('context', 'Unknown'),
                                    'risk_level': 'High'
                                })
                            
                            # Process YARA matches
                            for yara_match in plugin_data.get('yara_matches', []):
                                categorized_findings.append({
                                    'type': 'memory_yara',
                                    'severity': 'critical',
                                    'module': 'memory',
                                    'category': f'YARA Match in {plugin_name}',
                                    'plugin': plugin_name,
                                    'rule': yara_match.get('rule', 'Unknown'),
                                    'strings': yara_match.get('strings', []),
                                    'risk_level': 'High'
                                })
        
        # Handle legacy list format (if any)
        elif isinstance(memory_data, list):
            for finding in memory_data:
                if isinstance(finding, dict):
                    # Determine severity based on content
                    content = str(finding).lower()
                    severity = 'critical' if any(keyword in content for keyword in ['password', 'secret', 'token', 'key']) else 'warning'
                    
                    categorized_findings.append({
                        'type': 'memory_legacy',
                        'severity': severity,
                        'module': 'memory',
                        'category': 'Memory Finding',
                        'data': finding,
                        'risk_level': 'High' if severity == 'critical' else 'Medium'
                    })
        
        return categorized_findings
    
    def _categorize_dotfile_finding(self, dotfile_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Special categorization for dotfile module findings"""
        categorized_findings = []
        
        # Handle dict structure from dotfiles module
        if isinstance(dotfile_data, dict):
            # Process config files
            if 'config_files' in dotfile_data and dotfile_data['config_files']:
                for finding in dotfile_data['config_files']:
                    if isinstance(finding, dict):
                        for pattern_match in finding.get('pattern_matches', []):
                            categorized_findings.append({
                                'type': 'dotfile_config_secret',
                                'severity': 'critical',
                                'module': 'dotfiles',
                                'category': 'Config File Secret',
                                'file': finding.get('file', 'Unknown'),
                                'pattern_type': pattern_match.get('type', 'Unknown'),
                                'pattern': pattern_match.get('pattern', 'Unknown'),
                                'match': pattern_match.get('match', 'Unknown'),
                                'context': pattern_match.get('context', 'Unknown'),
                                'risk_level': 'High'
                            })
            
            # Process .env files
            if 'env_files' in dotfile_data and dotfile_data['env_files']:
                for finding in dotfile_data['env_files']:
                    if isinstance(finding, dict):
                        for variable in finding.get('variables', []):
                            # Determine severity based on variable name and value
                            var_name = variable.get('key', '').lower()
                            var_value = variable.get('value', '')
                            
                            severity = 'info'
                            if any(keyword in var_name for keyword in ['password', 'secret', 'token', 'key', 'api']):
                                severity = 'critical'
                            elif any(keyword in var_name for keyword in ['url', 'host', 'server', 'endpoint']):
                                severity = 'warning'
                            
                            categorized_findings.append({
                                'type': 'dotfile_env_var',
                                'severity': severity,
                                'module': 'dotfiles',
                                'category': 'Environment Variable',
                                'file': finding.get('file', 'Unknown'),
                                'variable_name': variable.get('key', 'Unknown'),
                                'variable_value': '***HIDDEN***' if severity == 'critical' else var_value,
                                'risk_level': 'High' if severity == 'critical' else 'Medium' if severity == 'warning' else 'Low'
                            })
            
            # Process Git configs
            if 'git_configs' in dotfile_data and dotfile_data['git_configs']:
                for finding in dotfile_data['git_configs']:
                    if isinstance(finding, dict):
                        config_data = finding.get('config', {})
                        
                        # Process credentials
                        for credential in config_data.get('credentials', []):
                            categorized_findings.append({
                                'type': 'dotfile_git_credential',
                                'severity': 'critical',
                                'module': 'dotfiles',
                                'category': 'Git Credential',
                                'file': finding.get('file', 'Unknown'),
                                'protocol': credential.get('protocol', 'Unknown'),
                                'username': credential.get('username', 'Unknown'),
                                'password': '***HIDDEN***',
                                'url': credential.get('url', 'Unknown'),
                                'risk_level': 'High'
                            })
                        
                        # Process user info
                        user_info = config_data.get('user', {})
                        if user_info:
                            categorized_findings.append({
                                'type': 'dotfile_git_user',
                                'severity': 'info',
                                'module': 'dotfiles',
                                'category': 'Git User Config',
                                'file': finding.get('file', 'Unknown'),
                                'user_info': user_info,
                                'risk_level': 'Low'
                            })
            
            # Process AWS configs
            if 'aws_configs' in dotfile_data and dotfile_data['aws_configs']:
                for finding in dotfile_data['aws_configs']:
                    if isinstance(finding, dict):
                        config_data = finding.get('config', {})
                        
                        # Process credentials
                        for profile_name, profile_data in config_data.get('credentials', {}).items():
                            categorized_findings.append({
                                'type': 'dotfile_aws_credential',
                                'severity': 'critical',
                                'module': 'dotfiles',
                                'category': 'AWS Credential',
                                'file': finding.get('file', 'Unknown'),
                                'profile': profile_name,
                                'aws_access_key_id': profile_data.get('aws_access_key_id', 'Unknown'),
                                'aws_secret_access_key': '***HIDDEN***',
                                'risk_level': 'High'
                            })
                        
                        # Process profiles/config
                        for profile_name, profile_data in config_data.get('profiles', {}).items():
                            categorized_findings.append({
                                'type': 'dotfile_aws_config',
                                'severity': 'warning',
                                'module': 'dotfiles',
                                'category': 'AWS Config',
                                'file': finding.get('file', 'Unknown'),
                                'profile': profile_name,
                                'region': profile_data.get('region', 'Unknown'),
                                'output': profile_data.get('output', 'Unknown'),
                                'risk_level': 'Medium'
                            })
            
            # Process Docker configs
            if 'docker_configs' in dotfile_data and dotfile_data['docker_configs']:
                for finding in dotfile_data['docker_configs']:
                    if isinstance(finding, dict):
                        categorized_findings.append({
                            'type': 'dotfile_docker_config',
                            'severity': 'warning',
                            'module': 'dotfiles',
                            'category': 'Docker Config',
                            'file': finding.get('file', 'Unknown'),
                            'config': finding.get('config', {}),
                            'risk_level': 'Medium'
                        })
            
            # Process other config types similarly...
            for config_type in ['kubernetes_configs', 'database_configs', 'other_configs']:
                if config_type in dotfile_data and dotfile_data[config_type]:
                    for finding in dotfile_data[config_type]:
                        if isinstance(finding, dict):
                            categorized_findings.append({
                                'type': f'dotfile_{config_type.replace("_configs", "")}',
                                'severity': 'warning',
                                'module': 'dotfiles',
                                'category': f'{config_type.replace("_", " ").title()}',
                                'file': finding.get('file', 'Unknown'),
                                'pattern_matches': finding.get('pattern_matches', []),
                                'content_preview': finding.get('content_preview', 'Unknown'),
                                'risk_level': 'Medium'
                            })
        
        # Handle legacy list format (if any)
        elif isinstance(dotfile_data, list):
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
    
    def _categorize_history_finding(self, history_data: Any) -> List[Dict[str, Any]]:
        """Special categorization for history module findings"""
        categorized_findings = []
        
        # History module returns a list directly, not a dict
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
                    
                    # Process pattern matches
                    for pattern_match in finding.get('pattern_matches', []):
                        categorized_findings.append({
                            'type': finding_type,
                            'severity': severity,
                            'module': 'history',
                            'category': 'Shell History Command',
                            'command': command,
                            'file': finding.get('file', 'Unknown'),
                            'line_number': finding.get('line_number', 'Unknown'),
                            'pattern_type': pattern_match.get('type', 'Unknown'),
                            'pattern': pattern_match.get('pattern', 'Unknown'),
                            'match': pattern_match.get('match', 'Unknown'),
                            'context': pattern_match.get('context', 'Unknown'),
                            'risk_level': 'High' if severity == 'critical' else 'Medium' if severity == 'warning' else 'Low'
                        })
                    
                    # If no pattern matches but still has concerning command, add it anyway
                    if not finding.get('pattern_matches') and severity != 'info':
                        categorized_findings.append({
                            'type': finding_type,
                            'severity': severity,
                            'module': 'history',
                            'category': 'Shell History Command',
                            'command': command,
                            'file': finding.get('file', 'Unknown'),
                            'line_number': finding.get('line_number', 'Unknown'),
                            'risk_level': 'High' if severity == 'critical' else 'Medium'
                        })
        
        return categorized_findings 

    def generate_reports(self, results, output_formats=None):
        """Generate reports in specified formats"""
        if output_formats is None:
            output_formats = ['json']
        
        reports_generated = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            for format_type in output_formats:
                if format_type.lower() == 'json':
                    json_path = self._generate_json(results, timestamp)
                    if json_path:
                        reports_generated.append(json_path)
                        
                elif format_type.lower() == 'html':
                    html_path = self._generate_html_python(results, timestamp)
                    if html_path:
                        reports_generated.append(html_path)
                        
        except Exception as e:
            self.logger.error(f"Error generating reports: {str(e)}")
            self.logger.error(f"Error type: {type(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
        return reports_generated

    def _generate_json(self, results, timestamp):
        """Generate JSON report"""
        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            json_file = reports_dir / f"credfinder_results_{timestamp}.json"
            
            report_data = {
                "timestamp": datetime.now().isoformat(),
                "modules": results,
                "summary": {
                    "total_modules": len(results),
                    "modules_with_findings": len([k for k, v in results.items() if v])
                }
            }
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
                
            self.logger.info(f"JSON report generated: {json_file}")
            return str(json_file)
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            return None

    def _generate_html_python(self, results, timestamp):
        """Generate HTML report using Python instead of complex Jinja templates"""
        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            html_file = reports_dir / f"credfinder_report_{timestamp}.html"
            
            # Generate HTML content
            html_content = self._build_html_content(results, timestamp)
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"HTML report generated: {html_file}")
            return str(html_file)
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return None

    def _build_html_content(self, results, timestamp):
        """Build complete HTML content using Python"""
        
        # Calculate comprehensive statistics
        total_findings = 0
        critical_findings = 0
        warning_findings = 0
        info_findings = 0
        modules_with_data = 0
        modules_with_errors = 0
        
        for module_name, module_data in results.items():
            if module_data:
                if isinstance(module_data, dict) and module_data.get('_status') == 'failed':
                    modules_with_errors += 1
                    continue
                    
                count = self._count_findings(module_data)
                if count > 0:
                    modules_with_data += 1
                    total_findings += count
                    
                    # More sophisticated severity classification
                    if module_name == 'ssh':
                        critical_findings += self._count_critical_ssh_findings(module_data)
                        warning_findings += count - self._count_critical_ssh_findings(module_data)
                    elif module_name == 'browser':
                        critical_findings += self._count_critical_browser_findings(module_data) 
                        warning_findings += count - self._count_critical_browser_findings(module_data)
                    elif module_name in ['keyring', 'memory']:
                        critical_findings += count
                    else:
                        info_findings += count

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CredFinder Security Assessment Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-spinner">
            <div class="spinner"></div>
            <div class="loading-text">Loading Security Report...</div>
        </div>
    </div>

    <nav class="top-nav">
        <div class="nav-content">
            <div class="nav-brand">
                <i class="fas fa-shield-alt"></i>
                <span>CredFinder</span>
            </div>
            <div class="nav-actions">
                <button class="nav-btn" onclick="toggleDarkMode()" title="Toggle Dark Mode">
                    <i class="fas fa-moon"></i>
                </button>
                <button class="nav-btn" onclick="showSearchModal()" title="Search Findings">
                    <i class="fas fa-search"></i>
                </button>
                <button class="nav-btn" onclick="exportReport()" title="Export Report">
                    <i class="fas fa-download"></i>
                </button>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="hero-section">
            <div class="hero-content">
                <div class="hero-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h1 class="hero-title">Security Assessment Report</h1>
                <div class="hero-subtitle">Comprehensive credential and secret discovery analysis</div>
                <div class="hero-meta">
                    <span class="meta-item">
                        <i class="fas fa-calendar"></i>
                        Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
                    </span>
                    <span class="meta-item">
                        <i class="fas fa-server"></i>
                        {self._get_hostname()}
                    </span>
                </div>
            </div>
            <div class="hero-visual">
                {self._build_risk_gauge_html(critical_findings, warning_findings, info_findings)}
            </div>
        </div>

        {self._build_enhanced_system_info_html()}
        {self._build_privilege_warning_html()}

        <div class="content">
            <div class="content-header">
                <h2 class="section-title">
                    <i class="fas fa-chart-bar"></i>
                    Assessment Overview
                </h2>
                <div class="action-buttons">
                    <button class="action-btn primary" onclick="generatePDF()">
                        <i class="fas fa-file-pdf"></i>
                        Export PDF
                    </button>
                    <button class="action-btn secondary" onclick="exportToJSON()">
                        <i class="fas fa-code"></i>
                        Export JSON
                    </button>
                    <button class="action-btn tertiary" onclick="toggleAllModules()">
                        <i class="fas fa-expand-alt"></i>
                        Expand All
                    </button>
                </div>
            </div>

            {self._build_enhanced_dashboard_html(total_findings, critical_findings, warning_findings, info_findings, modules_with_data, len(results), modules_with_errors)}

            <div class="findings-section">
                <div class="section-header">
                    <h2 class="section-title">
                        <i class="fas fa-bug"></i>
                        Detailed Findings
                    </h2>
                    <div class="filter-controls">
                        <select class="filter-select" id="severityFilter" onchange="filterBySeverity(this.value)">
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="warning">Warning</option>
                            <option value="info">Info</option>
                        </select>
                        <select class="filter-select" id="moduleFilter" onchange="filterByModule(this.value)">
                            <option value="">All Modules</option>
                            {self._build_module_filter_options(results)}
                        </select>
                    </div>
                </div>

                {self._build_enhanced_modules_html(results)}
            </div>
        </div>
    </div>

    <div class="search-modal" id="searchModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Search Findings</h3>
                <button class="modal-close" onclick="hideSearchModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <input type="text" class="search-input" placeholder="Search findings, paths, or content..." id="searchInput" onkeyup="performSearch()">
                <div class="search-results" id="searchResults"></div>
            </div>
        </div>
    </div>

    <footer class="report-footer">
        <div class="footer-content">
            <div class="footer-section">
                <h4>Report Summary</h4>
                <p>{total_findings} total findings across {len(results)} modules</p>
            </div>
            <div class="footer-section">
                <h4>Generated By</h4>
                <p>CredFinder v2.0 - Advanced Security Assessment Tool</p>
            </div>
            <div class="footer-section">
                <h4>Next Steps</h4>
                <p>Review critical findings immediately and implement security recommendations</p>
            </div>
        </div>
    </footer>

    <script>
        {self._get_enhanced_javascript()}
    </script>
</body>
</html>"""
        return html

    def _count_findings(self, data):
        """Count total findings in a data structure"""
        if not data:
            return 0
            
        count = 0
        if isinstance(data, dict):
            for key, value in data.items():
                if key.startswith('_'):  # Skip metadata fields
                    continue
                if value:
                    if isinstance(value, (list, tuple)):
                        count += len(value)
                    elif isinstance(value, dict):
                        if 'items' in value and isinstance(value['items'], list):
                            count += len(value['items'])
                        else:
                            # Recursively count nested dictionaries
                            count += self._count_findings(value)
                    else:
                        count += 1
        elif isinstance(data, (list, tuple)):
            count = len(data)
        else:
            count = 1
            
        return count

    def _count_critical_ssh_findings(self, ssh_data):
        """Count critical SSH findings (unencrypted private keys)"""
        critical_count = 0
        if isinstance(ssh_data, dict):
            private_keys = ssh_data.get('private_keys', [])
            if isinstance(private_keys, list):
                for key in private_keys:
                    if isinstance(key, dict) and not key.get('encrypted', True):
                        critical_count += 1
        return critical_count

    def _count_critical_browser_findings(self, browser_data):
        """Count critical browser findings (saved passwords)"""
        critical_count = 0
        if isinstance(browser_data, dict):
            for browser_name, browser_info in browser_data.items():
                if isinstance(browser_info, dict):
                    passwords = browser_info.get('passwords', [])
                    if isinstance(passwords, list):
                        critical_count += len(passwords)
        return critical_count

    def _build_modules_html(self, results):
        """Build HTML for all modules"""
        modules_html = ""
        
        for module_name, module_data in results.items():
            module_icon = self._get_module_icon(module_name)
            module_title = self._get_module_title(module_name)
            findings_count = self._count_findings(module_data)
            
            modules_html += f"""
            <div class="module">
                <div class="module-header" onclick="toggleModule('{module_name}')">
                    <div class="module-title">{module_icon} {module_title}</div>
                    <div class="module-badge">{findings_count} findings</div>
                </div>
                <div class="module-content" id="{module_name}">
                    {self._build_module_content(module_name, module_data)}
                </div>
            </div>"""
            
        return modules_html

    def _build_module_content(self, module_name, module_data):
        """Build content for a specific module"""
        if not module_data:
            return """
            <div class="no-findings">
                <h3>No findings detected</h3>
                <p>This module completed successfully but found no credentials or sensitive data.</p>
            </div>"""
        
        content = ""
        
        if isinstance(module_data, dict):
            for category, items in module_data.items():
                if items:
                    content += self._build_category_content(module_name, category, items)
        else:
            content += self._build_simple_content(module_name, module_data)
            
        return content

    def _build_category_content(self, module_name, category, items):
        """Build content for a category of findings"""
        content = ""
        
        if isinstance(items, (list, tuple)):
            if len(items) == 0:
                return ""
            for i, item in enumerate(items):
                content += self._build_finding_html(module_name, category, item, i)
        elif isinstance(items, dict):
            if 'items' in items and isinstance(items['items'], list):
                # Handle keyring-style data
                for i, item in enumerate(items['items']):
                    content += self._build_finding_html(module_name, category, item, i)
                if 'error' in items:
                    content += self._build_error_html(module_name, category, items['error'])
            elif len(items) > 0:
                # Handle nested dictionaries (like browser data)
                for sub_key, sub_items in items.items():
                    if isinstance(sub_items, (list, tuple)) and len(sub_items) > 0:
                        for i, item in enumerate(sub_items):
                            content += self._build_finding_html(module_name, f"{category}_{sub_key}", item, i)
                    elif isinstance(sub_items, dict) and len(sub_items) > 0:
                        content += self._build_finding_html(module_name, f"{category}_{sub_key}", sub_items, 0)
                    elif sub_items and not isinstance(sub_items, (list, dict)):
                        content += self._build_simple_finding_html(module_name, f"{category}_{sub_key}", sub_items)
                        
                # If no sub-items were processed, treat the whole dict as a finding
                if not content:
                    content += self._build_finding_html(module_name, category, items, 0)
        elif items and not isinstance(items, (list, dict)):
            content += self._build_simple_finding_html(module_name, category, items)
            
        return content

    def _build_finding_html(self, module_name, category, item, index):
        """Build HTML for a single finding"""
        severity_class, severity_label = self._get_severity(module_name, category, item)
        finding_title = self._get_finding_title(module_name, category, item)
        
        html = f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{finding_title}</div>
                <div class="{severity_class}">{severity_label}</div>
            </div>
            <div class="finding-body">
                {self._build_data_grid(item)}
                {self._build_analysis_section(module_name, category, item)}
                <button class="json-toggle" onclick="toggleJSON(this)">Show Raw Data</button>
                <div class="json-data">
                    <pre>{self._safe_json_dump(item)}</pre>
                </div>
            </div>
        </div>"""
        
        return html

    def _build_data_grid(self, item):
        """Build data grid for an item"""
        if not isinstance(item, dict):
            return f'<div class="data-item"><div class="data-value">{self._safe_str(item)}</div></div>'
        
        grid_html = '<div class="data-grid">'
        
        for key, value in item.items():
            display_value = self._format_value_for_display(key, value)
            grid_html += f"""
            <div class="data-item">
                <div class="data-label">{key.replace('_', ' ').title()}</div>
                <div class="data-value">{display_value}</div>
            </div>"""
            
        grid_html += '</div>'
        return grid_html

    def _format_value_for_display(self, key, value):
        """Format a value for safe display"""
        # Redaction disabled - show all data
        # sensitive_fields = ['password', 'secret', 'token', 'pass', 'pwd']
        # sensitive_key_fields = ['private_key', 'private_key_data', 'encrypted_password', 'auth_token', 'access_token']
        # 
        # # Check for exact sensitive field matches or sensitive private key data
        # if (any(field == key.lower() for field in sensitive_fields) or 
        #     any(field in key.lower() for field in sensitive_key_fields)) and value:
        #     return '<span class="redacted-value" title="Sensitive data hidden for security">●●●●●●●●</span>'
        
        # Handle different value types
        if isinstance(value, (list, tuple)):
            # Special handling for SSH hosts (both hosts_preview and raw hosts)
            if key.lower() in ['hosts_preview', 'hosts'] and isinstance(value, list):
                if len(value) == 0:
                    return '<span class="empty-list">No hosts data</span>'
                
                hosts_html = '<div class="ssh-hosts-preview">'
                for i, host in enumerate(value[:3]):  # Show max 3 hosts in preview
                    if isinstance(host, dict):
                        hostname = host.get('hostname', 'Unknown')
                        key_type = host.get('key_type', 'Unknown')
                        
                        # Handle both processed and raw key data
                        key_preview = host.get('key_data_preview', '')
                        if not key_preview:
                            raw_key_data = host.get('key_data', '')
                            if raw_key_data and len(raw_key_data) > 50:
                                key_preview = raw_key_data[:47] + "..."
                            else:
                                key_preview = raw_key_data
                        
                        # Format hostname - decode if it's hashed
                        display_hostname = hostname
                        if hostname.startswith('|1|'):
                            display_hostname = '[Hashed Hostname]'
                        elif len(hostname) > 40:
                            display_hostname = hostname[:37] + "..."
                        
                        hosts_html += f'''
                        <div class="ssh-host-item">
                            <div class="host-info">
                                <span class="hostname" title="SSH Host: {hostname}"><i class="fas fa-server"></i> {display_hostname}</span>
                                <span class="key-type" title="Key Type"><i class="fas fa-key"></i> {key_type}</span>
                            </div>
                            <div class="key-preview" title="Key Data Preview">
                                <code>{key_preview}</code>
                            </div>
                        </div>'''
                
                if len(value) > 3:
                    hosts_html += f'<div class="more-hosts">... and {len(value) - 3} more hosts</div>'
                
                hosts_html += '</div>'
                return hosts_html
            elif len(value) > 3:
                return f'<span class="list-summary" title="Click View Raw Data for full list">[{len(value)} items] - {", ".join(str(v)[:20] + ("..." if len(str(v)) > 20 else "") for v in value[:2])}</span>'
            else:
                return ', '.join(str(v) for v in value)
        elif isinstance(value, dict):
            # Special handling for SSH key data
            if key.lower() in ['hosts', 'hosts_data'] and isinstance(value, dict):
                return f'<span class="ssh-data-summary" title="SSH host data - click View Raw Data for details">[SSH Host Data] {len(value)} properties</span>'
            elif key.lower() in ['key_data', 'public_key', 'private_key'] and isinstance(value, dict):
                return f'<span class="ssh-key-summary" title="SSH key data - click View Raw Data for details">[SSH Key] {len(value)} properties</span>'
            else:
                return f'<span class="dict-summary" title="Click View Raw Data for full object">[{len(value)} properties]</span>'
        else:
            str_value = str(value)
            
            # Format SSH key data specially (show public keys, redact private keys)
            if key.lower() in ['key_data', 'key_data_preview', 'public_key_data', 'fingerprint']:
                # Show key data with expandable display for better readability
                if len(str_value) > 50:
                    return f'''
                    <div class="expandable-key-data">
                        <div class="key-data-preview" onclick="toggleKeyData(this)">
                            <code class="key-preview">{str_value[:47]}...</code>
                            <button class="expand-btn" title="Click to expand full key">
                                <i class="fas fa-expand-alt"></i>
                            </button>
                        </div>
                        <div class="key-data-full" style="display: none;">
                            <div class="key-data-header">
                                <span class="key-data-title">Full {key.replace('_', ' ').title()}</span>
                                <div class="key-data-actions">
                                    <button class="copy-key-btn" onclick="copyKeyData(this)" title="Copy to clipboard">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                    <button class="collapse-btn" onclick="toggleKeyData(this.closest('.expandable-key-data').querySelector('.key-data-preview'))" title="Collapse">
                                        <i class="fas fa-compress-alt"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="key-data-content">
                                <pre class="full-key-data">{str_value}</pre>
                            </div>
                        </div>
                    </div>'''
                else:
                    return f'<div class="short-key-data"><code>{str_value}</code></div>'
            
            # Format hostnames specially
            if key.lower() in ['hostname', 'host', 'server']:
                return f'<span class="hostname-value" title="SSH Host"><i class="fas fa-server"></i> {str_value}</span>'
            
            # Format timestamps
            if key.lower() in ['date_created', 'date_last_used', 'timestamp', 'created', 'modified', 'last_accessed', 'creation_utc', 'last_used_time']:
                if str_value.isdigit():
                    try:
                        import datetime
                        timestamp_int = int(str_value)
                        
                        # Handle different timestamp formats
                        if len(str_value) == 10:
                            # Unix timestamp (seconds since epoch)
                            dt = datetime.datetime.fromtimestamp(timestamp_int)
                        elif len(str_value) == 13:
                            # JavaScript timestamp (milliseconds since epoch)
                            dt = datetime.datetime.fromtimestamp(timestamp_int / 1000)
                        elif len(str_value) == 16:
                            # Microseconds since epoch  
                            dt = datetime.datetime.fromtimestamp(timestamp_int / 1000000)
                        elif len(str_value) == 17:
                            # Chrome/WebKit timestamp (microseconds since Windows epoch: Jan 1, 1601)
                            # Convert to Unix timestamp
                            windows_epoch = datetime.datetime(1601, 1, 1)
                            unix_epoch = datetime.datetime(1970, 1, 1)
                            epoch_diff = (unix_epoch - windows_epoch).total_seconds()
                            unix_timestamp = (timestamp_int / 1000000) - epoch_diff
                            dt = datetime.datetime.fromtimestamp(unix_timestamp)
                        else:
                            # Fallback: try as Unix timestamp
                            dt = datetime.datetime.fromtimestamp(timestamp_int)
                        
                        # Format with readable date and relative time
                        formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Add relative time indicator
                        now = datetime.datetime.now()
                        diff = now - dt
                        
                        if diff.days > 365:
                            relative = f"({diff.days // 365} years ago)"
                        elif diff.days > 30:
                            relative = f"({diff.days // 30} months ago)"
                        elif diff.days > 0:
                            relative = f"({diff.days} days ago)"
                        elif diff.seconds > 3600:
                            relative = f"({diff.seconds // 3600} hours ago)"
                        elif diff.seconds > 60:
                            relative = f"({diff.seconds // 60} minutes ago)"
                        else:
                            relative = "(just now)"
                        
                        return f'<span class="timestamp" title="Original: {str_value}">{formatted_date}<br/><small class="relative-time">{relative}</small></span>'
                    except Exception as e:
                        # If conversion fails, show original with note
                        return f'<span class="timestamp-raw" title="Failed to parse timestamp: {e}">Raw: {str_value}</span>'
            
            # Regular string handling with better long text display
            if len(str_value) > 80:
                return f'''
                <div class="expandable-text-data">
                    <div class="text-preview" onclick="toggleTextData(this)">
                        <span class="preview-text">{str_value[:77]}...</span>
                        <button class="text-expand-btn" title="Click to expand full text">
                            <i class="fas fa-expand-alt"></i>
                        </button>
                    </div>
                    <div class="text-full" style="display: none;">
                        <div class="text-header">
                            <span class="text-title">Full Content</span>
                            <div class="text-actions">
                                <button class="copy-text-btn" onclick="copyTextData(this)" title="Copy to clipboard">
                                    <i class="fas fa-copy"></i>
                                </button>
                                <button class="text-collapse-btn" onclick="toggleTextData(this.closest('.expandable-text-data').querySelector('.text-preview'))" title="Collapse">
                                    <i class="fas fa-compress-alt"></i>
                                </button>
                            </div>
                        </div>
                        <div class="text-content">
                            <pre class="full-text-data">{str_value}</pre>
                        </div>
                    </div>
                </div>'''
            return str_value

    def _build_analysis_section(self, module_name, category, item):
        """Build security analysis section"""
        analysis = self._get_security_analysis(module_name, category, item)
        if not analysis:
            return ""
        
        return f"""
        <div class="analysis">
            <div class="analysis-title">🔍 Security Analysis</div>
            <div class="analysis-content">{analysis}</div>
        </div>
        {self._build_exploitation_section(module_name, category, item)}"""

    def _build_exploitation_section(self, module_name, category, item):
        """Build exploitation notes section"""
        exploits = self._get_exploitation_notes(module_name, category, item)
        if not exploits:
            return ""
        
        return f"""
        <div class="exploit">
            <div class="exploit-title">⚡ Exploitation Notes</div>
            <ul>{exploits}</ul>
        </div>"""

    def _build_simple_finding_html(self, module_name, category, item):
        """Build HTML for simple findings"""
        return f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{category.replace('_', ' ').title()}</div>
                <div class="severity-info">INFO</div>
            </div>
            <div class="finding-body">
                <div class="data-item">
                    <div class="data-value">{self._safe_str(item)}</div>
                </div>
            </div>
        </div>"""

    def _build_error_html(self, module_name, category, error):
        """Build HTML for error messages"""
        return f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{category.replace('_', ' ').title()} Error</div>
                <div class="severity-warning">WARNING</div>
            </div>
            <div class="finding-body">
                <div class="data-item">
                    <div class="data-label">Error Message</div>
                    <div class="data-value">{self._safe_str(error)}</div>
                </div>
            </div>
        </div>"""

    def _build_simple_content(self, module_name, data):
        """Build content for simple data structures"""
        return f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{module_name.title()} Data</div>
                <div class="severity-info">INFO</div>
            </div>
            <div class="finding-body">
                <div class="data-item">
                    <div class="data-value">{self._safe_str(data)}</div>
                </div>
            </div>
        </div>"""

    def _get_module_icon(self, module_name):
        """Get icon for module"""
        icons = {
            'ssh': '🔑',
            'browser': '🌐', 
            'keyring': '🔐',
            'memory': '🧠',
            'dotfiles': '📁',
            'history': '📜'
        }
        return icons.get(module_name, '📊')

    def _get_module_title(self, module_name):
        """Get display title for module"""
        titles = {
            'ssh': 'SSH Analysis',
            'browser': 'Browser Data',
            'keyring': 'Keyring Store', 
            'memory': 'Memory Analysis',
            'dotfiles': 'Configuration Files',
            'history': 'Command History'
        }
        return titles.get(module_name, module_name.title())

    def _get_finding_title(self, module_name, category, item):
        """Get title for a finding"""
        title = category.replace('_', ' ').title()
        
        if isinstance(item, dict):
            if 'path' in item:
                title += f" - {item['path']}"
            elif 'url' in item:
                title += f" - {item['url']}"
            elif 'file' in item:
                title += f" - {item['file']}"
            elif 'name' in item:
                title += f" - {item['name']}"
                
        return title

    def _get_severity(self, module_name, category, item):
        """Get severity class and label"""
        if module_name == 'ssh' and category == 'private_keys':
            if isinstance(item, dict) and not item.get('encrypted', True):
                return 'severity-critical', 'CRITICAL'
            else:
                return 'severity-warning', 'WARNING'
        elif module_name == 'browser' and category == 'passwords':
            return 'severity-critical', 'CRITICAL'
        elif module_name == 'keyring':
            return 'severity-critical', 'CRITICAL'
        elif module_name == 'memory':
            return 'severity-critical', 'CRITICAL'
        else:
            return 'severity-info', 'INFO'

    def _get_security_analysis(self, module_name, category, item):
        """Get security analysis text"""
        analyses = {
            ('ssh', 'private_keys'): "SSH private key discovered. If unencrypted, this provides immediate access to systems. Check if the key is encrypted and whether it requires a passphrase.",
            ('browser', 'passwords'): "Browser-saved credentials found. These often exhibit password reuse patterns and may provide access to additional services.",
            ('browser', 'cookies'): "Session cookies can be used for session hijacking attacks. Authentication cookies provide immediate access without needing credentials.",
            ('keyring', ''): "Keyring entries contain stored application credentials and secrets. These are often high-value targets for lateral movement.",
            ('memory', ''): "Process memory often contains plaintext credentials. Environment variables and arguments frequently expose passwords and API keys.",
            ('dotfiles', ''): "Configuration files often contain hardcoded credentials and API keys. Look for .env files, database configs, and application settings.",
            ('history', ''): "Command history reveals credentials passed as arguments and usage patterns. Often contains database connections, API calls, and administrative commands."
        }
        
        return analyses.get((module_name, category), analyses.get((module_name, ''), ''))

    def _get_exploitation_notes(self, module_name, category, item):
        """Get exploitation notes"""
        if module_name == 'ssh' and category == 'private_keys':
            if isinstance(item, dict) and not item.get('encrypted', True):
                return """
                <li>Copy key and set permissions: <code>chmod 600 keyfile</code></li>
                <li>Attempt SSH connection: <code>ssh -i keyfile user@target</code></li>
                <li>Try common usernames: root, admin, ubuntu</li>"""
            else:
                return """
                <li>Crack encrypted key: <code>ssh2john keyfile > hash.txt && john hash.txt</code></li>
                <li>Try common passphrases and dictionary attacks</li>
                <li>Once cracked, use as above</li>"""
        elif module_name == 'browser' and category == 'passwords':
            return """
            <li>Test credentials on original website</li>
            <li>Check for password reuse on other services</li>
            <li>Look for administrative interfaces</li>
            <li>Search for cloud service logins</li>"""
        elif module_name == 'keyring':
            return """
            <li>Extract using system tools: <code>secret-tool search --all</code></li>
            <li>Test credentials against identified services</li>
            <li>Look for database connection strings</li>
            <li>Search for API keys and tokens</li>"""
        
        return ""

    def _safe_str(self, value):
        """Safely convert value to string"""
        try:
            if value is None:
                return "None"
            return str(value)
        except:
            return "[Unable to display]"

    def _safe_json_dump(self, data):
        """Safely dump JSON data"""
        try:
            return json.dumps(data, indent=2, default=str)
        except:
            return str(data)

    def _is_running_as_root(self):
        """Check if the script is running with root privileges"""
        try:
            import os
            return os.geteuid() == 0
        except:
            return False

    def _get_hostname(self):
        """Get system hostname"""
        try:
            import socket
            return socket.gethostname()
        except:
            return "Unknown"

    def _get_os_info(self):
        """Get OS information"""
        try:
            import platform
            return f"{platform.system()} {platform.release()}"
        except:
            return "Unknown"

    def _get_kernel_version(self):
        """Get detailed kernel version"""
        try:
            import platform
            return platform.release()
        except:
            return "Unknown"

    def _get_linux_distribution(self):
        """Get Linux distribution information"""
        try:
            import platform
            import os
            
            # Try multiple methods to get distribution info
            dist_info = "Unknown Linux"
            
            # Method 1: Try /etc/os-release
            if os.path.exists('/etc/os-release'):
                try:
                    with open('/etc/os-release', 'r') as f:
                        lines = f.readlines()
                        name = ""
                        version = ""
                        for line in lines:
                            if line.startswith('PRETTY_NAME='):
                                dist_info = line.split('=')[1].strip().strip('"')
                                break
                            elif line.startswith('NAME='):
                                name = line.split('=')[1].strip().strip('"')
                            elif line.startswith('VERSION='):
                                version = line.split('=')[1].strip().strip('"')
                        
                        if not dist_info or dist_info == "Unknown Linux":
                            if name and version:
                                dist_info = f"{name} {version}"
                            elif name:
                                dist_info = name
                except:
                    pass
            
            # Method 2: Try platform.freedesktop_os_release()
            if dist_info == "Unknown Linux":
                try:
                    if hasattr(platform, 'freedesktop_os_release'):
                        release_info = platform.freedesktop_os_release()
                        if 'PRETTY_NAME' in release_info:
                            dist_info = release_info['PRETTY_NAME']
                        elif 'NAME' in release_info:
                            name = release_info['NAME']
                            version = release_info.get('VERSION', '')
                            dist_info = f"{name} {version}".strip()
                except:
                    pass
            
            # Method 3: Try /etc/lsb-release
            if dist_info == "Unknown Linux" and os.path.exists('/etc/lsb-release'):
                try:
                    with open('/etc/lsb-release', 'r') as f:
                        lines = f.readlines()
                        description = ""
                        for line in lines:
                            if line.startswith('DISTRIB_DESCRIPTION='):
                                description = line.split('=')[1].strip().strip('"')
                                break
                        if description:
                            dist_info = description
                except:
                    pass
            
            return dist_info
        except:
            return "Unknown Linux"

    def _get_kernel_architecture(self):
        """Get kernel architecture"""
        try:
            import platform
            return platform.machine()
        except:
            return "Unknown"

    def _get_current_user(self):
        """Get current user"""
        try:
            import getpass
            return getpass.getuser()
        except:
            return "Unknown"

    def _build_system_info_html(self):
        """Build system information section"""
        return f"""
        <div class="system-info">
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">🖥️ Hostname</div>
                    <div class="info-value">{self._get_hostname()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">💻 Operating System</div>
                    <div class="info-value">{self._get_os_info()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">👤 Current User</div>
                    <div class="info-value">{self._get_current_user()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">🔐 Execution Mode</div>
                    <div class="info-value {'info-privileged' if self._is_running_as_root() else 'info-limited'}">
                        {'Administrator (Root)' if self._is_running_as_root() else 'Standard User'}
                    </div>
                </div>
            </div>
        </div>"""

    def _build_privilege_warning_html(self):
        """Build privilege warning section based on execution context"""
        if self._is_running_as_root():
            return """
            <div class="alert alert-info">
                <div class="alert-header">
                    <span class="alert-icon"><i class="fas fa-info-circle"></i></span>
                    <span class="alert-title">Running as Administrator</span>
                </div>
                <div class="alert-body">
                    <p><strong>Full System Access:</strong> Running with administrator privileges provides comprehensive access to system resources.</p>
                    <ul>
                        <li><i class="fas fa-check-circle"></i> Can access all user directories and system files</li>
                        <li><i class="fas fa-check-circle"></i> Full memory analysis capabilities</li>
                        <li><i class="fas fa-check-circle"></i> Complete keyring and credential store access</li>
                        <li><i class="fas fa-check-circle"></i> Browser data from all user profiles</li>
                        <li><i class="fas fa-check-circle"></i> System-wide configuration files</li>
                    </ul>
                    <p><strong>Note:</strong> Some user-specific data (like command history) may still be limited to the root user's profile.</p>
                </div>
            </div>"""
        else:
            return """
            <div class="alert alert-warning">
                <div class="alert-header">
                    <span class="alert-icon"><i class="fas fa-exclamation-triangle"></i></span>
                    <span class="alert-title">Limited User Mode</span>
                </div>
                <div class="alert-body">
                    <p><strong>Restricted Access:</strong> Running as a standard user limits access to some system resources.</p>
                    <ul>
                        <li><i class="fas fa-exclamation-circle"></i> Limited to current user's files and directories</li>
                        <li><i class="fas fa-exclamation-circle"></i> Memory analysis may be restricted</li>
                        <li><i class="fas fa-exclamation-circle"></i> Some system-wide keyrings may be inaccessible</li>
                        <li><i class="fas fa-exclamation-circle"></i> Browser data limited to current user</li>
                        <li><i class="fas fa-exclamation-circle"></i> Some configuration files may be protected</li>
                    </ul>
                    <div class="recommendation">
                        <i class="fas fa-lightbulb"></i>
                        <strong>Recommendation:</strong> For comprehensive assessment, consider running with administrator privileges: <code>sudo python3 main.py</code>
                    </div>
                </div>
            </div>"""

    def _build_risk_gauge_html(self, critical, warning, info):
        """Build a visual risk gauge showing threat level"""
        total = critical + warning + info
        if total == 0:
            risk_level = "LOW"
            risk_color = "#10b981"
            risk_percentage = 20
        elif critical > 5:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
            risk_percentage = 90
        elif critical > 0 or warning > 10:
            risk_level = "HIGH"
            risk_color = "#f59e0b"
            risk_percentage = 75
        elif warning > 5:
            risk_level = "MEDIUM"
            risk_color = "#f59e0b"
            risk_percentage = 50
        else:
            risk_level = "LOW"
            risk_color = "#10b981"
            risk_percentage = 30

        return f"""
        <div class="risk-gauge">
            <div class="gauge-container">
                <div class="gauge-track"></div>
                <div class="gauge-fill" style="--fill-percentage: {risk_percentage}%; --fill-color: {risk_color}"></div>
                <div class="gauge-center">
                    <div class="risk-level" style="color: {risk_color}">{risk_level}</div>
                    <div class="risk-subtitle">Risk Level</div>
                </div>
            </div>
            <div class="gauge-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #dc2626"></div>
                    <span>Critical</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #f59e0b"></div>
                    <span>High/Medium</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #10b981"></div>
                    <span>Low</span>
                </div>
            </div>
        </div>"""

    def _build_enhanced_system_info_html(self):
        """Build enhanced system information section"""
        return f"""
        <div class="system-info-enhanced">
            <div class="system-header">
                <h3><i class="fas fa-server"></i> System Information</h3>
            </div>
            <div class="system-grid">
                <div class="system-card">
                    <div class="card-icon">
                        <i class="fas fa-desktop"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Hostname</div>
                        <div class="card-value">{self._get_hostname()}</div>
                    </div>
                </div>
                <div class="system-card linux-distro-card">
                    <div class="card-icon">
                        <i class="fab fa-linux"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Linux Distribution</div>
                        <div class="card-value">{self._get_linux_distribution()}</div>
                    </div>
                </div>
                <div class="system-card kernel-card">
                    <div class="card-icon">
                        <i class="fas fa-microchip"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Kernel Version</div>
                        <div class="card-value">{self._get_kernel_version()}</div>
                    </div>
                </div>
                <div class="system-card">
                    <div class="card-icon">
                        <i class="fas fa-cogs"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Architecture</div>
                        <div class="card-value">{self._get_kernel_architecture()}</div>
                    </div>
                </div>
                <div class="system-card">
                    <div class="card-icon">
                        <i class="fas fa-user"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Current User</div>
                        <div class="card-value">{self._get_current_user()}</div>
                    </div>
                </div>
                <div class="system-card privilege-card">
                    <div class="card-icon">
                        <i class="fas fa-{'crown' if self._is_running_as_root() else 'user-shield'}"></i>
                    </div>
                    <div class="card-content">
                        <div class="card-label">Execution Mode</div>
                        <div class="card-value {'privilege-root' if self._is_running_as_root() else 'privilege-user'}">
                            {'Administrator (Root)' if self._is_running_as_root() else 'Standard User'}
                        </div>
                    </div>
                </div>
            </div>
        </div>"""

    def _build_enhanced_dashboard_html(self, total, critical, warning, info, modules_with_data, total_modules, modules_with_errors):
        """Build enhanced dashboard with animations and better visuals"""
        return f"""
        <div class="dashboard-enhanced">
            <div class="dashboard-grid">
                <div class="metric-card total-card" data-metric="total">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-trend">
                            <i class="fas fa-arrow-up"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number" data-target="{total}">{total}</div>
                        <div class="metric-label">Total Findings</div>
                        <div class="metric-detail">{modules_with_data}/{total_modules} modules with data</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar" style="--progress: {min(100, (modules_with_data/total_modules)*100 if total_modules > 0 else 0)}%"></div>
                    </div>
                </div>

                <div class="metric-card critical-card" data-metric="critical">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-trend critical">
                            <i class="fas fa-{'arrow-up' if critical > 0 else 'check'}"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number critical" data-target="{critical}">{critical}</div>
                        <div class="metric-label">Critical Issues</div>
                        <div class="metric-detail">Immediate attention required</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar critical" style="--progress: {min(100, (critical/max(1,total))*100)}%"></div>
                    </div>
                </div>

                <div class="metric-card warning-card" data-metric="warning">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-trend warning">
                            <i class="fas fa-{'arrow-up' if warning > 0 else 'check'}"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number warning" data-target="{warning}">{warning}</div>
                        <div class="metric-label">Warnings</div>
                        <div class="metric-detail">Should be reviewed</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar warning" style="--progress: {min(100, (warning/max(1,total))*100)}%"></div>
                    </div>
                </div>

                <div class="metric-card info-card" data-metric="info">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-info-circle"></i>
                        </div>
                        <div class="metric-trend info">
                            <i class="fas fa-chart-line"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number info" data-target="{info}">{info}</div>
                        <div class="metric-label">Informational</div>
                        <div class="metric-detail">For reference</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar info" style="--progress: {min(100, (info/max(1,total))*100)}%"></div>
                    </div>
                </div>

                <div class="metric-card modules-card" data-metric="modules">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-puzzle-piece"></i>
                        </div>
                        <div class="metric-trend">
                            <i class="fas fa-{'exclamation' if modules_with_errors > 0 else 'check'}"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number" data-target="{total_modules}">{total_modules}</div>
                        <div class="metric-label">Modules Executed</div>
                        <div class="metric-detail">{modules_with_errors} with errors</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar" style="--progress: {((total_modules-modules_with_errors)/total_modules)*100 if total_modules > 0 else 100}%"></div>
                    </div>
                </div>

                <div class="metric-card privilege-card" data-metric="privilege">
                    <div class="metric-header">
                        <div class="metric-icon">
                            <i class="fas fa-{'crown' if self._is_running_as_root() else 'user-shield'}"></i>
                        </div>
                        <div class="metric-trend {'critical' if not self._is_running_as_root() else 'success'}">
                            <i class="fas fa-{'shield-alt' if self._is_running_as_root() else 'exclamation-triangle'}"></i>
                        </div>
                    </div>
                    <div class="metric-content">
                        <div class="metric-number {'critical' if not self._is_running_as_root() else 'success'}">{'ROOT' if self._is_running_as_root() else 'USER'}</div>
                        <div class="metric-label">Privilege Level</div>
                        <div class="metric-detail">{'Full system access' if self._is_running_as_root() else 'Limited access'}</div>
                    </div>
                    <div class="metric-progress">
                        <div class="progress-bar {'success' if self._is_running_as_root() else 'warning'}" style="--progress: {100 if self._is_running_as_root() else 50}%"></div>
                    </div>
                </div>
            </div>
        </div>"""

    def _build_module_filter_options(self, results):
        """Build module filter options for the dropdown"""
        options = ""
        for module_name in results.keys():
            module_title = self._get_module_title(module_name)
            options += f'<option value="{module_name}">{module_title}</option>'
        return options

    def _build_enhanced_modules_html(self, results):
        """Build enhanced modules HTML with better interactivity"""
        modules_html = ""
        
        for module_name, module_data in results.items():
            module_icon = self._get_module_icon(module_name)
            module_title = self._get_module_title(module_name)
            findings_count = self._count_findings(module_data)
            
            # Determine module status and styling
            status_class = ""
            status_icon = ""
            if isinstance(module_data, dict) and module_data.get('_status') == 'failed':
                status_class = "module-failed"
                status_icon = '<i class="fas fa-exclamation-triangle"></i>'
            elif isinstance(module_data, dict) and module_data.get('_status') == 'skipped':
                status_class = "module-skipped"
                status_icon = '<i class="fas fa-forward"></i>'
            elif findings_count > 0:
                if findings_count >= 5:
                    status_class = "module-high"
                    status_icon = '<i class="fas fa-fire"></i>'
                else:
                    status_class = "module-normal"
                    status_icon = '<i class="fas fa-check-circle"></i>'
            else:
                status_class = "module-empty"
                status_icon = '<i class="fas fa-check"></i>'
                
            modules_html += f"""
            <div class="module-enhanced {status_class}" data-module="{module_name}">
                <div class="module-header-enhanced" onclick="toggleModuleEnhanced('{module_name}')">
                    <div class="module-info">
                        <div class="module-icon-container">
                            {module_icon}
                        </div>
                        <div class="module-details">
                            <div class="module-title-enhanced">{module_title}</div>
                            <div class="module-subtitle">{self._get_module_description(module_name)}</div>
                        </div>
                    </div>
                    <div class="module-stats">
                        <div class="findings-badge">
                            <span class="findings-count">{findings_count}</span>
                            <span class="findings-label">findings</span>
                        </div>
                        <div class="module-status">
                            {status_icon}
                        </div>
                        <div class="expand-icon">
                            <i class="fas fa-chevron-down"></i>
                        </div>
                    </div>
                </div>
                <div class="module-content-enhanced" id="{module_name}-content">
                    {self._build_enhanced_module_content(module_name, module_data)}
                </div>
            </div>"""
            
        return modules_html

    def _get_module_description(self, module_name):
        """Get description for a module"""
        descriptions = {
            'ssh': 'Analyzes SSH keys, configurations, and agent status',
            'browser': 'Extracts saved passwords, cookies, and autofill data',
            'keyring': 'Scans system keyrings and credential stores', 
            'memory': 'Searches process memory for credentials and secrets',
            'dotfiles': 'Examines configuration files for hardcoded secrets',
            'history': 'Parses command history for exposed credentials'
        }
        return descriptions.get(module_name, 'Security analysis module')

    def _build_enhanced_module_content(self, module_name, module_data):
        """Build enhanced content for a module"""
        if not module_data:
            return """
            <div class="no-findings-enhanced">
                <div class="no-findings-icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="no-findings-content">
                    <h4>No findings detected</h4>
                    <p>This module completed successfully but found no credentials or sensitive data.</p>
                </div>
            </div>"""
        
        if isinstance(module_data, dict) and module_data.get('_status') == 'failed':
            return f"""
            <div class="module-error">
                <div class="error-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="error-content">
                    <h4>Module Execution Failed</h4>
                    <p>{module_data.get('_error', 'Unknown error occurred')}</p>
                </div>
            </div>"""
        
        if isinstance(module_data, dict) and module_data.get('_status') == 'skipped':
            return f"""
            <div class="module-skipped">
                <div class="skipped-icon">
                    <i class="fas fa-forward"></i>
                </div>
                <div class="skipped-content">
                    <h4>Module Skipped</h4>
                    <p>Reason: {module_data.get('_reason', 'Not specified')}</p>
                </div>
            </div>"""
        
        # Build enhanced findings
        content = ""
        if isinstance(module_data, dict):
            for category, items in module_data.items():
                if items and not category.startswith('_'):
                    content += self._build_enhanced_category_content(module_name, category, items)
        else:
            content += self._build_enhanced_simple_content(module_name, module_data)
            
        return content or """
        <div class="no-findings-enhanced">
            <div class="no-findings-icon">
                <i class="fas fa-info-circle"></i>
            </div>
            <div class="no-findings-content">
                <h4>No actionable findings</h4>
                <p>Data was collected but no security issues were identified.</p>
            </div>
        </div>"""

    def _build_enhanced_category_content(self, module_name, category, items):
        """Build enhanced category content with better styling"""
        if not items:
            return ""
            
        category_title = category.replace('_', ' ').title()
        
        # Handle different data structures
        findings_content = ""
        has_findings = False
        
        if isinstance(items, (list, tuple)):
            if len(items) > 0:
                category_count = len(items)
                has_findings = True
                for i, item in enumerate(items):
                    findings_content += self._build_enhanced_finding_card(module_name, category, item, i)
        elif isinstance(items, dict):
            if 'items' in items and isinstance(items['items'], list):
                if len(items['items']) > 0:
                    category_count = len(items['items'])
                    has_findings = True
                    for i, item in enumerate(items['items']):
                        findings_content += self._build_enhanced_finding_card(module_name, category, item, i)
                
                # Only show error if it's meaningful (not None, not empty string, not "None")
                if 'error' in items and items['error'] and str(items['error']).strip() and str(items['error']).strip().lower() not in ['none', 'null', '']:
                    findings_content += self._build_enhanced_error_card(module_name, category, items['error'])
            else:
                # Handle nested dictionaries - count actual content
                actual_items = []
                for sub_key, sub_items in items.items():
                    if isinstance(sub_items, (list, tuple)) and len(sub_items) > 0:
                        actual_items.extend(sub_items)
                        for i, item in enumerate(sub_items):
                            findings_content += self._build_enhanced_finding_card(module_name, f"{category}_{sub_key}", item, i)
                    elif isinstance(sub_items, dict) and len(sub_items) > 0:
                        # Check if dict has meaningful content (not just None/empty values)
                        meaningful_values = [v for v in sub_items.values() if v and str(v).strip() and str(v).strip().lower() not in ['none', 'null', '']]
                        if meaningful_values:
                            actual_items.append(sub_items)
                            findings_content += self._build_enhanced_finding_card(module_name, f"{category}_{sub_key}", sub_items, len(actual_items) - 1)
                
                if actual_items:
                    category_count = len(actual_items)
                    has_findings = True
        else:
            # Single item
            if items and str(items).strip() and str(items).strip().lower() not in ['none', 'null', '']:
                category_count = 1
                has_findings = True
                findings_content += self._build_enhanced_finding_card(module_name, category, items, 0)
        
        # Only return content if there are actual findings
        if not has_findings:
            return ""
            
        content = f"""
        <div class="category-section">
            <div class="category-header">
                <h4 class="category-title">
                    <i class="fas fa-folder-open"></i>
                    {category_title}
                </h4>
                <span class="category-count">{category_count} items</span>
            </div>
            <div class="category-content">
                {findings_content}
            </div>
        </div>"""
        
        return content

    def _build_enhanced_finding_card(self, module_name, category, item, index):
        """Build an enhanced finding card with modern styling"""
        severity_class, severity_label = self._get_severity(module_name, category, item)
        finding_title = self._get_finding_title(module_name, category, item)
        
        return f"""
        <div class="finding-card {severity_class}" data-severity="{severity_class}" data-module="{module_name}">
            <div class="finding-card-header">
                <div class="finding-title-section">
                    <h5 class="finding-title">{finding_title}</h5>
                    <div class="finding-meta">
                        <span class="severity-badge {severity_class}">{severity_label}</span>
                        <span class="finding-id">#{index + 1}</span>
                    </div>
                </div>
                <div class="finding-actions">
                    <button class="action-icon-btn" onclick="copyFinding(this)" title="Copy Finding">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="action-icon-btn" onclick="toggleFindingDetails(this)" title="Toggle Details">
                        <i class="fas fa-chevron-down"></i>
                    </button>
                </div>
            </div>
            <div class="finding-card-body" style="display: none;">
                {self._build_enhanced_data_grid(item)}
                {self._build_enhanced_analysis_section(module_name, category, item)}
            </div>
            <div class="finding-card-footer">
                <button class="json-toggle-enhanced" onclick="toggleJSONEnhanced(this)">
                    <i class="fas fa-code"></i>
                    <span>View Raw Data</span>
                </button>
                <div class="json-data-enhanced" style="display: none;">
                    <pre><code>{self._safe_json_dump(item)}</code></pre>
                </div>
            </div>
        </div>"""

    def _build_enhanced_data_grid(self, item):
        """Build enhanced data grid with better styling"""
        if not isinstance(item, dict):
            return f'<div class="simple-data"><span class="data-value">{self._safe_str(item)}</span></div>'
        
        grid_html = '<div class="enhanced-data-grid">'
        
        for key, value in item.items():
            if key.startswith('_'):  # Skip metadata
                continue
                
            display_value = self._format_value_for_display(key, value)
            icon = self._get_field_icon(key)
            
            grid_html += f"""
            <div class="data-field">
                <div class="field-header">
                    <i class="fas fa-{icon}"></i>
                    <span class="field-label">{key.replace('_', ' ').title()}</span>
                </div>
                <div class="field-value">{display_value}</div>
            </div>"""
            
        grid_html += '</div>'
        return grid_html

    def _get_field_icon(self, field_name):
        """Get appropriate icon for a field"""
        field_icons = {
            'path': 'folder',
            'file': 'file',
            'url': 'link',
            'username': 'user',
            'password': 'key',
            'email': 'envelope',
            'size': 'weight-hanging',
            'permissions': 'shield-alt',
            'encrypted': 'lock',
            'owner': 'user-tag',
            'hostname': 'server',
            'port': 'plug',
            'protocol': 'network-wired',
            'command': 'terminal',
            'process': 'cog',
            'pid': 'hashtag',
            'line': 'list-ol'
        }
        
        for keyword, icon in field_icons.items():
            if keyword in field_name.lower():
                return icon
        return 'info-circle'

    def _build_enhanced_analysis_section(self, module_name, category, item):
        """Build enhanced analysis section"""
        analysis = self._get_security_analysis(module_name, category, item)
        exploits = self._get_exploitation_notes(module_name, category, item)
        
        if not analysis and not exploits:
            return ""
        
        html = ""
        if analysis:
            html += f"""
            <div class="analysis-enhanced">
                <div class="analysis-header">
                    <i class="fas fa-search"></i>
                    <span>Security Analysis</span>
                </div>
                <div class="analysis-content">{analysis}</div>
            </div>"""
        
        if exploits:
            html += f"""
            <div class="exploitation-enhanced">
                <div class="exploitation-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Exploitation Notes</span>
                </div>
                <div class="exploitation-content">
                    <ul>{exploits}</ul>
                </div>
            </div>"""
        
        return html

    def _build_enhanced_simple_content(self, module_name, data):
        """Build enhanced content for simple data"""
        return f"""
        <div class="simple-content-enhanced">
            <div class="simple-header">
                <i class="fas fa-info-circle"></i>
                <span>{module_name.title()} Data</span>
            </div>
            <div class="simple-body">
                <pre>{self._safe_str(data)}</pre>
            </div>
        </div>"""

    def _build_enhanced_error_card(self, module_name, category, error):
        """Build enhanced error card with better error handling"""
        # Don't show error card for meaningless errors
        if not error or str(error).strip().lower() in ['none', 'null', '', 'no error']:
            return ""
            
        error_str = self._safe_str(error)
        if not error_str or error_str.strip().lower() in ['none', 'null', '', 'no error']:
            return ""
            
        return f"""
        <div class="error-card-enhanced">
            <div class="error-header-enhanced">
                <div class="error-icon-enhanced">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="error-info">
                    <h5 class="error-title">Process Error</h5>
                    <span class="error-category">{category.replace('_', ' ').title()}</span>
                </div>
            </div>
            <div class="error-body-enhanced">
                <div class="error-message">{error_str}</div>
                <div class="error-impact">
                    <small><i class="fas fa-info-circle"></i> This error may indicate missing dependencies, permission issues, or service unavailability.</small>
                </div>
            </div>
        </div>"""

    def _get_css_styles(self):
        """Get CSS styles for the report"""
        return """
        /* ===== CORE RESET & TYPOGRAPHY ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-color: #3b82f6;
            --primary-dark: #1d4ed8;
            --secondary-color: #64748b;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #dc2626;
            --info-color: #0ea5e9;
            --dark-color: #1f2937;
            --light-color: #f8fafc;
            --white: #ffffff;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-400: #9ca3af;
            --gray-500: #6b7280;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
            
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            
            --border-radius: 0.5rem;
            --border-radius-lg: 0.75rem;
            --border-radius-xl: 1rem;
            
            --transition: all 0.2s ease-in-out;
            --transition-slow: all 0.3s ease-in-out;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            min-height: 100vh;
        }

        /* ===== LOADING OVERLAY ===== */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 1;
            visibility: visible;
            transition: var(--transition-slow);
        }

        .loading-overlay.hidden {
            opacity: 0;
            visibility: hidden;
        }

        .loading-spinner {
            text-align: center;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--gray-200);
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loading-text {
            color: var(--gray-600);
            font-weight: 500;
        }

        /* ===== NAVIGATION ===== */
        .top-nav {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            background: var(--white);
            border-bottom: 1px solid var(--gray-200);
            box-shadow: var(--shadow);
            z-index: 1000;
            backdrop-filter: blur(10px);
        }

        .nav-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 64px;
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 700;
            font-size: 1.25rem;
            color: var(--primary-color);
        }

        .nav-actions {
            display: flex;
            gap: 0.5rem;
        }

        .nav-btn, .action-icon-btn {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 0.5rem;
            cursor: pointer;
            transition: var(--transition);
            color: var(--gray-600);
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
        }

        .nav-btn:hover, .action-icon-btn:hover {
            background: var(--primary-color);
            color: var(--white);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        /* ===== MAIN CONTAINER ===== */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            margin-top: 64px;
            background: var(--white);
            border-radius: var(--border-radius-xl);
            overflow: hidden;
            box-shadow: var(--shadow-xl);
        }

        /* ===== HERO SECTION ===== */
        .hero-section {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            color: var(--white);
            padding: 4rem 2rem;
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 3rem;
            align-items: center;
        }

        .hero-content {
            text-align: left;
        }

        .hero-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.9;
        }

        .hero-title {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 1rem;
            line-height: 1.2;
        }

        .hero-subtitle {
            font-size: 1.25rem;
            opacity: 0.9;
            margin-bottom: 2rem;
        }

        .hero-meta {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            opacity: 0.8;
            font-size: 0.9rem;
        }

        .hero-visual {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        /* ===== RISK GAUGE ===== */
        .risk-gauge {
            text-align: center;
        }

        .gauge-container {
            position: relative;
            width: 200px;
            height: 200px;
            margin: 0 auto 1rem;
        }

        .gauge-track {
            position: absolute;
            width: 100%;
            height: 100%;
            border: 8px solid rgba(255, 255, 255, 0.2);
            border-radius: 50%;
        }

        .gauge-fill {
            position: absolute;
            width: 100%;
            height: 100%;
            border: 8px solid transparent;
            border-top-color: var(--fill-color);
            border-radius: 50%;
            transform: rotate(calc(var(--fill-percentage) * 3.6deg - 90deg));
            transition: transform 2s ease-in-out;
        }

        .gauge-center {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .risk-level {
            font-size: 1.5rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }

        .risk-subtitle {
            font-size: 0.9rem;
            opacity: 0.8;
        }

        .gauge-legend {
            display: flex;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.8rem;
        }

        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        /* ===== ENHANCED SYSTEM INFO ===== */
        .system-info-enhanced {
            background: var(--gray-50);
            border-bottom: 1px solid var(--gray-200);
            padding: 2rem;
        }

        .system-header {
            margin-bottom: 1.5rem;
        }

        .system-header h3 {
            color: var(--gray-700);
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .system-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .system-card {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius-lg);
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: var(--transition);
            box-shadow: var(--shadow-sm);
        }

        .system-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        .card-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: var(--white);
            border-radius: var(--border-radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            flex-shrink: 0;
        }

        .card-content {
            flex: 1;
        }

        .card-label {
            font-size: 0.875rem;
            color: var(--gray-500);
            font-weight: 500;
            margin-bottom: 0.25rem;
        }

        .card-value {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--gray-800);
            font-family: 'SF Mono', Monaco, monospace;
        }

        .privilege-root {
            color: var(--danger-color) !important;
        }

        .privilege-user {
            color: var(--warning-color) !important;
        }

        .linux-distro-card .card-icon {
            background: linear-gradient(135deg, #ff6b35, #f7931e);
        }

        .kernel-card .card-icon {
            background: linear-gradient(135deg, #667eea, #764ba2);
        }

        /* ===== ENHANCED DASHBOARD ===== */
        .dashboard-enhanced {
            padding: 2rem;
            background: var(--white);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .metric-card {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius-xl);
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: var(--transition);
            box-shadow: var(--shadow);
        }

        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--primary-dark));
        }

        .metric-card.critical-card::before {
            background: linear-gradient(90deg, var(--danger-color), #b91c1c);
        }

        .metric-card.warning-card::before {
            background: linear-gradient(90deg, var(--warning-color), #d97706);
        }

        .metric-card.info-card::before {
            background: linear-gradient(90deg, var(--info-color), #0284c7);
        }

        .metric-card.modules-card::before {
            background: linear-gradient(90deg, #8b5cf6, #7c3aed);
        }

        .metric-card.privilege-card::before {
            background: linear-gradient(90deg, #f97316, #ea580c);
        }

        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .metric-icon {
            width: 48px;
            height: 48px;
            background: var(--gray-100);
            border-radius: var(--border-radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: var(--gray-600);
        }

        .metric-trend {
            padding: 0.5rem;
            border-radius: var(--border-radius);
            background: var(--success-color);
            color: var(--white);
            font-size: 0.875rem;
        }

        .metric-trend.critical {
            background: var(--danger-color);
        }

        .metric-trend.warning {
            background: var(--warning-color);
        }

        .metric-content {
            margin-bottom: 1rem;
        }

        .metric-number {
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--gray-800);
            line-height: 1;
            margin-bottom: 0.5rem;
        }

        .metric-number.critical {
            color: var(--danger-color);
        }

        .metric-number.warning {
            color: var(--warning-color);
        }

        .metric-number.info {
            color: var(--info-color);
        }

        .metric-number.success {
            color: var(--success-color);
        }

        .metric-label {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--gray-600);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }

        .metric-detail {
            font-size: 0.8rem;
            color: var(--gray-500);
        }

        .metric-progress {
            height: 6px;
            background: var(--gray-100);
            border-radius: 3px;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary-color), var(--primary-dark));
            width: var(--progress);
            transition: width 2s ease-in-out;
        }

        .progress-bar.critical {
            background: linear-gradient(90deg, var(--danger-color), #b91c1c);
        }

        .progress-bar.warning {
            background: linear-gradient(90deg, var(--warning-color), #d97706);
        }

        .progress-bar.info {
            background: linear-gradient(90deg, var(--info-color), #0284c7);
        }

        .progress-bar.success {
            background: linear-gradient(90deg, var(--success-color), #059669);
        }

        /* ===== CONTENT SECTIONS ===== */
        .content {
            padding: 2rem;
        }

        .content-header, .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--gray-100);
        }

        .section-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--gray-800);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .action-buttons, .filter-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .action-btn {
            padding: 0.75rem 1.5rem;
            border-radius: var(--border-radius);
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }

        .action-btn.primary {
            background: var(--primary-color);
            color: var(--white);
        }

        .action-btn.primary:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        .action-btn.secondary {
            background: var(--gray-100);
            color: var(--gray-700);
        }

        .action-btn.secondary:hover {
            background: var(--gray-200);
        }

        .action-btn.tertiary {
            background: transparent;
            color: var(--gray-600);
            border: 1px solid var(--gray-300);
        }

        .action-btn.tertiary:hover {
            background: var(--gray-50);
        }

        .filter-select {
            padding: 0.5rem 1rem;
            border: 1px solid var(--gray-300);
            border-radius: var(--border-radius);
            background: var(--white);
            font-size: 0.875rem;
            cursor: pointer;
        }

        .filter-select:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        /* ===== ENHANCED MODULES ===== */
        .module-enhanced {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius-xl);
            margin-bottom: 2rem;
            overflow: hidden;
            transition: var(--transition);
            box-shadow: var(--shadow);
        }

        .module-enhanced:hover {
            box-shadow: var(--shadow-lg);
        }

        .module-enhanced.module-high {
            border-left: 4px solid var(--danger-color);
        }

        .module-enhanced.module-normal {
            border-left: 4px solid var(--warning-color);
        }

        .module-enhanced.module-empty {
            border-left: 4px solid var(--success-color);
        }

        .module-enhanced.module-failed {
            border-left: 4px solid var(--gray-400);
        }

        .module-enhanced.module-skipped {
            border-left: 4px solid var(--info-color);
        }

        .module-header-enhanced {
            padding: 1.5rem 2rem;
            background: var(--gray-50);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: var(--transition);
        }

        .module-header-enhanced:hover {
            background: var(--gray-100);
        }

        .module-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .module-icon-container {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: var(--white);
            border-radius: var(--border-radius-lg);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .module-details {
            flex: 1;
        }

        .module-title-enhanced {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--gray-800);
            margin-bottom: 0.25rem;
        }

        .module-subtitle {
            font-size: 0.9rem;
            color: var(--gray-600);
        }

        .module-stats {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .findings-badge {
            background: var(--primary-color);
            color: var(--white);
            padding: 0.5rem 1rem;
            border-radius: var(--border-radius-lg);
            text-align: center;
            min-width: 80px;
        }

        .findings-count {
            display: block;
            font-size: 1.25rem;
            font-weight: 700;
        }

        .findings-label {
            display: block;
            font-size: 0.75rem;
            opacity: 0.9;
        }

        .module-status {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--gray-100);
            color: var(--gray-600);
        }

        .module-high .module-status {
            background: var(--danger-color);
            color: var(--white);
        }

        .module-normal .module-status {
            background: var(--warning-color);
            color: var(--white);
        }

        .module-empty .module-status {
            background: var(--success-color);
            color: var(--white);
        }

        .expand-icon {
            transition: var(--transition);
        }

        .module-content-enhanced {
            padding: 2rem;
            display: none;
            background: var(--white);
        }

        .module-content-enhanced.active {
            display: block;
        }

        /* ===== FINDING CARDS ===== */
        .finding-card {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius-lg);
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: var(--transition);
            box-shadow: var(--shadow-sm);
        }

        .finding-card:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .finding-card.severity-critical {
            border-left: 4px solid var(--danger-color);
        }

        .finding-card.severity-warning {
            border-left: 4px solid var(--warning-color);
        }

        .finding-card.severity-info {
            border-left: 4px solid var(--info-color);
        }

        .finding-card-header {
            background: var(--gray-50);
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--gray-200);
        }

        .finding-title-section {
            flex: 1;
        }

        .finding-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--gray-800);
            margin-bottom: 0.5rem;
        }

        .finding-meta {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-badge.severity-critical {
            background: var(--danger-color);
            color: var(--white);
        }

        .severity-badge.severity-warning {
            background: var(--warning-color);
            color: var(--white);
        }

        .severity-badge.severity-info {
            background: var(--info-color);
            color: var(--white);
        }

        .finding-id {
            font-size: 0.8rem;
            color: var(--gray-500);
            font-weight: 500;
        }

        .finding-actions {
            display: flex;
            gap: 0.5rem;
        }

                 .finding-card-body {
             padding: 1.5rem;
         }

         .finding-card-footer {
             padding: 1.5rem;
             border-top: 1px solid var(--gray-200);
             background: var(--gray-50);
         }

         .json-toggle-enhanced {
             background: linear-gradient(135deg, var(--gray-100), var(--gray-200));
             border: 1px solid var(--gray-300);
             color: var(--gray-700);
             padding: 0.75rem 1.25rem;
             border-radius: var(--border-radius);
             cursor: pointer;
             font-weight: 500;
             font-size: 0.875rem;
             transition: var(--transition);
             display: inline-flex;
             align-items: center;
             gap: 0.5rem;
             box-shadow: var(--shadow-sm);
         }

         .json-toggle-enhanced:hover {
             background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
             color: var(--white);
             transform: translateY(-1px);
             box-shadow: var(--shadow-md);
         }

         .json-toggle-enhanced.active {
             background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
             color: var(--white);
             border-color: var(--primary-dark);
         }

         .json-data-enhanced {
             margin-top: 1rem;
             background: var(--gray-900);
             color: var(--gray-100);
             border-radius: var(--border-radius);
             overflow: hidden;
             box-shadow: var(--shadow-lg);
             border: 1px solid var(--gray-700);
         }

         .json-data-enhanced pre {
             margin: 0;
             padding: 1.5rem;
             overflow-x: auto;
             font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
             font-size: 0.875rem;
             line-height: 1.6;
         }

         .json-data-enhanced code {
             color: var(--gray-100);
         }

        .enhanced-data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .data-field {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 1rem;
        }

        .field-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .field-label {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--gray-600);
        }

        .field-value {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9rem;
            color: var(--gray-800);
            word-break: break-all;
        }

        /* ===== ANALYSIS SECTIONS ===== */
        .analysis-enhanced, .exploitation-enhanced {
            margin-top: 1.5rem;
            padding: 1.25rem;
            border-radius: var(--border-radius);
            border: 1px solid var(--gray-200);
        }

        .analysis-enhanced {
            background: #f0f9ff;
            border-color: #bae6fd;
        }

        .exploitation-enhanced {
            background: #fef3c7;
            border-color: #fcd34d;
        }

        .analysis-header, .exploitation-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }

        .analysis-header {
            color: #0ea5e9;
        }

        .exploitation-header {
            color: #d97706;
        }

        .analysis-content, .exploitation-content {
            font-size: 0.9rem;
            line-height: 1.6;
        }

        .analysis-content {
            color: #0c4a6e;
        }

        .exploitation-content {
            color: #92400e;
        }

        .exploitation-content ul {
            margin: 0;
            padding-left: 1.5rem;
        }

        .exploitation-content code {
            background: #f59e0b;
            color: var(--white);
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.85rem;
        }

        /* ===== FOOTER ===== */
        .report-footer {
            background: var(--gray-800);
            color: var(--gray-300);
            padding: 3rem 2rem 2rem;
            margin-top: 4rem;
        }

        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
        }

        .footer-section h4 {
            color: var(--white);
            font-size: 1.125rem;
            margin-bottom: 0.75rem;
        }

        .footer-section p {
            font-size: 0.9rem;
            line-height: 1.6;
        }

        /* ===== RESPONSIVE DESIGN ===== */
        @media (max-width: 768px) {
            .hero-section {
                grid-template-columns: 1fr;
                text-align: center;
                gap: 2rem;
            }

            .hero-title {
                font-size: 2rem;
            }

            .system-grid, .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .content-header, .section-header {
                flex-direction: column;
                gap: 1rem;
                align-items: stretch;
            }

            .action-buttons, .filter-controls {
                justify-content: center;
                flex-wrap: wrap;
            }

            .enhanced-data-grid {
                grid-template-columns: 1fr;
            }

            .module-header-enhanced {
                padding: 1rem;
            }

            .module-info {
                flex-direction: column;
                text-align: center;
                gap: 0.75rem;
            }

            .module-stats {
                gap: 0.75rem;
            }
        }

        /* ===== ALERT STYLES (Enhanced) ===== */
        .alert {
            margin: 1rem;
            border-radius: var(--border-radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-md);
            backdrop-filter: blur(10px);
        }

        .alert-info {
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            border-left: 4px solid var(--primary-color);
        }

        .alert-warning {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border-left: 4px solid var(--warning-color);
        }

        .alert-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1.25rem 1.5rem 0.75rem;
            font-weight: 700;
        }

        .alert-info .alert-header {
            color: var(--primary-dark);
        }

        .alert-warning .alert-header {
            color: #92400e;
        }

        .alert-body {
            padding: 0.75rem 1.5rem 1.5rem;
            color: var(--gray-700);
        }

        .alert-body ul {
            margin: 1rem 0;
            padding-left: 1.5rem;
        }

        .alert-body li {
            margin: 0.5rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .recommendation {
            background: rgba(255, 255, 255, 0.8);
            padding: 1rem;
            border-radius: var(--border-radius);
            margin-top: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .alert-body code {
            background: rgba(0, 0, 0, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9rem;
            font-weight: 600;
        }

        /* ===== SEARCH MODAL ===== */
        .search-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }

        .search-modal.active {
            display: flex;
        }

        .modal-content {
            background: var(--white);
            border-radius: var(--border-radius-xl);
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: var(--shadow-xl);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--gray-200);
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--gray-500);
            padding: 0.5rem;
            border-radius: var(--border-radius);
        }

        .modal-close:hover {
            background: var(--gray-100);
            color: var(--gray-700);
        }

        .modal-body {
            padding: 1.5rem;
        }

        .search-input {
            width: 100%;
            padding: 1rem;
            border: 2px solid var(--gray-200);
            border-radius: var(--border-radius-lg);
            font-size: 1rem;
            margin-bottom: 1rem;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .search-results {
            max-height: 300px;
            overflow-y: auto;
        }

        /* ===== TIMESTAMP STYLES ===== */
        .timestamp {
            display: inline-block;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: var(--white);
            padding: 0.5rem 0.75rem;
            border-radius: var(--border-radius);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            font-weight: 500;
            text-align: center;
            line-height: 1.4;
            min-width: 160px;
            box-shadow: var(--shadow-sm);
            cursor: help;
            transition: var(--transition);
        }

        .timestamp:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .timestamp .relative-time {
            font-size: 0.75rem;
            opacity: 0.9;
            color: rgba(255, 255, 255, 0.9);
            font-weight: 400;
        }

        .timestamp-raw {
            display: inline-block;
            background: var(--warning-color);
            color: var(--white);
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.8rem;
            font-weight: 500;
            cursor: help;
        }

        /* ===== ENHANCED ERROR CARDS ===== */
        .error-card-enhanced {
            background: var(--white);
            border: 1px solid #fecaca;
            border-left: 4px solid var(--danger-color);
            border-radius: var(--border-radius-lg);
            margin: 1rem 0;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
            transition: var(--transition);
        }

        .error-card-enhanced:hover {
            box-shadow: var(--shadow-md);
        }

        .error-header-enhanced {
            background: linear-gradient(135deg, #fef2f2, #fee2e2);
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-bottom: 1px solid #fecaca;
        }

        .error-icon-enhanced {
            width: 40px;
            height: 40px;
            background: var(--danger-color);
            color: var(--white);
            border-radius: var(--border-radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.125rem;
            flex-shrink: 0;
        }

        .error-info {
            flex: 1;
        }

        .error-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--danger-color);
            margin: 0 0 0.25rem 0;
        }

        .error-category {
            font-size: 0.875rem;
            color: var(--gray-600);
            font-weight: 500;
        }

        .error-body-enhanced {
            padding: 1rem 1.5rem;
        }

        .error-message {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 0.75rem;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            color: var(--gray-800);
            margin-bottom: 0.75rem;
            word-break: break-word;
        }

        .error-impact {
            color: var(--gray-600);
            font-size: 0.8rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .error-impact i {
            color: var(--info-color);
        }

        /* ===== ENHANCED CATEGORY SECTIONS ===== */
        .category-section {
            margin: 2rem 0;
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius-lg);
            overflow: hidden;
            background: var(--white);
            box-shadow: var(--shadow-sm);
        }

        .category-header {
            background: linear-gradient(135deg, var(--gray-50), var(--gray-100));
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .category-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--gray-800);
            margin: 0;
        }

        .category-title i {
            color: var(--primary-color);
            font-size: 1rem;
        }

        .category-count {
            background: var(--primary-color);
            color: var(--white);
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .category-content {
            padding: 0;
        }

        /* ===== ENHANCED DATA GRID ===== */
        .enhanced-data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            padding: 1.5rem;
        }

        .data-field {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 1rem;
            transition: var(--transition);
        }

        .data-field:hover {
            background: var(--white);
            box-shadow: var(--shadow-sm);
        }

        .field-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .field-header i {
            color: var(--primary-color);
            font-size: 0.875rem;
        }

        .field-label {
            font-weight: 600;
            color: var(--gray-700);
            font-size: 0.875rem;
        }

        .field-value {
            color: var(--gray-800);
            font-weight: 500;
            word-break: break-word;
        }

        /* ===== NO FINDINGS ENHANCED ===== */
        .no-findings-enhanced {
            padding: 3rem 2rem;
            text-align: center;
            background: var(--gray-50);
            border-radius: var(--border-radius-lg);
            margin: 2rem 0;
        }

        .no-findings-icon {
            font-size: 3rem;
            color: var(--success-color);
            margin-bottom: 1rem;
        }

        .no-findings-content h4 {
            color: var(--gray-800);
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .no-findings-content p {
            color: var(--gray-600);
            font-size: 1rem;
        }

        /* ===== SSH-SPECIFIC STYLING ===== */
        .ssh-hosts-preview {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 0.75rem;
            margin: 0.5rem 0;
        }

        .ssh-host-item {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            transition: var(--transition);
        }

        .ssh-host-item:hover {
            box-shadow: var(--shadow-sm);
            border-color: var(--primary-color);
        }

        .ssh-host-item:last-child {
            margin-bottom: 0;
        }

        .host-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .hostname {
            font-weight: 600;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .hostname i {
            font-size: 0.875rem;
        }

        .key-type {
            background: var(--info-color);
            color: var(--white);
            padding: 0.125rem 0.5rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .key-type i {
            font-size: 0.625rem;
        }

        .key-preview {
            background: var(--gray-100);
            border-radius: var(--border-radius);
            padding: 0.5rem;
        }

        .key-preview code {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.75rem;
            color: var(--gray-700);
            word-break: break-all;
        }

        .more-hosts {
            text-align: center;
            color: var(--gray-500);
            font-style: italic;
            padding: 0.5rem;
            border-top: 1px dashed var(--gray-300);
            margin-top: 0.5rem;
            font-size: 0.875rem;
        }

        .ssh-key-data {
            background: var(--gray-100);
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            color: var(--gray-700);
            border: 1px solid var(--gray-300);
            cursor: help;
        }

        .ssh-key-data code {
            color: var(--gray-700);
            background: none;
            padding: 0;
        }

        .hostname-value {
            color: var(--primary-color);
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }

        .hostname-value i {
            font-size: 0.875rem;
        }

        .ssh-data-summary, .ssh-key-summary {
            background: linear-gradient(135deg, var(--info-color), #0284c7);
            color: var(--white);
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: help;
        }

        .redacted-value {
            background: var(--danger-color);
            color: var(--white);
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: help;
            letter-spacing: 0.1em;
        }

        .list-summary, .dict-summary {
            background: var(--gray-100);
            border: 1px solid var(--gray-300);
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-size: 0.875rem;
            color: var(--gray-700);
            cursor: help;
        }

        .empty-list {
            color: var(--gray-500);
            font-style: italic;
            font-size: 0.875rem;
        }

        /* ===== EXPANDABLE DATA STYLES ===== */
        .expandable-key-data, .expandable-text-data {
            background: var(--gray-50);
            border: 1px solid var(--gray-200);
            border-radius: var(--border-radius);
            overflow: hidden;
            margin: 0.25rem 0;
        }

        .key-data-preview, .text-preview {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem;
            cursor: pointer;
            transition: var(--transition);
            background: var(--white);
        }

        .key-data-preview:hover, .text-preview:hover {
            background: var(--gray-50);
        }

        .key-preview, .preview-text {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            color: var(--gray-700);
            flex: 1;
            word-break: break-all;
            margin-right: 0.5rem;
        }

        .expand-btn, .text-expand-btn {
            background: var(--primary-color);
            color: var(--white);
            border: none;
            border-radius: var(--border-radius);
            padding: 0.25rem 0.5rem;
            cursor: pointer;
            transition: var(--transition);
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .expand-btn:hover, .text-expand-btn:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
        }

        .key-data-full, .text-full {
            border-top: 1px solid var(--gray-200);
        }

        .key-data-header, .text-header {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: var(--white);
            padding: 0.75rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .key-data-title, .text-title {
            font-weight: 600;
            font-size: 0.875rem;
        }

        .key-data-actions, .text-actions {
            display: flex;
            gap: 0.5rem;
        }

        .copy-key-btn, .copy-text-btn, .collapse-btn, .text-collapse-btn {
            background: rgba(255, 255, 255, 0.2);
            color: var(--white);
            border: none;
            border-radius: var(--border-radius);
            padding: 0.25rem 0.5rem;
            cursor: pointer;
            transition: var(--transition);
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .copy-key-btn:hover, .copy-text-btn:hover, .collapse-btn:hover, .text-collapse-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-1px);
        }

        .key-data-content, .text-content {
            padding: 1rem;
            background: var(--gray-800);
            color: var(--gray-100);
        }

        .full-key-data, .full-text-data {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 0;
            background: none;
            color: inherit;
            border: none;
            padding: 0;
        }

        .short-key-data {
            background: var(--gray-100);
            border: 1px solid var(--gray-300);
            border-radius: var(--border-radius);
            padding: 0.5rem;
            margin: 0.25rem 0;
        }

        .short-key-data code {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            color: var(--gray-700);
            background: none;
            padding: 0;
        }

        /* Expandable data animations */
        .key-data-full, .text-full {
            animation: slideDown 0.3s ease-out;
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        """

    def _get_enhanced_javascript(self):
        """Get enhanced JavaScript functionality for the report"""
        return """
        // Global state
        let isDarkMode = false;
        let allData = {}; // Will be populated with findings data

        // Initialize on DOM ready
        document.addEventListener('DOMContentLoaded', function() {
            initializeReport();
            hideLoadingOverlay();
            animateMetrics();
            ensureAllCollapsed();
        });

        function initializeReport() {
            // Initialize tooltips, event listeners, etc.
            console.log('CredFinder Enhanced Report initialized');
        }

        function hideLoadingOverlay() {
            setTimeout(() => {
                const overlay = document.getElementById('loadingOverlay');
                if (overlay) {
                    overlay.classList.add('hidden');
                    setTimeout(() => overlay.remove(), 300);
                }
            }, 800);
        }

        function animateMetrics() {
            const metrics = document.querySelectorAll('.metric-number[data-target]');
            metrics.forEach(metric => {
                const target = parseInt(metric.getAttribute('data-target'));
                animateNumber(metric, 0, target, 2000);
            });
        }

        function animateNumber(element, start, end, duration) {
            const startTime = performance.now();
            const animate = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const easeOutCubic = 1 - Math.pow(1 - progress, 3);
                const current = Math.floor(start + (end - start) * easeOutCubic);
                element.textContent = current;
                
                if (progress < 1) {
                    requestAnimationFrame(animate);
                }
            };
            requestAnimationFrame(animate);
        }

        function ensureAllCollapsed() {
            // All modules and findings start collapsed by default
            const modules = document.querySelectorAll('.module-enhanced');
            modules.forEach(module => {
                const content = module.querySelector('.module-content-enhanced');
                if (content) {
                    content.classList.remove('active');
                    const icon = module.querySelector('.expand-icon i');
                    if (icon) icon.style.transform = 'rotate(0deg)';
                }
            });
        }

        // Enhanced module toggling
        function toggleModuleEnhanced(moduleId) {
            const content = document.getElementById(moduleId + '-content');
            const icon = document.querySelector(`[onclick="toggleModuleEnhanced('${moduleId}')"] .expand-icon i`);
            
            if (content) {
                content.classList.toggle('active');
                if (icon) {
                    icon.style.transform = content.classList.contains('active') ? 'rotate(180deg)' : 'rotate(0deg)';
                }
            }
        }

        function toggleAllModules() {
            const contents = document.querySelectorAll('.module-content-enhanced');
            const allActive = Array.from(contents).every(content => content.classList.contains('active'));
            
            contents.forEach(content => {
                if (allActive) {
                    content.classList.remove('active');
                } else {
                    content.classList.add('active');
                }
            });

            // Update all expand icons
            const icons = document.querySelectorAll('.expand-icon i');
            icons.forEach(icon => {
                icon.style.transform = allActive ? 'rotate(0deg)' : 'rotate(180deg)';
            });
        }

                 // Enhanced JSON toggling
         function toggleJSONEnhanced(button) {
             const jsonData = button.parentElement.querySelector('.json-data-enhanced');
             const icon = button.querySelector('i');
             const text = button.querySelector('span');
             
             if (jsonData) {
                 const isCurrentlyVisible = jsonData.style.display === 'block';
                 
                 if (isCurrentlyVisible) {
                     jsonData.style.display = 'none';
                     icon.className = 'fas fa-code';
                     text.textContent = 'View Raw Data';
                     button.classList.remove('active');
                 } else {
                     jsonData.style.display = 'block';
                     icon.className = 'fas fa-eye-slash';
                     text.textContent = 'Hide Raw Data';
                     button.classList.add('active');
                 }
             }
         }

        // Finding interactions
        function toggleFindingDetails(button) {
            const card = button.closest('.finding-card');
            const body = card.querySelector('.finding-card-body');
            const icon = button.querySelector('i');
            
            if (body.style.display === 'none') {
                body.style.display = 'block';
                icon.className = 'fas fa-chevron-up';
            } else {
                body.style.display = 'none';
                icon.className = 'fas fa-chevron-down';
            }
        }

        function copyFinding(button) {
            const card = button.closest('.finding-card');
            const title = card.querySelector('.finding-title').textContent;
            const jsonData = card.querySelector('.json-data-enhanced pre code').textContent;
            
            const content = `Finding: ${title}\\n\\nData:\\n${jsonData}`;
            
            navigator.clipboard.writeText(content).then(() => {
                showToast('Finding copied to clipboard!', 'success');
                const icon = button.querySelector('i');
                icon.className = 'fas fa-check';
                setTimeout(() => {
                    icon.className = 'fas fa-copy';
                }, 2000);
            }).catch(err => {
                showToast('Failed to copy finding', 'error');
            });
        }

        // Search functionality
        function showSearchModal() {
            const modal = document.getElementById('searchModal');
            if (modal) {
                modal.classList.add('active');
                document.getElementById('searchInput').focus();
            }
        }

        function hideSearchModal() {
            const modal = document.getElementById('searchModal');
            if (modal) {
                modal.classList.remove('active');
            }
        }

        function performSearch() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const results = document.getElementById('searchResults');
            
            if (query.length < 2) {
                results.innerHTML = '<p style="color: #6b7280; text-align: center; padding: 2rem;">Enter at least 2 characters to search</p>';
                return;
            }

            // Search through all findings
            const findings = document.querySelectorAll('.finding-card');
            const matches = [];

            findings.forEach(finding => {
                const title = finding.querySelector('.finding-title').textContent.toLowerCase();
                const content = finding.querySelector('.json-data-enhanced').textContent.toLowerCase();
                
                if (title.includes(query) || content.includes(query)) {
                    matches.push({
                        element: finding,
                        title: finding.querySelector('.finding-title').textContent,
                        module: finding.getAttribute('data-module')
                    });
                }
            });

            if (matches.length === 0) {
                results.innerHTML = '<p style="color: #6b7280; text-align: center; padding: 2rem;">No matches found</p>';
            } else {
                results.innerHTML = matches.map(match => `
                    <div style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; cursor: pointer;" 
                         onclick="jumpToFinding('${match.module}', '${match.title}')">
                        <div style="font-weight: 600; color: #1f2937;">${match.title}</div>
                        <div style="font-size: 0.875rem; color: #6b7280;">Module: ${match.module}</div>
                    </div>
                `).join('');
            }
        }

        function jumpToFinding(module, title) {
            hideSearchModal();
            
            // Expand the module if needed
            const moduleContent = document.getElementById(module + '-content');
            if (moduleContent && !moduleContent.classList.contains('active')) {
                toggleModuleEnhanced(module);
            }
            
            // Find and scroll to the finding
            setTimeout(() => {
                const findings = document.querySelectorAll('.finding-card');
                for (let finding of findings) {
                    if (finding.querySelector('.finding-title').textContent === title) {
                        finding.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        finding.style.boxShadow = '0 0 0 4px rgba(59, 130, 246, 0.3)';
                        setTimeout(() => {
                            finding.style.boxShadow = '';
                        }, 3000);
                        break;
                    }
                }
            }, 300);
        }

        // Filtering
        function filterBySeverity(severity) {
            const findings = document.querySelectorAll('.finding-card');
            
            findings.forEach(finding => {
                if (!severity || finding.getAttribute('data-severity') === 'severity-' + severity) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }

        function filterByModule(module) {
            const modules = document.querySelectorAll('.module-enhanced');
            
            modules.forEach(moduleEl => {
                if (!module || moduleEl.getAttribute('data-module') === module) {
                    moduleEl.style.display = 'block';
                } else {
                    moduleEl.style.display = 'none';
                }
            });
        }

        // Dark mode toggle
        function toggleDarkMode() {
            isDarkMode = !isDarkMode;
            document.body.classList.toggle('dark-mode', isDarkMode);
            
            const icon = document.querySelector('[onclick="toggleDarkMode()"] i');
            if (icon) {
                icon.className = isDarkMode ? 'fas fa-sun' : 'fas fa-moon';
            }
            
            showToast(isDarkMode ? 'Dark mode enabled' : 'Light mode enabled', 'info');
        }

        // Export functions
        function generatePDF() {
            showToast('PDF generation would require additional libraries', 'info');
            // In a real implementation, you'd use libraries like jsPDF or Puppeteer
        }

        function exportToJSON() {
            const reportData = {
                timestamp: new Date().toISOString(),
                findings: getAllFindings(),
                metadata: getReportMetadata()
            };
            
            const blob = new Blob([JSON.stringify(reportData, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'credfinder_enhanced_report_' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showToast('Report exported as JSON', 'success');
        }

        function exportReport() {
            // Create export options menu
            showToast('Multiple export formats available via action buttons', 'info');
        }

        // Utility functions
        function getAllFindings() {
            const findings = [];
            document.querySelectorAll('.finding-card').forEach(card => {
                const jsonData = card.querySelector('.json-data-enhanced pre code');
                if (jsonData) {
                    try {
                        findings.push(JSON.parse(jsonData.textContent));
                    } catch (e) {
                        // Skip invalid JSON
                    }
                }
            });
            return findings;
        }

        function getReportMetadata() {
            return {
                totalFindings: document.querySelectorAll('.finding-card').length,
                modules: Array.from(document.querySelectorAll('.module-enhanced')).map(m => m.getAttribute('data-module')),
                generatedAt: new Date().toISOString()
            };
        }

        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.style.cssText = `
                position: fixed;
                top: 100px;
                right: 20px;
                background: ${type === 'success' ? '#10b981' : type === 'error' ? '#dc2626' : '#3b82f6'};
                color: white;
                padding: 1rem 1.5rem;
                border-radius: 0.5rem;
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                z-index: 3000;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
            `;
            toast.textContent = message;
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.style.opacity = '1';
                toast.style.transform = 'translateX(0)';
            }, 100);
            
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => document.body.removeChild(toast), 300);
            }, 3000);
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'f':
                        e.preventDefault();
                        showSearchModal();
                        break;
                    case 'e':
                        e.preventDefault();
                        exportToJSON();
                        break;
                    case 'd':
                        e.preventDefault();
                        toggleDarkMode();
                        break;
                }
            }
            
            if (e.key === 'Escape') {
                hideSearchModal();
            }
        });

        // Close modal when clicking outside
        document.addEventListener('click', function(e) {
            const modal = document.getElementById('searchModal');
            if (modal && e.target === modal) {
                hideSearchModal();
            }
        });

        // ===== NEW EXPANDABLE DATA FUNCTIONS =====
        
        // Toggle key data expansion
        function toggleKeyData(element) {
            const container = element.closest('.expandable-key-data');
            const fullData = container.querySelector('.key-data-full');
            const icon = element.querySelector('.expand-btn i');
            
            if (fullData.style.display === 'none' || !fullData.style.display) {
                fullData.style.display = 'block';
                icon.className = 'fas fa-compress-alt';
            } else {
                fullData.style.display = 'none';
                icon.className = 'fas fa-expand-alt';
            }
        }

        // Toggle text data expansion
        function toggleTextData(element) {
            const container = element.closest('.expandable-text-data');
            const fullData = container.querySelector('.text-full');
            const icon = element.querySelector('.text-expand-btn i');
            
            if (fullData.style.display === 'none' || !fullData.style.display) {
                fullData.style.display = 'block';
                icon.className = 'fas fa-compress-alt';
            } else {
                fullData.style.display = 'none';
                icon.className = 'fas fa-expand-alt';
            }
        }

        // Copy key data to clipboard
        function copyKeyData(button) {
            const container = button.closest('.expandable-key-data');
            const keyData = container.querySelector('.full-key-data').textContent;
            
            navigator.clipboard.writeText(keyData).then(() => {
                showToast('Key data copied to clipboard!', 'success');
                const icon = button.querySelector('i');
                const originalClass = icon.className;
                icon.className = 'fas fa-check';
                setTimeout(() => {
                    icon.className = originalClass;
                }, 2000);
            }).catch(err => {
                showToast('Failed to copy key data', 'error');
            });
        }

        // Copy text data to clipboard
        function copyTextData(button) {
            const container = button.closest('.expandable-text-data');
            const textData = container.querySelector('.full-text-data').textContent;
            
            navigator.clipboard.writeText(textData).then(() => {
                showToast('Text data copied to clipboard!', 'success');
                const icon = button.querySelector('i');
                const originalClass = icon.className;
                icon.className = 'fas fa-check';
                setTimeout(() => {
                    icon.className = originalClass;
                }, 2000);
            }).catch(err => {
                showToast('Failed to copy text data', 'error');
            });
        }
        """