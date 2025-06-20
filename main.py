#!/usr/bin/env python3
"""
credfinder-linux — Main Entry Point
Linux Credential & Secret Hunting Toolkit
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Import modules
from modules.ssh_scanner import SSHScanner
from modules.browser_extractor import BrowserExtractor
from modules.keyring_dump import KeyringDump
from modules.memory_grepper import MemoryGrepper
from modules.dotfile_scanner import DotfileScanner
from modules.history_parser import HistoryParser
from modules.report_generator import ReportGenerator
from modules.utils.logger import Logger
from modules.utils.config_loader import ConfigLoader


class CredFinder:
    def __init__(self, config_path="config.json"):
        self.config = ConfigLoader(config_path)
        self.logger = Logger(self.config.get("opsec", {}).get("minimal_logging", False))
        self.results = {}
        
    def run_ssh_scan(self):
        """Run SSH credential discovery"""
        self.logger.info("Starting SSH credential discovery...")
        scanner = SSHScanner(self.config)
        self.results['ssh'] = scanner.scan()
        return self.results['ssh']
    
    def run_browser_scan(self):
        """Run browser credential extraction"""
        self.logger.info("Starting browser credential extraction...")
        extractor = BrowserExtractor(self.config)
        self.results['browser'] = extractor.extract_all()
        return self.results['browser']
    
    def run_keyring_scan(self):
        """Run desktop keyring dump"""
        self.logger.info("Starting desktop keyring dump...")
        keyring = KeyringDump(self.config)
        self.results['keyring'] = keyring.dump()
        return self.results['keyring']
    
    def run_memory_scan(self):
        """Run memory-based secret hunting"""
        self.logger.info("Starting memory-based secret hunting...")
        memory = MemoryGrepper(self.config)
        self.results['memory'] = memory.scan()
        return self.results['memory']
    
    def run_dotfile_scan(self):
        """Run dotfile credential scanning"""
        self.logger.info("Starting dotfile credential scanning...")
        scanner = DotfileScanner(self.config)
        self.results['dotfiles'] = scanner.scan()
        return self.results['dotfiles']
    
    def run_history_scan(self):
        """Run shell history parsing"""
        self.logger.info("Starting shell history parsing...")
        parser = HistoryParser(self.config)
        self.results['history'] = parser.parse()
        return self.results['history']
    
    def run_all_scans(self):
        """Run all available scans"""
        self.logger.info("Starting comprehensive credential hunt...")
        
        modules = self.config.get("modules", {})
        
        if modules.get("ssh", True):
            self.run_ssh_scan()
        
        if modules.get("browser", True):
            self.run_browser_scan()
        
        if modules.get("keyring", True):
            self.run_keyring_scan()
        
        if modules.get("memory", True):
            self.run_memory_scan()
        
        if modules.get("dotfiles", True):
            self.run_dotfile_scan()
        
        if modules.get("history", True):
            self.run_history_scan()
        
        return self.results
    
    def generate_report(self, format_type="json"):
        """Generate report in specified format"""
        self.logger.info(f"Generating {format_type} report...")
        generator = ReportGenerator(self.config)
        return generator.generate(self.results, format_type)
    
    def save_results(self, output_dir="./reports"):
        """Save results to output directory"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_path = os.path.join(output_dir, f"credfinder_results_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to {json_path}")
        return json_path


def main():
    parser = argparse.ArgumentParser(
        description="credfinder-linux — Linux Credential & Secret Hunting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --all                    # Run all scans
  python3 main.py --ssh --browser          # Run specific modules
  python3 main.py --all --report html      # Generate HTML report
  python3 main.py --all --target /home/user # Scan specific directory
  python3 main.py --all --opsec            # OPSEC mode
        """
    )
    
    # Module selection
    parser.add_argument("--all", action="store_true", help="Run all available scans")
    parser.add_argument("--ssh", action="store_true", help="SSH credential discovery")
    parser.add_argument("--browser", action="store_true", help="Browser credential extraction")
    parser.add_argument("--keyring", action="store_true", help="Desktop keyring dump")
    parser.add_argument("--memory", action="store_true", help="Memory-based secret hunting")
    parser.add_argument("--dotfiles", action="store_true", help="Dotfile credential scanning")
    parser.add_argument("--history", action="store_true", help="Shell history parsing")
    
    # Options
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    parser.add_argument("--target", help="Target directory to scan")
    parser.add_argument("--report", choices=["json", "html", "csv", "console"], 
                       default="json", help="Report format")
    parser.add_argument("--opsec", action="store_true", help="Enable OPSEC mode")
    parser.add_argument("--output-dir", default="./reports", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize CredFinder
    credfinder = CredFinder(args.config)
    
    # Override config with command line arguments
    if args.target:
        credfinder.config.set_scan_paths(args.target)
    
    if args.opsec:
        credfinder.config.set_opsec_mode(True)
    
    # Run scans based on arguments
    if args.all:
        results = credfinder.run_all_scans()
    else:
        results = {}
        if args.ssh:
            results['ssh'] = credfinder.run_ssh_scan()
        if args.browser:
            results['browser'] = credfinder.run_browser_scan()
        if args.keyring:
            results['keyring'] = credfinder.run_keyring_scan()
        if args.memory:
            results['memory'] = credfinder.run_memory_scan()
        if args.dotfiles:
            results['dotfiles'] = credfinder.run_dotfile_scan()
        if args.history:
            results['history'] = credfinder.run_history_scan()
        
        if not any([args.ssh, args.browser, args.keyring, args.memory, args.dotfiles, args.history]):
            print("No modules selected. Use --all or specify individual modules.")
            sys.exit(1)
    
    # Generate and save results
    if results:
        credfinder.save_results(args.output_dir)
        
        if args.report != "json":
            report_path = credfinder.generate_report(args.report)
            print(f"Report generated: {report_path}")
        
        # Print summary
        total_findings = sum(len(v) if isinstance(v, list) else 1 for v in results.values() if v)
        print(f"\nScan completed! Found {total_findings} potential credentials/secrets.")
        
        if args.verbose:
            print("\nSummary:")
            for module, data in results.items():
                if data:
                    count = len(data) if isinstance(data, list) else 1
                    print(f"  {module}: {count} findings")
    else:
        print("No credentials or secrets found.")


if __name__ == "__main__":
    main() 