# CredFinder Documentation Wiki

<div align="center">

![CredFinder Logo](https://img.shields.io/badge/CredFinder-Linux%20Credential%20Scanner-blue?style=for-the-badge)

**Professional Linux Credential Discovery & Analysis Toolkit**

[![Version](https://img.shields.io/badge/version-1.0-green.svg)](https://github.com/user/credfinder-linux)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://github.com/user/credfinder-linux)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)

</div>

---

## 📚 Documentation Index

### 🚀 **Getting Started**
- [Quick Start Guide](#quick-start)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Command Examples](#command-examples)

### 📖 **Core Documentation**
- **[📋 Configuration Wiki](CONFIG_WIKI.md)** - Complete configuration reference
- **[🏗️ Architecture Guide](ARCHITECTURE.md)** - System design and technical details

### 🔧 **Advanced Topics**
- [Module Development](#module-development)
- [Custom Patterns](#custom-patterns)
- [Performance Tuning](#performance-tuning)
- [Security Considerations](#security-considerations)

### 🎯 **Use Cases**
- [Security Assessment](#security-assessment-mode)
- [Forensic Analysis](#forensic-analysis-mode)
- [OPSEC Operations](#opsec-stealth-mode)
- [Compliance Auditing](#compliance-auditing)

---

## 🌟 What is CredFinder?

CredFinder is a **comprehensive credential discovery and analysis toolkit** designed specifically for Linux environments. It employs a modular architecture to systematically scan for exposed credentials, API keys, passwords, and sensitive data across multiple vectors.

### ✨ Key Features

🔍 **Multi-Vector Scanning**
- SSH keys and configurations
- Browser stored credentials (Chrome, Firefox)
- Shell command history analysis
- Configuration file scanning
- System keyring extraction
- Process environment analysis

🛡️ **Security-First Design**
- OPSEC-aware stealth operations
- Comprehensive error handling
- Resource usage limits
- No network communications
- Secure temporary file handling

⚡ **High Performance**
- Parallel module execution
- Memory-efficient processing
- Configurable resource limits
- Early filtering and optimization

📊 **Professional Reporting**
- Modern HTML reports with interactive UI
- JSON output for automation
- CSV export for spreadsheet analysis
- Console output for immediate results
- Detailed statistics and metadata

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/user/credfinder-linux.git
cd credfinder-linux

# Install dependencies
pip3 install -r requirements.txt

# Make executable (optional)
chmod +x main.py
```

### Basic Usage

```bash
# Quick scan with fast modules
python3 main.py --fast-only --report console

# Full comprehensive scan
python3 main.py --all --report extend_html

# Specific modules with JSON output
python3 main.py --modules ssh browser keyring --report json

# High-performance parallel execution
python3 main.py --all --parallel --max-workers 6
```

### First Run Example

```bash
# Start with a safe, fast scan
python3 main.py --modules ssh dotfiles --report extend_html --verbose

# View the generated report
firefox reports/credfinder_extend_report_*.html
```

---

## 📋 Documentation Structure

### Configuration Reference
The **[Configuration Wiki](CONFIG_WIKI.md)** provides comprehensive details on:

| Section | Description |
|---------|-------------|
| **Scan Paths** | Where each module searches for credentials |
| **Pattern Library** | Regex patterns for credential detection |
| **Module Settings** | Detailed configuration for each scanner |
| **OPSEC Options** | Stealth and security settings |
| **Output Controls** | Report generation and formatting |
| **Performance Tuning** | Optimization for different scenarios |

### Architecture Guide
The **[Architecture Documentation](ARCHITECTURE.md)** covers:

| Topic | Description |
|-------|-------------|
| **System Design** | High-level architecture and design principles |
| **Module System** | Plugin architecture and scanner modules |
| **Data Flow** | How data flows through the system |
| **Security Model** | Threat mitigation and protection mechanisms |
| **Extension Points** | How to add custom modules and reporters |

---

## ⚡ Command Reference

### Module Selection
```bash
# All available modules
--all

# Fast modules only (< 30 seconds)
--fast-only

# Specific modules
--modules ssh browser keyring file_grep dotfiles history
```

### Report Formats
```bash
# Modern interactive HTML report
--report extend_html

# Structured JSON for automation
--report json

# CSV for spreadsheet analysis
--report csv

# Immediate console output
--report console
```

### Execution Modes
```bash
# Parallel execution (default, faster)
--parallel --max-workers 4

# Sequential execution (safer, debugging)
--sequential

# Verbose output
--verbose

# Debug mode
--debug
```

### Configuration
```bash
# Custom configuration file
--config /path/to/custom-config.json

# Custom output directory
--output-dir /path/to/reports/
```

---

## 🎯 Use Cases & Scenarios

### 🔒 Security Assessment Mode
**Purpose:** Professional security assessments and penetration testing

```bash
# Comprehensive security scan
python3 main.py --all --report extend_html --verbose

# Focus on high-risk areas
python3 main.py --modules ssh browser keyring --report json
```

**Best For:** Security teams, penetration testers, security auditors

### 🕵️ Forensic Analysis Mode
**Purpose:** Digital forensics and incident response

```bash
# Forensic evidence collection
python3 main.py --all --sequential --report json --debug

# Historical analysis
python3 main.py --modules history dotfiles --report csv
```

**Configuration:** Enable metadata collection, disable file modifications

### 👤 OPSEC Stealth Mode
**Purpose:** Covert operations with minimal detection risk

```bash
# Minimal footprint scan
python3 main.py --fast-only --report console --config opsec-config.json
```

**OPSEC Settings:**
```json
{
  "opsec": {
    "minimal_logging": true,
    "no_network_calls": true,
    "delete_temp_files": true
  }
}
```

### 📊 Compliance Auditing
**Purpose:** Regulatory compliance and policy enforcement

```bash
# Compliance credential audit
python3 main.py --modules dotfiles ssh --report csv --config compliance.json
```

**Focus Areas:** PCI DSS, SOX, GDPR credential exposure detection

---

## 🛠️ Advanced Configuration

### Performance Tuning

**Fast Scans (< 1 minute):**
```json
{
  "modules": {
    "ssh": {"enabled": true},
    "dotfiles": {"enabled": true},
    "history": {"enabled": true}
  }
}
```

**Comprehensive Scans (5-15 minutes):**
```json
{
  "module_settings": {
    "file_grep": {
      "max_files_per_pattern": 50,
      "search_base_paths": [
        "~/", "/tmp/", "/var/tmp/", "/opt/"
      ]
    }
  }
}
```

### Custom Pattern Examples

**Organization-Specific Patterns:**
```json
{
  "patterns": {
    "company_api_keys": [
      "CORP_KEY_[A-Za-z0-9]{32}",
      "INTERNAL_TOKEN[=:\\s]+[a-zA-Z0-9_-]+"
    ],
    "database_credentials": [
      "prod_db_pass[=:\\s]*[^\\s\"']+",
      "staging_password[=:\\s]*[^\\s\"']+"
    ]
  }
}
```

---

## 🔧 Module Development

### Creating Custom Scanner Modules

1. **Implement the Scanner Interface:**
```python
class CustomScanner:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("credfinder.custom")
    
    def scan(self) -> Dict[str, Any]:
        return {
            "findings": [],
            "statistics": {},
            "metadata": {}
        }
```

2. **Register in ModuleRunner:**
```python
self.module_classes = {
    'custom': {'class': CustomScanner, 'method': 'scan'}
}
```

3. **Add Configuration:**
```json
{
  "modules": {
    "custom": {
      "enabled": true,
      "priority": 7,
      "timeout": 60
    }
  }
}
```

### Custom Report Formats

1. **Implement Reporter Interface:**
```python
class CustomReporter:
    def generate(self, results, execution_stats, custom_filename=None):
        # Generate custom format
        return output_path
```

2. **Register with ReportOrchestrator:**
```python
self.reporters['custom'] = CustomReporter(self.config)
```

---

## 🛡️ Security Considerations

### File Permissions
```bash
# Secure configuration
chmod 600 config.json
chmod 700 reports/

# Secure execution
umask 077
python3 main.py --all
```

### Resource Limits
- **Memory Usage:** Configurable file size limits
- **Disk I/O:** Limited concurrent file operations
- **CPU Usage:** Process timeout enforcement
- **Network:** Zero network communications

### Data Protection
- **No Credential Caching:** All processing in-memory
- **Secure Cleanup:** Temporary files securely deleted
- **Minimal Logging:** OPSEC-aware log reduction
- **Permission Validation:** File access validation

---

## 📊 Performance Benchmarks

### Typical Execution Times

| Scan Type | Modules | Time | Findings |
|-----------|---------|------|----------|
| **Quick** | ssh, dotfiles | 15-30s | 10-25 |
| **Standard** | ssh, browser, history | 1-3m | 25-50 |
| **Comprehensive** | All modules | 5-15m | 50-200+ |

### Resource Usage

| Component | Memory | CPU | Disk I/O |
|-----------|--------|-----|----------|
| **SSH Scanner** | 10-20MB | Low | Medium |
| **Browser Extractor** | 20-50MB | Medium | High |
| **File Grepper** | 15-30MB | High | Very High |

---

## 🐛 Troubleshooting

### Common Issues

**Permission Denied Errors:**
```bash
# Run with appropriate permissions
sudo python3 main.py --modules keyring

# Or adjust scan paths in config
```

**Large Memory Usage:**
```bash
# Reduce file size limits
# Edit config.json module_settings
```

**Slow Performance:**
```bash
# Use fast-only mode
python3 main.py --fast-only

# Increase parallel workers
python3 main.py --all --max-workers 6
```

### Debug Mode
```bash
# Enable comprehensive debugging
python3 main.py --debug --verbose --modules ssh

# Check configuration validation
python3 main.py --modules ssh --debug 2>&1 | grep -i config
```

---

## 📞 Support & Contributing

### Getting Help
- **Documentation:** Review this wiki for comprehensive guidance
- **Issues:** Report bugs and feature requests via GitHub issues
- **Community:** Join discussions and share use cases

### Contributing
- **Bug Reports:** Detailed reproduction steps and logs
- **Feature Requests:** Use case descriptions and requirements
- **Code Contributions:** Follow the architecture patterns
- **Documentation:** Help improve and expand this wiki

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/user/credfinder-linux.git
cd credfinder-linux

# Install development dependencies
pip3 install -r requirements.txt

# Run tests
python3 -m pytest tests/

# Validate configuration
python3 main.py --modules ssh --debug
```

---

## 📜 License & Legal

**License:** MIT License - see [LICENSE](../LICENSE) file for details

**Legal Notice:** This tool is intended for authorized security testing and compliance auditing only. Users are responsible for ensuring proper authorization before scanning systems.

**Disclaimer:** The authors are not responsible for misuse or damage caused by this tool. Use responsibly and in accordance with applicable laws and regulations.

---

<div align="center">

**CredFinder** - Professional Linux Credential Discovery

[![GitHub](https://img.shields.io/badge/GitHub-View%20Source-black?style=flat-square&logo=github)](https://github.com/SweetLikeTwinkie/credfinder-linux)
[![Documentation](https://img.shields.io/badge/Docs-Read%20More-blue?style=flat-square&logo=gitbook)](https://github.com/SweetLikeTwinkie/credfinder-linux/wiki)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](../LICENSE)


</div> 