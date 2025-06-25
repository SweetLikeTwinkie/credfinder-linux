<div align="center">

![CredFinder Logo](https://github.com/user-attachments/assets/a7bfe52f-7d10-42cb-9226-10a0ceb165b1)

# 🔍 CredFinder Linux

### Professional Linux Credential Discovery & Analysis Toolkit

[![Version](https://img.shields.io/badge/version-2.0-brightgreen?style=for-the-badge)](https://github.com/SweetLikeTwinkie/credfinder-linux)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange?style=for-the-badge)](https://github.com/SweetLikeTwinkie/credfinder-linux)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)

[![Stars](https://img.shields.io/github/stars/SweetLikeTwinkie/credfinder-linux?style=social)](https://github.com/SweetLikeTwinkie/credfinder-linux/stargazers)
[![Forks](https://img.shields.io/github/forks/SweetLikeTwinkie/credfinder-linux?style=social)](https://github.com/SweetLikeTwinkie/credfinder-linux/network/members)

**A comprehensive, modular toolkit for discovering exposed credentials, SSH keys, API tokens, and sensitive data across Linux environments.**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](docs/README.md) • [🎯 Features](#-features) • [💾 Installation](#-installation) • [🛡️ Security](#-security-considerations)

</div>

## ⚠️ Legal Disclaimer

<div align="center">

> **🚨 AUTHORIZED USE ONLY 🚨**
> 
> This toolkit is designed for **authorized security testing**, **penetration testing**, and **compliance auditing** purposes only. 
> 
> **Use only on systems you own or have explicit written permission to test.**
> 
> Unauthorized use may violate local, state, and federal laws. Users are solely responsible for compliance with applicable laws and regulations.

</div>

---

## 🎯 Features

<div align="left">

### 🔐 **Multi-Vector Credential Discovery**

| Module | Description | Key Features |
|--------|-------------|--------------|
| 🔑 **SSH Scanner** | SSH key and configuration discovery | Private/public keys, SSH agent, known hosts, fingerprints |
| 🌐 **Browser Extractor** | Web browser credential extraction | Chrome/Firefox passwords, cookies, autofill data |
| 📝 **History Parser** | Shell command history analysis | Credential exposure detection, risk assessment |
| 📄 **Dotfile Scanner** | Configuration file analysis | Environment files, AWS/Docker/K8s configs |
| 🔍 **File Grepper** | Filesystem pattern scanning | Intelligent pattern matching, process environments |
| 💾 **Keyring Dump** | System keyring access | GNOME Keyring, KWallet, service credentials |

### ⚡ **Advanced Capabilities**

```
🚀 High-Performance Execution    🛡️ Security-First Design    📊 Professional Reporting
├─ Parallel module execution    ├─ OPSEC-aware operations   ├─ Interactive HTML reports
├─ Configurable workers         ├─ Resource usage limits    ├─ JSON for automation  
├─ Memory-efficient processing  ├─ No network calls         ├─ CSV for analysis
└─ Early filtering optimization └─ Secure temp file cleanup └─ Real-time console output
```

### 🎯 **Use Case Scenarios**

- **🔒 Security Assessments** - Professional penetration testing and security auditing
- **🕵️ Digital Forensics** - Incident response and forensic evidence collection  
- **👤 OPSEC Operations** - Covert scanning with minimal detection footprint
- **📋 Compliance Auditing** - PCI DSS, SOX, GDPR credential exposure detection

---

## 💾 Installation

<details>
<summary><b>📦 Quick Installation (Recommended)</b></summary>

```bash
# Clone the repository
git clone https://github.com/SweetLikeTwinkie/credfinder-linux.git
cd credfinder-linux

# Install Python dependencies
pip3 install -r requirements.txt

# Verify installation
python3 main.py --help
```

</details>

<details>
<summary><b>🐧 System Requirements</b></summary>

**Minimum Requirements:**
- Linux distribution (Ubuntu 18.04+, CentOS 7+, etc.)
- Python 3.8 or higher
- 512MB RAM (2GB+ recommended)
- 100MB disk space

**Recommended Setup:**
- Modern Linux distribution
- Python 3.10+
- 4GB+ RAM for comprehensive scans
- SSD storage for better performance

**Optional Dependencies:**
- `secret-tool` - For GNOME Keyring access
- `kwallet-query` - For KDE Wallet access
- Desktop environment - For full keyring functionality

</details>

<details>
<summary><b>🔧 Development Installation</b></summary>

```bash
# Clone with full development setup
git clone https://github.com/SweetLikeTwinkie/credfinder-linux.git
cd credfinder-linux

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x main.py

# Run test scan
python3 main.py --modules ssh --report console
```

</details>

---

## 🚀 Quick Start

### 🎯 **First Scan** (Safe & Fast)

```bash
# Quick security assessment (30-60 seconds)
python3 main.py --fast-only --report extend_html --verbose

# View the beautiful interactive report
firefox reports/credfinder_extend_report_*.html
```

### 🔍 **Common Usage Patterns**

<table>
<tr>
<th>Scenario</th>
<th>Command</th>
<th>Description</th>
</tr>
<tr>
<td><b>🔒 Security Assessment</b></td>
<td><code>python3 main.py --all --report extend_html</code></td>
<td>Comprehensive scan with modern HTML report</td>
</tr>
<tr>
<td><b>⚡ Quick Check</b></td>
<td><code>python3 main.py --fast-only --report console</code></td>
<td>Fast scan with immediate console output</td>
</tr>
<tr>
<td><b>🤖 Automation</b></td>
<td><code>python3 main.py --all --report json</code></td>
<td>Structured JSON output for scripts</td>
</tr>
<tr>
<td><b>🕵️ Stealth Mode</b></td>
<td><code>python3 main.py --modules ssh dotfiles --report console</code></td>
<td>Targeted scan with minimal footprint</td>
</tr>
</table>

### 🛠️ **Advanced Configuration**

```bash
# High-performance parallel execution
python3 main.py --all --parallel --max-workers 6

# Sequential execution for debugging
python3 main.py --all --sequential --debug

# Custom configuration file
python3 main.py --all --config custom-config.json

# Specific output directory
python3 main.py --all --output-dir /path/to/reports/
```

---

## 🧩 Available Modules

<div align="center">

| Module | Performance | Description | Key Targets |
|:------:|:-----------:|-------------|-------------|
| 🔑 `ssh` | ⚡ **Fast** | SSH key discovery and agent analysis | Private keys, public keys, known hosts, SSH configs |
| 📄 `dotfiles` | ⚡ **Fast** | Configuration file and dotfile scanning | `.env` files, `.bashrc`, AWS credentials, Docker configs |
| 📝 `history` | ⚡ **Fast** | Shell history parsing for credentials | Command history, exposed passwords, API keys |
| 🌐 `browser` | 🔄 **Medium** | Browser password and cookie extraction | Chrome/Firefox passwords, cookies, autofill data |
| 💾 `keyring` | 🔄 **Medium** | Desktop keyring credential extraction | GNOME Keyring, KWallet, stored passwords |
| 🔍 `file_grep` | ⏳ **Slow** | File-based credential pattern matching | Filesystem patterns, process environments |

</div>

### 📊 **Performance Guide**

- **⚡ Fast Modules** (15-30s): `ssh`, `dotfiles`, `history` - Perfect for quick assessments
- **🔄 Medium Modules** (1-3min): `browser`, `keyring` - Balanced speed vs coverage  
- **⏳ Comprehensive** (5-15min): All modules including `file_grep` - Complete analysis

---

## 📋 Configuration & Customization

<details>
<summary><b>🔧 Quick Configuration</b></summary>

The `config.json` file controls all scanning behavior:

```json
{
  "modules": {
    "ssh": {"enabled": true, "priority": 1},
    "browser": {"enabled": true, "priority": 4}
  },
  "patterns": {
    "aws_keys": ["AKIA[0-9A-Z]{16}"],
    "api_tokens": ["sk_[a-zA-Z0-9]{24,}"]
  },
  "output": {
    "default_format": "extend_html",
    "include_metadata": true
  }
}
```

**📖 [Complete Configuration Guide](docs/CONFIG_WIKI.md)**

</details>

<details>
<summary><b>📊 Report Formats</b></summary>

| Format | File Extension | Best For | Features |
|--------|----------------|----------|----------|
| **extend_html** | `.html` | 👁️ **Visual Analysis** | Interactive UI, modern design, filtering |
| **json** | `.json` | 🤖 **Automation** | Structured data, API integration |
| **csv** | `.csv` | 📈 **Spreadsheet Analysis** | Excel/LibreOffice compatible |
| **console** | Terminal | ⚡ **Real-time** | Immediate feedback, debugging |

</details>

---

## 🛡️ Security Considerations

<div align="center">

### 🔒 **Security-First Design Philosophy**

</div>

| Security Feature | Implementation | Benefit |
|------------------|----------------|---------|
| 🚫 **No Memory Access** | No `/dev/mem` or dangerous memory operations | Eliminates system crash risks |
| 🔓 **No Privilege Escalation** | Standard user permissions sufficient | Safer execution environment |
| 📏 **Resource Limits** | File size, memory, and timeout constraints | Prevents resource exhaustion |
| 🌐 **Zero Network Calls** | Completely offline operation | No data leakage or external dependencies |
| 🧹 **Secure Cleanup** | Automatic temporary file removal | Maintains operational security |

### 🎯 **OPSEC Features**

<details>
<summary><b>👤 Stealth Operation Mode</b></summary>

```json
{
  "opsec": {
    "minimal_logging": true,
    "no_network_calls": true,
    "delete_temp_files": true,
    "file_permissions": "600"
  }
}
```

**OPSEC Benefits:**
- ✅ Minimal forensic footprint
- ✅ No network traffic generation  
- ✅ Secure file permission handling
- ✅ Comprehensive cleanup procedures

</details>

<details>
<summary><b>🔒 Safe Operational Practices</b></summary>

**File System Safety:**
- Read-only operations where possible
- Size limits prevent memory exhaustion
- Path validation prevents directory traversal
- Binary file detection and skipping

**Process Safety:**
- No dangerous system calls
- Timeout protection for all operations
- Graceful error handling and recovery
- Resource usage monitoring

</details>

---

## 📚 Documentation

<div align="center">

### 📖 **[Complete Documentation Wiki](docs/README.md)**

**Professional documentation for advanced usage, configuration, and development**

</div>

<table>
<tr>
<th width="30%">📋 Category</th>
<th width="40%">📖 Resource</th>
<th width="30%">🎯 Purpose</th>
</tr>
<tr>
<td><b>🚀 Quick Start</b></td>
<td><a href="docs/README.md#quick-start">Installation & First Scan</a></td>
<td>Get started immediately</td>
</tr>
<tr>
<td><b>⚙️ Configuration</b></td>
<td><a href="docs/CONFIG_WIKI.md">Complete Config Reference</a></td>
<td>Customize scanning behavior</td>
</tr>
<tr>
<td><b>🏗️ Architecture</b></td>
<td><a href="docs/ARCHITECTURE.md">Technical Design Guide</a></td>
<td>Understand system internals</td>
</tr>
<tr>
<td><b>🎯 Use Cases</b></td>
<td><a href="docs/README.md#use-cases--scenarios">Security Scenarios</a></td>
<td>Real-world applications</td>
</tr>
<tr>
<td><b>⚡ Performance</b></td>
<td><a href="docs/README.md#performance-tuning">Optimization Guide</a></td>
<td>Speed up scans</td>
</tr>
<tr>
<td><b>🔧 Development</b></td>
<td><a href="docs/README.md#module-development">Custom Modules</a></td>
<td>Extend functionality</td>
</tr>
</table>

### 💡 **Quick Reference**

```bash
# 📖 View documentation locally
firefox docs/README.md

# ⚙️ Configuration examples  
cat docs/CONFIG_WIKI.md | grep -A 10 "Examples"

# 🏗️ Architecture overview
head -50 docs/ARCHITECTURE.md
```

---

## 🤝 Contributing

We welcome contributions from the security community! Here's how you can help improve CredFinder:

<div align="center">

### 🌟 **Ways to Contribute**

[![Report Bug](https://img.shields.io/badge/🐛-Report%20Bug-red?style=for-the-badge)](https://github.com/SweetLikeTwinkie/credfinder-linux/issues)
[![Request Feature](https://img.shields.io/badge/💡-Request%20Feature-blue?style=for-the-badge)](https://github.com/SweetLikeTwinkie/credfinder-linux/issues)
[![Improve Docs](https://img.shields.io/badge/📖-Improve%20Docs-green?style=for-the-badge)](docs/)

</div>

<details>
<summary><b>🚀 Quick Contribution Guide</b></summary>

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/credfinder-linux.git
cd credfinder-linux

# 2. Create feature branch
git checkout -b feature/your-amazing-feature

# 3. Make your changes
# Add your improvements, fixes, or new modules

# 4. Test your changes
python3 main.py --modules ssh --report console --debug

# 5. Commit and push
git commit -m "Add amazing feature"
git push origin feature/your-amazing-feature

# 6. Create Pull Request
# Go to GitHub and create a PR with detailed description
```

</details>

<details>
<summary><b>🔧 Development Areas</b></summary>

**High-Impact Contributions:**
- 🔍 **New Scanner Modules** - Add support for new credential sources
- 📊 **Report Formats** - Create custom output formats
- 🎯 **Pattern Libraries** - Improve credential detection patterns
- ⚡ **Performance** - Optimize scanning algorithms
- 🛡️ **Security** - Enhance OPSEC and safety features
- 📖 **Documentation** - Improve guides and examples

**Beginner-Friendly:**
- 🐛 **Bug Reports** - Detailed issue descriptions with reproduction steps
- 📝 **Documentation** - Fix typos, improve examples, add use cases
- 🧪 **Testing** - Add test cases for edge cases and configurations
- 🌐 **Localization** - Translate documentation to other languages

</details>

### 📋 **Contribution Guidelines**

- **Code Quality:** Follow existing patterns and include proper error handling
- **Documentation:** Update relevant docs for any new features
- **Testing:** Test your changes on multiple Linux distributions
- **Security:** Ensure all contributions maintain security-first principles

---

## 📜 License & Legal

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**This project is licensed under the MIT License**

</div>

<details>
<summary><b>📖 License Summary</b></summary>

**Permissions:**
- ✅ Commercial use
- ✅ Modification  
- ✅ Distribution
- ✅ Private use

**Conditions:**
- 📄 Include copyright notice
- 📄 Include license text

**Limitations:**
- ❌ No warranty
- ❌ No liability

**Full License:** See [LICENSE](LICENSE) file for complete terms.

</details>

---

## 📈 Changelog

<details>
<summary><b>🚀 Version 2.0 - Security-First Rewrite (Current)</b></summary>

### 🔄 **Breaking Changes**
- ❌ **Removed dangerous memory scanning** - Eliminated `/dev/mem` access for system safety
- ❌ **Simplified execution strategies** - Streamlined complex dependency management
- ⚡ **Performance improvements** - Race condition fixes and optimized parallel execution

### ✨ **New Features**
- 🔍 **Safe file-based scanning** - Comprehensive filesystem credential discovery
- 🎯 **Modern pattern matching** - Updated patterns for current credential formats
- 📊 **Professional HTML reports** - Interactive, modern UI with filtering and search
- 🛡️ **OPSEC capabilities** - Stealth operation modes with minimal footprint
- 📋 **Configuration validation** - Robust config file validation and error handling

### 🔧 **Improvements**
- ⚙️ **Simplified configuration** - Streamlined config structure with better defaults
- 🔧 **Enhanced error handling** - Comprehensive exception management and recovery
- 📖 **Professional documentation** - Complete wiki with guides and examples
- 🧪 **Modular architecture** - Plugin-based system for easy extension

### 🐛 **Fixes**
- 🛡️ **Security vulnerabilities** - Removed all dangerous system access patterns
- 📦 **Dependency reduction** - Minimal external dependencies for better portability
- 🧹 **Code cleanup** - Removed unused functionality and dead code
- ⚡ **Performance issues** - Fixed race conditions and resource leaks

</details>

<details>
<summary><b>📜 Version 1.0 - Initial Release (Deprecated)</b></summary>

- 🚀 Initial release with memory scanning capabilities
- ⚠️ **Deprecated due to security concerns**
- 🔄 **Replaced by Version 2.0** for safer operation

</details>

---

<div align="center">

## 🎯 **Ready to Start?**

### Choose Your Adventure

<table>
<tr>
<td align="center" width="33%">
<b>🚀 Quick Start</b><br/>
<code>python3 main.py --fast-only --report extend_html</code><br/>
<em>Perfect for first-time users</em>
</td>
<td align="center" width="33%">
<b>🔒 Security Assessment</b><br/>
<code>python3 main.py --all --report extend_html</code><br/>
<em>Comprehensive professional scan</em>
</td>
<td align="center" width="33%">
<b>🤖 Automation</b><br/>
<code>python3 main.py --all --report json</code><br/>
<em>Perfect for scripts and tools</em>
</td>
</tr>
</table>

### 🌟 **Star this repository if CredFinder helped you!**

[![GitHub stars](https://img.shields.io/github/stars/SweetLikeTwinkie/credfinder-linux?style=social)](https://github.com/SweetLikeTwinkie/credfinder-linux)

---

### 💬 **Questions, Issues, or Ideas?**

**We're here to help!** Open an issue or contribute to make CredFinder even better.

[![Report Issue](https://img.shields.io/badge/🐛-Report%20Issue-red?style=flat-square)](https://github.com/SweetLikeTwinkie/credfinder-linux/issues)
[![Request Feature](https://img.shields.io/badge/💡-Request%20Feature-blue?style=flat-square)](https://github.com/SweetLikeTwinkie/credfinder-linux/issues)
[![Join Discussion](https://img.shields.io/badge/💬-Join%20Discussion-green?style=flat-square)](https://github.com/SweetLikeTwinkie/credfinder-linux/discussions)

---

**🔍 CredFinder Linux** - *Professional credential discovery made safe and powerful*

[![Made with ❤️](https://img.shields.io/badge/Made%20with-❤️-red?style=flat-square)](#) 
[![For Security](https://img.shields.io/badge/For-Security%20Professionals-blue?style=flat-square)](#)
[![Open Source](https://img.shields.io/badge/Open-Source-green?style=flat-square)](LICENSE)

*© 2025 CredFinder Contributors. Released under MIT License.*

</div>
