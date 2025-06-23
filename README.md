# credfinder-linux

**Linux Credential & Secret Hunting Toolkit**

A comprehensive post-exploitation toolkit for harvesting secrets, credentials, SSH keys, tokens, and config leaks on Linux systems. Designed for security professionals, penetration testers, and system administrators.

---

## Legal Disclaimer

> **This toolkit is intended for authorized security testing and penetration testing purposes only. Use it only on systems you own or have explicit permission to test. Unauthorized use may violate laws and regulations.**

---

## Features

- **SSH Credential Discovery**
  - Find private/public keys in common locations
  - Check SSH agent and dump loaded identities

- **Browser Password & History Extraction**
  - Extract and decrypt credentials from Chromium-based browsers (Chrome, Chromium, Brave)
  - Extract Firefox saved passwords and cookies (with optional decryption)
  - Automatic password decryption for supported browsers on Linux

- **Desktop Keyring Dump**
  - Extract passwords from GNOME Keyring and KWallet

- **Memory-Based Secret Hunting**
  - Search processes and memory for secrets
  - Parse memory dumps for credentials (Volatility support)

- **Dotfile & Config Parsers**
  - Scan configuration files and dotfiles for secrets
  - Parse shell history for credentials

- **Keylogging & Clipboard Sniffers (Optional)**
  - Capture keystrokes (desktop environments only)
  - Monitor clipboard for sensitive data

---

## Installation

```bash
git clone <repository-url>
cd credfinder-linux
pip install -r requirements.txt
chmod +x scripts/*.sh
```

---

## Quick Start

### Basic Scan

```bash
# Run all modules
python3 main.py --all

# Run specific modules
python3 main.py --modules ssh browser
```

### Advanced Usage

```bash
# Generate an HTML report
python3 main.py --all --report html

# Scan a specific directory
python3 main.py --all --target /home/user

# Enable OPSEC mode (minimal logging)
python3 main.py --all --opsec
```

---

## Requirements

- Python 3.7+
- SQLite3
- Common Linux utilities (`grep`, `find`, `ps`, etc.)
- Optional: Volatility Framework (for memory analysis)
- Optional: `pycryptodome` (for browser password decryption)
- Optional: `secretstorage` (for GNOME Keyring access)

---

## Configuration

Edit `config.json` to customize:
- Scan paths and file patterns
- Output formats and directories
- OPSEC and security settings

---

## Output Formats

- **JSON**: Structured data for automation
- **HTML**: Human-readable reports
- **CSV**: Spreadsheet-friendly format
- **Console**: Real-time output

---

## OPSEC Considerations

- Minimal logging in OPSEC mode
- No network calls unless explicitly configured
- Clean exit without traces
- Configurable file and directory permissions

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## Acknowledgments

- Inspired by common post-exploitation and credential hunting techniques
- Contributions and feedback are welcome!

---

**For questions, issues, or contributions, please open an issue or pull request on the repository.**