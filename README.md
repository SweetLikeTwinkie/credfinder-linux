# credfinder-linux — Linux Credential & Secret Hunting Scripts

A comprehensive post-exploitation toolkit for harvesting secrets, credentials, SSH keys, tokens, and config leaks on Linux systems.

## Legal Disclaimer

This toolkit is designed for **authorized security testing and penetration testing purposes only**. Only use on systems you own or have explicit permission to test. Unauthorized use may violate laws and regulations.

## Features / Script Modules

### 1. SSH Credential Discovery
- **`find_ssh_keys.sh`**: Search for private/public keys in common locations
- **`check_ssh_agents.py`**: Check SSH agent and dump loaded identities

### 2. Browser Password & History Extractor
- **`chrome_dump.py`**: Extract credentials from Chromium-based browsers
- **`firefox_logins.py`**: Extract Firefox saved passwords and cookies

### 3. Desktop Keyring Dump
- **`keyring_dump.sh`**: Extract passwords from GNOME Keyring and KWallet

### 4. Memory-Based Secret Hunting
- **`memory_grepper.sh`**: Search processes and memory for secrets
- **`volatility_parser.py`**: Parse memory dumps for credentials (requires Volatility)

### 5. Dotfile Credentials & Config Parsers
- **`dotfile_scanner.py`**: Scan configuration files for secrets
- **`history_parser.py`**: Parse shell history for credentials

### 6. Keylogging & Clipboard Sniffers (Optional)
- **`keylogger.py`**: Capture keystrokes (desktop environments only)
- **`clipboard_sniffer.py`**: Monitor clipboard for sensitive data

## Installation

```bash
git clone <repository-url>
cd credfinder-linux
pip install -r requirements.txt
chmod +x scripts/*.sh
```

## Quick Start

### Basic Scan
```bash
# Run all modules
python3 main.py --all

# Run specific module
python3 main.py --ssh
python3 main.py --browser
python3 main.py --keyring
```

### Advanced Options
```bash
# Generate HTML report
python3 main.py --all --report html

# Scan specific directory
python3 main.py --all --target /home/user

# OPSEC mode (minimal logging)
python3 main.py --all --opsec
```

## Requirements

- Python 3.7+
- SQLite3
- Common Linux utilities (grep, find, ps, etc.)
- Optional: Volatility Framework for memory analysis

## Configuration

Edit `config.json` to customize:
- Scan paths
- File patterns
- Output formats
- OPSEC settings

## Output Formats

- **JSON**: Structured data for automation
- **HTML**: Human-readable reports
- **CSV**: Spreadsheet-friendly format
- **Console**: Real-time output

## OPSEC Considerations

- Minimal logging in OPSEC mode
- No network calls unless explicitly configured
- Clean exit without traces
- Configurable file permissions

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request