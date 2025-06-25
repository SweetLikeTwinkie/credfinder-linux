# CredFinder Configuration Wiki

## Table of Contents
- [Overview](#overview)
- [Configuration Sections](#configuration-sections)
- [Scan Paths](#scan-paths)
- [Patterns](#patterns)
- [Module Settings](#module-settings)
- [OPSEC Settings](#opsec-settings)
- [Output Settings](#output-settings)
- [Module Configuration](#module-configuration)
- [Logging Configuration](#logging-configuration)
- [Security Considerations](#security-considerations)
- [Performance Tuning](#performance-tuning)
- [Examples](#examples)

---

## Overview

CredFinder uses a JSON configuration file (`config.json`) to control all aspects of credential scanning behavior. The configuration is organized into logical sections that control different aspects of the application:

- **Scan Paths**: Where to look for credentials
- **Patterns**: What credential patterns to detect
- **Module Settings**: Detailed settings for each scanner module
- **OPSEC**: Operational security and stealth settings
- **Output**: Report generation and formatting
- **Modules**: Enable/disable and prioritize scanner modules
- **Logging**: Control application logging behavior

### Configuration File Location

By default, CredFinder looks for `config.json` in the current directory. You can specify a different location using:

```bash
python3 main.py --config /path/to/custom-config.json
```

---

## Configuration Sections

### Scan Paths

The `scan_paths` section defines where each module should look for credentials. Paths support:
- **Home directory expansion**: `~/` expands to user home directory
- **Wildcards**: `*` for pattern matching
- **Glob patterns**: For flexible path matching

```json
{
  "scan_paths": {
    "ssh": [
      "~/.ssh/",
      "/etc/ssh/",
      "/home/*/.ssh/",
      "/root/.ssh/"
    ],
    "browsers": {
      "chrome": [
        "~/.config/google-chrome/Default/",
        "~/.config/chromium/Default/",
        "~/.config/brave-browser/Default/"
      ],
      "firefox": [
        "~/.mozilla/firefox/*.default*/",
        "~/.mozilla/firefox/*.default-release/"
      ]
    },
    "config_files": [
      "~/.bash_history",
      "~/.git-credentials",
      "~/.aws/credentials",
      "~/.docker/config.json"
    ],
    "common_files": [
      "/tmp/*.env*",
      "~/Downloads/*.config*",
      "~/Desktop/*.env*"
    ],
    "history_files": [
      "~/.bash_history",
      "~/.zsh_history",
      "~/.sh_history"
    ],
    "env_file_patterns": [
      "~/.env*",
      "~/.config/*/.env*",
      "~/projects/*/.env*"
    ],
    "git_config_paths": [
      "~/.git-credentials",
      "~/.gitconfig"
    ]
  }
}
```

#### Scan Paths Reference

| Section | Purpose | Used By |
|---------|---------|---------|
| `ssh` | SSH key and configuration locations | SSH Scanner |
| `browsers.chrome` | Chrome/Chromium browser profiles | Browser Extractor |
| `browsers.firefox` | Firefox browser profiles | Browser Extractor |
| `config_files` | Common configuration files | Dotfile Scanner |
| `common_files` | Temporary and common credential locations | File Grepper |
| `history_files` | Shell command history files | History Parser |
| `env_file_patterns` | Environment variable files | Dotfile Scanner |
| `git_config_paths` | Git credential storage | Dotfile Scanner |

---

## Patterns

The `patterns` section defines regex patterns for detecting different types of credentials. Each pattern type maps to an array of regular expressions.

```json
{
  "patterns": {
    "aws_keys": [
      "AKIA[0-9A-Z]{16}",
      "aws_access_key_id\\s*[=:]\\s*[A-Z0-9]{20}",
      "aws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}"
    ],
    "api_tokens": [
      "sk_[a-zA-Z0-9]{24,}",
      "ghp_[a-zA-Z0-9]{36}",
      "xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"
    ],
    "jwt_tokens": [
      "eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*"
    ],
    "passwords": [
      "password\\s*[=:]\\s*[^\\s\"']+",
      "secret\\s*[=:]\\s*[^\\s\"']+",
      "key\\s*[=:]\\s*[^\\s\"']+"
    ],
    "database_urls": [
      "mysql://[^\\s\"']+",
      "postgresql://[^\\s\"']+",
      "mongodb://[^\\s\"']+"
    ],
    "private_keys": [
      "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    ],
    "credentials": [
      "GITHUB_TOKEN[=:\\s]+[a-zA-Z0-9_]+",
      "DATABASE_URL[=:\\s]+[^\\s\"']+"
    ]
  }
}
```

#### Pattern Types Reference

| Pattern Type | Description | Example Matches |
|--------------|-------------|-----------------|
| `aws_keys` | AWS access keys and secrets | `AKIAIOSFODNN7EXAMPLE` |
| `api_tokens` | API tokens (Stripe, GitHub, Slack) | `sk_test_abc123`, `ghp_xyz789` |
| `jwt_tokens` | JSON Web Tokens | `eyJhbGciOiJIUzI1NiJ9...` |
| `passwords` | Password assignments | `password=secret123` |
| `database_urls` | Database connection strings | `mysql://user:pass@host/db` |
| `private_keys` | SSH/PGP private keys | `-----BEGIN RSA PRIVATE KEY-----` |
| `credentials` | Environment variable credentials | `GITHUB_TOKEN=abc123` |

---

## Module Settings

The `module_settings` section provides detailed configuration for each scanner module.

### SSH Module Settings

```json
{
  "module_settings": {
    "ssh": {
      "key_patterns": [
        "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*"
      ],
      "secure_permissions": [384, 256],
      "key_data_truncate_length": 50,
      "ssh_agent_timeout": 5,
      "fingerprint_timeout": 5
    }
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `key_patterns` | Array | `["id_rsa*", ...]` | File patterns for SSH private keys |
| `secure_permissions` | Array | `[384, 256]` | Octal file permissions considered secure |
| `key_data_truncate_length` | Integer | `50` | Max characters to show from key data |
| `ssh_agent_timeout` | Integer | `5` | Timeout for SSH agent queries (seconds) |
| `fingerprint_timeout` | Integer | `5` | Timeout for key fingerprint generation |

### Browser Module Settings

```json
{
  "browser": {
    "chrome_default_password": "peanuts",
    "chrome_salt": "saltysalt",
    "chrome_key_length": 16,
    "chrome_iterations": 1,
    "secret_tool_timeout": 5,
    "database_files": {
      "chrome_passwords": "Login Data",
      "chrome_cookies": "Cookies",
      "firefox_key_db": "key4.db",
      "firefox_logins": "logins.json"
    },
    "max_copy_retries": 3
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `chrome_default_password` | String | `"peanuts"` | Default Chrome encryption password |
| `chrome_salt` | String | `"saltysalt"` | Salt for Chrome key derivation |
| `secret_tool_timeout` | Integer | `5` | Timeout for secret-tool commands |
| `database_files` | Object | `{...}` | Names of browser database files |
| `max_copy_retries` | Integer | `3` | Max retries for database file copying |

### File Grepper Settings

```json
{
  "file_grep": {
    "file_extensions": [
      "*.env", "*.ini", "*.conf", "*.config",
      "*.json", "*.yaml", "*.yml", "*.properties"
    ],
    "search_base_paths": [
      "~/.config/", "~/.local/", "/tmp/", "/var/tmp/"
    ],
    "max_files_per_pattern": 10,
    "max_file_size_bytes": 1048576,
    "max_file_read_bytes": 10000,
    "process_scan_timeout": 10,
    "context_size": 40,
    "min_match_length": 5
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `file_extensions` | Array | `["*.env", ...]` | File extensions to scan |
| `search_base_paths` | Array | `["~/.config/", ...]` | Base directories to search |
| `max_files_per_pattern` | Integer | `10` | Max files to scan per pattern |
| `max_file_size_bytes` | Integer | `1048576` | Max file size to scan (1MB) |
| `max_file_read_bytes` | Integer | `10000` | Max bytes to read per file (10KB) |
| `process_scan_timeout` | Integer | `10` | Timeout for process scanning |
| `context_size` | Integer | `40` | Characters of context around matches |
| `min_match_length` | Integer | `5` | Minimum match length to report |

### Other Module Settings

**Dotfile Scanner:**
```json
{
  "dotfile": {
    "max_file_size_bytes": 1048576,
    "content_preview_length": 100,
    "context_size": 25
  }
}
```

**History Parser:**
```json
{
  "history": {
    "max_file_size_bytes": 5242880,
    "context_size": 20,
    "risk_patterns": {
      "critical": ["aws_keys", "api_tokens", "jwt_tokens"],
      "medium": ["passwords"],
      "low": []
    }
  }
}
```

**Keyring Dump:**
```json
{
  "keyring": {
    "version_check_timeout": 5,
    "keyring_access_timeout": 30,
    "wallet_access_timeout": 15,
    "common_services": [
      "chrome", "ssh", "git", "aws", "docker"
    ]
  }
}
```

---

## OPSEC Settings

Operational Security (OPSEC) settings control stealth and security aspects:

```json
{
  "opsec": {
    "minimal_logging": false,
    "no_network_calls": true,
    "clean_exit": true,
    "file_permissions": "600",
    "log_to_file": false,
    "delete_temp_files": true
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `minimal_logging` | Boolean | `false` | Reduce logging output for stealth |
| `no_network_calls` | Boolean | `true` | Prevent any network communication |
| `clean_exit` | Boolean | `true` | Clean up resources on exit |
| `file_permissions` | String | `"600"` | Permissions for created files |
| `log_to_file` | Boolean | `false` | Whether to log to files |
| `delete_temp_files` | Boolean | `true` | Clean up temporary files |

---

## Output Settings

Control report generation and formatting:

```json
{
  "output": {
    "formats": ["json", "html", "console"],
    "default_format": "json",
    "output_dir": "./reports",
    "compress_results": false,
    "include_metadata": true,
    "include_raw_data": false,
    "json_indent": 0,
    "timestamp_format": "%Y%m%d_%H%M%S"
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `formats` | Array | `["json", "html", "console"]` | Available report formats |
| `default_format` | String | `"json"` | Default report format |
| `output_dir` | String | `"./reports"` | Directory for report files |
| `compress_results` | Boolean | `false` | Compress output files |
| `include_metadata` | Boolean | `true` | Include system metadata in reports |
| `include_raw_data` | Boolean | `false` | Include raw scan data |
| `json_indent` | Integer | `0` | JSON indentation (0 = compact) |
| `timestamp_format` | String | `"%Y%m%d_%H%M%S"` | Timestamp format for filenames |

---

## Module Configuration

Enable/disable modules and set execution priorities:

```json
{
  "modules": {
    "ssh": {
      "enabled": true,
      "priority": 1,
      "timeout": 30,
      "parallel_safe": true,
      "requires_privileges": false,
      "estimated_time": "fast",
      "resource_intensive": false
    },
    "file_grep": {
      "enabled": true,
      "priority": 6,
      "timeout": 90,
      "parallel_safe": true,
      "estimated_time": "medium"
    }
  }
}
```

| Setting | Type | Description |
|---------|------|-------------|
| `enabled` | Boolean | Whether module is enabled |
| `priority` | Integer | Execution priority (1 = highest) |
| `timeout` | Integer | Module timeout in seconds |
| `parallel_safe` | Boolean | Safe to run in parallel |
| `requires_privileges` | Boolean | Needs elevated privileges |
| `estimated_time` | String | Time estimate: "fast", "medium", "slow" |
| `resource_intensive` | Boolean | Uses significant system resources |

---

## Logging Configuration

Control application logging behavior:

```json
{
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "console_logging": true,
    "use_colors": true
  }
}
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `level` | String | `"INFO"` | Log level: DEBUG, INFO, WARNING, ERROR |
| `format` | String | `"%(asctime)s..."` | Python logging format string |
| `console_logging` | Boolean | `true` | Enable console output |
| `use_colors` | Boolean | `true` | Use colored console output |

---

## Security Considerations

### File Permissions
- Keep `config.json` readable only by owner: `chmod 600 config.json`
- Set secure output directory permissions
- Use OPSEC settings for stealth operations

### Pattern Security
- Avoid overly broad regex patterns that cause false positives
- Test patterns against known credential formats
- Balance detection accuracy with performance

### Path Safety
- Avoid scanning system-critical directories (`/dev/`, `/proc/`, `/sys/`)
- Be cautious with recursive patterns and symlinks
- Limit scan depth to prevent infinite loops

---

## Performance Tuning

### For Fast Scans
```json
{
  "modules": {
    "ssh": {"enabled": true, "priority": 1},
    "dotfiles": {"enabled": true, "priority": 2},
    "history": {"enabled": true, "priority": 3},
    "browser": {"enabled": false},
    "keyring": {"enabled": false},
    "file_grep": {"enabled": false}
  }
}
```

### For Comprehensive Scans
```json
{
  "module_settings": {
    "file_grep": {
      "max_files_per_pattern": 50,
      "max_file_size_bytes": 5242880,
      "search_base_paths": [
        "~/", "~/.config/", "~/.local/", "/tmp/", "/var/tmp/",
        "/opt/", "/srv/", "/var/log/"
      ]
    }
  }
}
```

### Memory Optimization
- Reduce `max_file_size_bytes` and `max_file_read_bytes`
- Limit `max_files_per_pattern`
- Use `json_indent: 0` for compact output
- Set `include_raw_data: false`

---

## Examples

### Minimal Configuration
```json
{
  "scan_paths": {
    "ssh": ["~/.ssh/"],
    "history_files": ["~/.bash_history"]
  },
  "patterns": {
    "aws_keys": ["AKIA[0-9A-Z]{16}"],
    "passwords": ["password\\s*[=:]\\s*[^\\s\"']+"]
  },
  "modules": {
    "ssh": {"enabled": true},
    "history": {"enabled": true}
  },
  "output": {
    "default_format": "console"
  }
}
```

### High-Security OPSEC Configuration
```json
{
  "opsec": {
    "minimal_logging": true,
    "no_network_calls": true,
    "clean_exit": true,
    "log_to_file": false,
    "delete_temp_files": true
  },
  "output": {
    "include_metadata": false,
    "include_raw_data": false,
    "json_indent": 0
  },
  "logging": {
    "level": "ERROR",
    "use_colors": false
  }
}
```

### Custom Pattern Configuration
```json
{
  "patterns": {
    "custom_api_keys": [
      "myapp_[a-zA-Z0-9]{32}",
      "CUSTOM_SECRET[=:\\s]+[a-zA-Z0-9_-]+"
    ],
    "database_passwords": [
      "DB_PASS[=:\\s]*[^\\s\"']+",
      "mysql.*password[=:\\s]*[^\\s\"']+"
    ]
  }
}
```

---

## Configuration Validation

CredFinder validates the configuration file on startup and will:
- **Warn** about missing optional sections
- **Error** if required sections are missing
- **Skip** invalid patterns with warnings
- **Use defaults** for missing individual settings

To test your configuration:
```bash
python3 main.py --modules ssh --report console --debug
```

This will show detailed configuration loading and validation messages. 