# CredFinder Architecture Documentation

## Table of Contents
- [System Overview](#system-overview)
- [Core Architecture](#core-architecture)
- [Module System](#module-system)
- [Data Flow](#data-flow)
- [Component Details](#component-details)
- [Security Architecture](#security-architecture)
- [Performance Considerations](#performance-considerations)
- [Extension Points](#extension-points)

---

## System Overview

CredFinder is a modular credential discovery and analysis toolkit designed for Linux environments. The system employs a plugin-based architecture with a central orchestrator managing multiple specialized scanner modules.

### Key Design Principles

- **Modularity**: Independent scanner modules with standardized interfaces
- **Safety**: Comprehensive error handling and resource limits
- **Performance**: Parallel execution with configurable resource constraints
- **Security**: OPSEC-aware design with stealth operation capabilities
- **Extensibility**: Plugin architecture for easy module development

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CredFinder Main                        │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface │ Configuration │ Module Orchestrator       │
└─────────────────┬───────────────┬───────────────────────────┘
                  │               │
    ┌─────────────▼─────────────┐ │ ┌─────────────────────────┐
    │   Config Loader           │ │ │   Module Runner         │
    │   - JSON validation       │ │ │   - Parallel execution  │
    │   - Schema checking       │ │ │   - Error handling      │
    │   - Default values        │ │ │   - Resource management │
    └───────────────────────────┘ │ └─────────────┬───────────┘
                                  │               │
    ┌─────────────────────────────▼───────────────▼───────────┐
    │                Scanner Modules                         │
    ├───────────┬──────────┬──────────┬──────────┬──────────┤
    │SSH Scanner│ Browser  │ History  │ Dotfile  │File Grep │
    │           │Extractor │ Parser   │ Scanner  │          │
    └───────────┴──────────┴──────────┴──────────┴──────────┘
                                  │
    ┌─────────────────────────────▼───────────────────────────┐
    │                Report Generation                       │
    ├───────────┬──────────┬──────────┬──────────┬──────────┤
    │JSON       │HTML      │Console   │CSV       │Extended  │
    │Reporter   │Reporter  │Reporter  │Reporter  │HTML      │
    └───────────┴──────────┴──────────┴──────────┴──────────┘
```

---

## Core Architecture

### 1. Application Entry Point (`main.py`)

**Primary Responsibilities:**
- Command-line argument parsing
- Application initialization and configuration
- Module orchestration and execution
- Error handling and exit codes

**Key Components:**
```python
class CredFinder:
    - config: ConfigLoader
    - logger: Logger
    - module_runner: ModuleRunner
    - results: Dict[str, Any]
    - execution_stats: Dict[str, Any]

class ModuleRunner:
    - config: Configuration
    - logger: Logger  
    - module_classes: Dict[str, ModuleInfo]
    - results: Dict[str, Any]  # Shared state (thread-safe after fixes)
```

### 2. Configuration System (`modules/utils/config_loader.py`)

**Architecture Pattern:** Singleton-like configuration manager

**Features:**
- JSON schema validation
- Environment variable expansion
- Default value fallbacks
- Structure validation
- Dynamic reconfiguration support

```python
class ConfigLoader:
    Methods:
    - _load_config() -> Dict[str, Any]
    - _validate_config_structure() -> bool
    - get(key: str, default=None) -> Any
    - set_scan_paths(target_path: str) -> None
    - enable_opsec_mode() -> None
```

### 3. Logging System (`modules/utils/logger.py`)

**Architecture Pattern:** Factory pattern with centralized configuration

**Features:**
- Structured logging with JSON formatting
- Color-coded console output
- Configurable log levels
- Optional file logging with rotation
- OPSEC-aware minimal logging mode

```python
class Logger:
    - Console handler (colored output)
    - Optional file handler (JSON format)
    - Rotation and size limits
    - Context-aware formatting
```

---

## Module System

### Module Interface Contract

All scanner modules implement a standardized interface:

```python
class ScannerModule:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(f"credfinder.{module_name}")
        
    def scan(self) -> Dict[str, Any]:
        """Primary scanning method - returns findings"""
        pass
```

### Module Types and Responsibilities

#### 1. SSH Scanner (`modules/ssh_scanner.py`)
**Purpose:** Discover and analyze SSH keys and configurations

**Architecture:**
- File system scanning for SSH keys
- Permission analysis for security assessment
- SSH agent integration for key discovery
- Fingerprint generation for key identification

**Data Structures:**
```python
Results = {
    "private_keys": List[PrivateKeyInfo],
    "public_keys": List[PublicKeyInfo],
    "known_hosts": List[KnownHostInfo],
    "config_files": List[ConfigFileInfo],
    "authorized_keys": List[AuthorizedKeyInfo]
}
```

#### 2. Browser Extractor (`modules/browser_extractor.py`)
**Purpose:** Extract stored credentials from web browsers

**Architecture:**
- Database file copying with file locking
- Encryption key retrieval from system keyring
- Chrome/Firefox credential decryption
- Cookie and autofill data extraction

**Security Features:**
- Path validation to prevent traversal attacks
- Temporary file cleanup
- Database locking to prevent corruption
- Encryption key caching

#### 3. History Parser (`modules/history_parser.py`)
**Purpose:** Analyze shell command history for credential exposure

**Architecture:**
- Multi-encoding file reading (UTF-8, Latin-1 fallback)
- Pattern matching with context extraction
- Risk assessment based on credential types
- Large file handling with size limits

#### 4. Dotfile Scanner (`modules/dotfile_scanner.py`)
**Purpose:** Scan configuration files and environment files

**Architecture:**
- Recursive file discovery with glob patterns
- Content analysis with pattern matching
- Special handling for Git, AWS, Docker configs
- Preview generation for found credentials

#### 5. File Grepper (`modules/file_grepper.py`)
**Purpose:** Broad filesystem scanning for credential patterns

**Architecture:**
- Limited-depth recursive scanning (DoS protection)
- Process environment variable scanning via `ps` command
- Binary file detection and skipping
- Configurable file type and size filtering

#### 6. Keyring Dump (`modules/keyring_dump.py`)
**Purpose:** Extract credentials from system keyrings

**Architecture:**
- Multi-keyring support (GNOME, KWallet)
- D-Bus integration for keyring access
- External tool integration (secret-tool)
- Service-based credential organization

---

## Data Flow

### 1. Initialization Flow

```
main() 
  ├── Parse CLI arguments
  ├── Validate config file exists
  ├── Initialize CredFinder(config_path)
  │   ├── Load configuration via ConfigLoader
  │   ├── Setup logger with OPSEC settings
  │   └── Initialize ModuleRunner
  ├── Determine modules to run
  └── Configure execution mode (parallel/sequential)
```

### 2. Execution Flow

```
run_scan(modules, parallel, max_workers)
  ├── Execute modules (parallel or sequential)
  │   ├── For each module:
  │   │   ├── Initialize module with config
  │   │   ├── Execute module.scan() method
  │   │   ├── Collect results and statistics
  │   │   └── Handle errors gracefully
  │   └── Return ModuleResult objects
  ├── Aggregate results and statistics
  ├── Process successful/failed module counts
  └── Return consolidated results dictionary
```

### 3. Reporting Flow

```
generate_report(format_type)
  ├── Initialize ReportOrchestrator
  ├── Select appropriate reporter (JSON/HTML/CSV/Console)
  ├── Pass results and execution_stats to reporter
  ├── Reporter processes data:
  │   ├── Build structured report data
  │   ├── Apply formatting and styling
  │   ├── Generate metadata and summaries
  │   └── Write output file
  └── Return report file path
```

### 4. Data Transformation Pipeline

```
Raw Module Data → ModuleResult → Aggregated Results → Report Data → Formatted Output

1. Module Output:     Dict[str, Any] (module-specific structure)
2. ModuleResult:      Standardized wrapper with metadata
3. Aggregated:        Dict[module_name, module_data]
4. Report Structure:  Normalized format with metadata
5. Final Output:      JSON/HTML/CSV/Console formatted
```

---

## Component Details

### 1. Module Execution Engine

**Thread Safety:** Fixed race condition in parallel execution
- Removed shared state modification in `run_module_safe()`
- Results passed via return values only
- Thread-safe aggregation in main thread

**Error Handling:**
- Three-tier exception handling (module init, execution, critical)
- Graceful degradation for failed modules
- Comprehensive error reporting and statistics

**Resource Management:**
- Configurable timeouts per module
- File size limits to prevent memory exhaustion
- Process limits for external command execution

### 2. Pattern Matching System

**Architecture:** Centralized pattern library with module-specific application

**Pattern Categories:**
- **Static Patterns**: Fixed string matches (API key prefixes)
- **Regex Patterns**: Dynamic credential detection
- **Context-Aware**: Patterns with surrounding context requirements
- **Risk-Categorized**: Patterns classified by severity

**Performance Optimizations:**
- Compiled regex patterns (cached)
- Early filtering by file type and size
- Context extraction with length limits
- Binary file detection and skipping

### 3. Report Generation System

**Architecture Pattern:** Strategy pattern with pluggable reporters

**Reporter Interface:**
```python
class Reporter:
    def __init__(self, config: Dict[str, Any])
    def generate(self, results: Dict[str, Any], 
                execution_stats: Dict[str, Any],
                custom_filename: str = None) -> str
```

**Report Orchestrator:**
- Factory pattern for reporter instantiation
- Consistent data structure normalization
- Metadata injection (system info, timestamps)
- Error handling and fallback reporting

### 4. Security Architecture

**Input Validation:**
- Path traversal prevention
- File size and type validation
- Command injection prevention
- Configuration schema validation

**Resource Protection:**
- Memory usage limits
- File descriptor management
- Process timeout enforcement
- Temporary file cleanup

**OPSEC Features:**
- Minimal logging mode
- Network call prevention
- Temporary file secure deletion
- Process hiding capabilities

---

## Security Architecture

### 1. Threat Model

**Threats Addressed:**
- Path traversal attacks
- Resource exhaustion (DoS)
- Information disclosure
- Command injection
- Race conditions in parallel execution

**Mitigation Strategies:**
- Input sanitization and validation
- Resource limits and timeouts
- Secure temporary file handling
- Thread-safe data structures
- Comprehensive error handling

### 2. OPSEC Considerations

**Stealth Operation Features:**
- Minimal logging to reduce forensic traces
- No network communications
- Secure cleanup of temporary files
- Optional process hiding
- Configurable file permissions

**Detection Avoidance:**
- Read-only operations where possible
- Minimal system resource usage
- Avoiding common security tool patterns
- Graceful error handling without crashes

### 3. Data Protection

**Sensitive Data Handling:**
- In-memory processing only (no credential caching)
- Secure temporary file creation and cleanup
- Limited data retention in logs
- Encrypted credential storage detection

**Output Security:**
- Configurable output permissions
- Optional result compression
- Metadata filtering capabilities
- Sanitized error messages

---

## Performance Considerations

### 1. Scalability Design

**Parallel Execution:**
- Thread pool executor with configurable workers
- Module independence for parallel safety
- Resource sharing minimization
- Lock-free data aggregation

**Memory Management:**
- Streaming file processing
- Size-limited data structures
- Garbage collection friendly design
- Memory-mapped file access for large files

### 2. Optimization Strategies

**File I/O Optimization:**
- Binary file detection and early skipping
- Chunked reading for large files
- Efficient glob pattern matching
- Database file copying with locking

**CPU Optimization:**
- Compiled regex pattern caching
- Early pattern filtering
- Lazy evaluation where possible
- Minimal string operations

### 3. Resource Limits

**Configurable Limits:**
- Maximum file sizes per module
- Maximum files processed per pattern
- Execution timeouts per module
- Memory usage thresholds

**Protection Mechanisms:**
- Recursive depth limiting (DoS prevention)
- File descriptor leak prevention
- Process timeout enforcement
- Emergency resource cleanup

---

## Extension Points

### 1. Adding New Scanner Modules

**Steps to Create a Module:**
1. Implement the scanner interface
2. Add module configuration to `config.json`
3. Register module in `ModuleRunner.module_classes`
4. Add module-specific settings section
5. Update documentation and tests

**Module Template:**
```python
class NewScanner:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("credfinder.newscanner")
        self.settings = config.get("module_settings", {}).get("new_scanner", {})
    
    def scan(self) -> Dict[str, Any]:
        """Implement scanning logic here"""
        return {
            "findings": [],
            "statistics": {},
            "metadata": {}
        }
```

### 2. Adding New Report Formats

**Steps to Add a Reporter:**
1. Create reporter class implementing the interface
2. Add to `ReportOrchestrator.reporters` mapping
3. Update CLI argument choices
4. Add format-specific configuration options

### 3. Custom Pattern Development

**Pattern Categories:**
- Add new pattern types to `config.json`
- Implement pattern-specific processing logic
- Add risk categorization rules
- Update documentation with examples

### 4. Integration Points

**External Tool Integration:**
- Command execution with timeout handling
- Output parsing and error detection
- Security validation of external tools
- Fallback strategies for missing tools

**API Integration Points:**
- Configuration loading hooks
- Module discovery mechanisms
- Report format registration
- Pattern library extensions

---

## Deployment Architecture

### 1. Standalone Deployment
- Single Python script execution
- Local configuration file
- Local report generation
- No external dependencies for core functionality

### 2. Security Assessment Integration
- Integration with existing security toolchains
- Scriptable execution for automation
- Standardized output formats
- Exit code conventions for scripting

### 3. Forensic Analysis Mode
- Read-only operation mode
- Minimal system interaction
- Comprehensive logging for audit trails
- Evidence preservation considerations

---

This architecture provides a robust, secure, and extensible foundation for credential discovery while maintaining high performance and security standards. 