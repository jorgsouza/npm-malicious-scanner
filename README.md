# npm-malicious-scanner

[![Go Version](https://img.shields.io/badge/Go-1.21.1-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/jorgsouza/npm-malicious-scanner)](https://github.com/jorgsouza/npm-malicious-scanner/releases)

## Overview

`npm-malicious-scanner` is a CLI tool written in Go to scan your Linux machine for potentially malicious npm packages. It identifies matches from a blocklist and detects Indicators of Compromise (IoCs) heuristically. The tool can export results in Pretty, JSON, and SARIF formats.

## 🚀 Features

- ✅ Scans global and local npm directories
- 🛡️ Detects malicious packages using a blocklist
- 🔍 Identifies IoCs in target files
- 📊 Generates reports in Pretty, JSON formats
- ⚙️ Configurable paths, exclusions, and patterns
- 🚀 Fast and efficient Go implementation
- 📦 Static binary with no dependencies
- Identifies IoCs in target files.
- Generates reports in Pretty, JSON, and SARIF formats.
- Configurable paths, exclusions, and concurrency.

## Installation

### Build from Source

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd npm-malicious-scanner
   ```

2. Build the static binary:

   ```bash
   make build
   ```

## Usage

### Basic Scan

```bash
# Scan current directory
./bin/npm-malicious

# Scan specific paths
./bin/npm-malicious --paths /opt/apps /home/user/projects

# Scan with exclusions
./bin/npm-malicious --paths /opt/apps --exclude '(/node_modules/.cache|/\.git/)'
```

### Security Scanning with Blocklist

```bash
# Scan with blocklist for known malicious packages
./bin/npm-malicious --paths /opt/apps --blocklist example-blocklist.json

# The tool will detect:
# - Packages that match the blocklist (known malicious packages)
# - Suspicious code patterns (IoCs) in JavaScript files
```

### Export Reports

```bash
# Export JSON Report
./bin/npm-malicious --output json --paths /opt/apps --blocklist example-blocklist.json

# Pretty output (default)
./bin/npm-malicious --output pretty --paths /opt/apps --blocklist example-blocklist.json
```

## Configuration

### Blocklist File

Create a JSON file with known malicious packages:

```json
[
  {
    "name": "event-stream",
    "versions": ["3.3.6"]
  },
  {
    "name": "flatmap-stream",
    "versions": []
  }
]
```

- `name`: Package name to block
- `versions`: Specific versions to block (empty array blocks all versions)

The tool includes an `example-blocklist.json` with known malicious packages.

### IoC Patterns

The tool automatically scans for suspicious code patterns:

- `eval()` usage
- Child process spawning (`child_process`)
- File system operations (`fs.unlinkSync`)
- Environment variable access
- HTTP requests in suspicious contexts
- Cryptocurrency-related keywords
- Credential harvesting patterns
- Executable downloads

### Flags

- `--paths`: List of paths to scan (default: current directory)
- `--exclude`: Regex patterns to exclude from scanning
- `--output`: Output format (`pretty`, `json`)
- `--blocklist`: Path to JSON blocklist file containing known malicious packages
- `--help`: Show help information

### Exit Codes

- `0`: No security issues found
- `1`: Security issues detected (malicious packages or suspicious code patterns)

## Limitations

- Designed for Linux/Ubuntu.
- Does not execute scripts; only reads files.

## Contributing

Feel free to open issues or submit pull requests for improvements.
