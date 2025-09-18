# npm-malicious-scanner v1.0.0 Release Notes

## 🎉 First Stable Release

This is the initial stable release of **npm-malicious-scanner**, a powerful CLI tool for detecting malicious npm packages.

## 🚀 What's New

### Core Features
- **📦 NPM Package Scanner**: Comprehensive scanning of node_modules directories
- **🛡️ Blocklist Verification**: Checks packages against known malicious package database  
- **🔍 IoC Detection**: Identifies suspicious code patterns in JavaScript files
- **📊 Multiple Output Formats**: Pretty-printed and JSON output support
- **⚙️ Configurable Scanning**: Custom paths, exclusions, and pattern matching

### Security Detection Capabilities
- `eval()` usage detection
- Child process spawning (`child_process`)
- File system operations (`fs.unlinkSync`)
- Environment variable access patterns
- HTTP requests in suspicious contexts
- Cryptocurrency-related keywords
- Credential harvesting patterns
- Executable download attempts

## 📥 Downloads

### Linux Binaries

| Platform | Download | SHA256 Checksum |
|----------|----------|-----------------|
| **Linux x86_64** | [npm-malicious-v1.0.0-linux-amd64](https://github.com/jorgsouza/npm-malicious-scanner/releases/download/v1.0.0/npm-malicious-v1.0.0-linux-amd64) | `8a5070d2c5c6b94cf287aaf20df522336a7d0c15f72d1b247b2fe654e421fe1c` |
| **Linux x86** | [npm-malicious-v1.0.0-linux-386](https://github.com/jorgsouza/npm-malicious-scanner/releases/download/v1.0.0/npm-malicious-v1.0.0-linux-386) | `0606bd6447ab68f1e0231cc99d9ce687c3dc9a50b65f027121e5f6fcce27e6a8` |
| **Linux ARM64** | [npm-malicious-v1.0.0-linux-arm64](https://github.com/jorgsouza/npm-malicious-scanner/releases/download/v1.0.0/npm-malicious-v1.0.0-linux-arm64) | `bff45cafb924f424d1d786cde01c4ffe4db77fb77042869300610cfb54fd667a` |

### Installation

```bash
# Download for Linux x86_64
wget https://github.com/jorgsouza/npm-malicious-scanner/releases/download/v1.0.0/npm-malicious-v1.0.0-linux-amd64

# Make executable
chmod +x npm-malicious-v1.0.0-linux-amd64

# Move to PATH (optional)
sudo mv npm-malicious-v1.0.0-linux-amd64 /usr/local/bin/npm-malicious
```

## 🔧 Quick Start

```bash
# Basic scan of current directory
./npm-malicious

# Scan specific paths with blocklist
./npm-malicious --paths /app --blocklist example-blocklist.json

# Generate JSON report
./npm-malicious --output json --paths /project > security-report.json
```

## 📋 Example Output

```
=== SCAN RESULTS ===
Packages scanned: 247
Security findings: 2

🚨 BLOCKLISTED PACKAGES (1):
1. Package: malicious-package@1.0.0
   Path: /project/node_modules/malicious-package
   Reason: Matched blocklist

⚠️  SUSPICIOUS CODE PATTERNS (1):
1. File: /project/node_modules/suspicious/index.js
   Pattern: child_process
   Reason: Matched pattern
```

## 🔍 Exit Codes

- **0**: No security issues detected
- **1**: Security issues found (malicious packages or suspicious patterns)

## 🛠️ Build from Source

```bash
git clone https://github.com/jorgsouza/npm-malicious-scanner.git
cd npm-malicious-scanner
make build
```

## 📚 Documentation

- [README](https://github.com/jorgsouza/npm-malicious-scanner/blob/main/README.md) - Main documentation
- [Architecture](https://github.com/jorgsouza/npm-malicious-scanner/blob/main/ARCHITECTURE.md) - Technical architecture
- [MCP Analysis](https://github.com/jorgsouza/npm-malicious-scanner/blob/main/MCP_ANALYSIS.md) - Protocol analysis

## 🤝 Contributing

Issues and pull requests are welcome! Please see our [GitHub repository](https://github.com/jorgsouza/npm-malicious-scanner) for more information.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jorgsouza/npm-malicious-scanner/blob/main/LICENSE) file for details.

---

**Release Date**: September 18, 2025  
**Commit**: e37cb5e  
**Go Version**: 1.21.1  
**Platform Support**: Linux (x86_64, x86, ARM64)
