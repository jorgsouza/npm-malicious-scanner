# Release Notes

## v1.0.0 - Initial Release

### Features
- ✅ **NPM Package Scanner**: Scans node_modules directories for malicious packages
- 🛡️ **Blocklist Verification**: Checks packages against known malicious package database
- 🔍 **IoC Detection**: Identifies suspicious code patterns in JavaScript files
- 📊 **Multiple Output Formats**: Pretty-printed and JSON output support
- ⚙️ **Configurable Scanning**: Custom paths, exclusions, and pattern matching
- 🚀 **High Performance**: Fast Go implementation with static binary

### Components
- **Discovery Engine**: Finds npm packages and node_modules directories
- **Security Scanner**: Detects malicious patterns and indicators of compromise
- **Blocklist Matcher**: Compares packages against known threats
- **Report Generator**: Creates detailed security reports

### Supported Platforms
- Linux x86_64
- Static binary with no dependencies

### Usage
```bash
# Basic scan
./npm-malicious

# Scan with blocklist
./npm-malicious --blocklist example-blocklist.json --paths /project

# JSON output
./npm-malicious --output json --paths /app > findings.json
```

### Security Patterns Detected
- `eval()` usage
- Child process spawning
- File system operations
- Environment variable access
- HTTP requests in suspicious contexts
- Cryptocurrency-related keywords
- Credential harvesting patterns
- Executable downloads

### Exit Codes
- `0`: No security issues found
- `1`: Security issues detected

---

**Release Date**: September 18, 2025  
**Commit**: e3233f5  
**Go Version**: 1.21.1
