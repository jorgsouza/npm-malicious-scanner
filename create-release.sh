#!/bin/bash

# Release Creation Script for npm-malicious-scanner v1.0.0
# This script helps create the GitHub release

echo "🚀 npm-malicious-scanner v1.0.0 Release Creation Guide"
echo "=================================================="
echo ""

echo "📁 Release Files Ready:"
echo "- npm-malicious-v1.0.0-linux-amd64 (Linux x86_64)"
echo "- npm-malicious-v1.0.0-linux-386 (Linux x86)"  
echo "- npm-malicious-v1.0.0-linux-arm64 (Linux ARM64)"
echo "- npm-malicious-v1.0.0-darwin-amd64 (macOS x86_64)"
echo "- npm-malicious-v1.0.0-darwin-arm64 (macOS ARM64)"
echo "- npm-malicious-v1.0.0-windows-amd64.exe (Windows x86_64)"
echo "- npm-malicious-v1.0.0-windows-386.exe (Windows x86)"
echo "- checksums.txt (SHA256 checksums)"
echo "- RELEASE_NOTES_v1.0.0.md (Release notes)"
echo ""

echo "📋 Release Information:"
echo "Tag: v1.0.0"
echo "Title: npm-malicious-scanner v1.0.0 - Initial Release"
echo "Target: main branch"
echo ""

echo "📝 Release Description (copy this to GitHub):"
echo "=============================================="
cat << 'EOF'
## 🎉 First Stable Release

This is the initial stable release of **npm-malicious-scanner**, a powerful CLI tool for detecting malicious npm packages.

### 🚀 Key Features
- 📦 **NPM Package Scanner**: Comprehensive scanning of node_modules directories
- 🛡️ **Blocklist Verification**: Checks packages against known malicious packages
- 🔍 **IoC Detection**: Identifies suspicious code patterns in JavaScript files  
- 📊 **Multiple Output Formats**: Pretty-printed and JSON output
- ⚙️ **Configurable Scanning**: Custom paths, exclusions, and patterns

### 🔧 Quick Start
```bash
# Download and install
wget https://github.com/jorgsouza/npm-malicious-scanner/releases/download/v1.0.0/npm-malicious-v1.0.0-linux-amd64
chmod +x npm-malicious-v1.0.0-linux-amd64

# Basic scan
./npm-malicious-v1.0.0-linux-amd64

# Scan with blocklist
./npm-malicious-v1.0.0-linux-amd64 --blocklist example-blocklist.json --paths /project
```

### 📥 Downloads
- **Linux x86_64**: npm-malicious-v1.0.0-linux-amd64
- **Linux x86**: npm-malicious-v1.0.0-linux-386  
- **Linux ARM64**: npm-malicious-v1.0.0-linux-arm64
- **macOS x86_64**: npm-malicious-v1.0.0-darwin-amd64
- **macOS ARM64**: npm-malicious-v1.0.0-darwin-arm64
- **Windows x86_64**: npm-malicious-v1.0.0-windows-amd64.exe
- **Windows x86**: npm-malicious-v1.0.0-windows-386.exe

**SHA256 Checksums**: See checksums.txt

### 🔍 Security Detection
- eval() usage, child process spawning, file operations
- Environment variables, HTTP requests, crypto keywords
- Credential harvesting, executable downloads

**Exit Codes**: 0 (clean), 1 (issues found)

Full documentation: [README](https://github.com/jorgsouza/npm-malicious-scanner/blob/main/README.md)
EOF

echo ""
echo "=============================================="
echo ""

echo "📤 Files to Upload:"
echo "1. bin/npm-malicious-v1.0.0-linux-amd64"
echo "2. bin/npm-malicious-v1.0.0-linux-386"
echo "3. bin/npm-malicious-v1.0.0-linux-arm64"
echo "4. bin/npm-malicious-v1.0.0-darwin-amd64"
echo "5. bin/npm-malicious-v1.0.0-darwin-arm64"
echo "6. bin/npm-malicious-v1.0.0-windows-amd64.exe"
echo "7. bin/npm-malicious-v1.0.0-windows-386.exe"
echo "8. bin/checksums.txt"
echo ""

echo "🌐 GitHub Release URL:"
echo "https://github.com/jorgsouza/npm-malicious-scanner/releases/new?tag=v1.0.0"
echo ""

echo "✅ Tag v1.0.0 has been pushed to GitHub"
echo "✅ Release files are ready in bin/ directory"
echo "✅ Release notes are prepared"
echo ""

echo "📋 Next Steps:"
echo "1. Go to: https://github.com/jorgsouza/npm-malicious-scanner/releases/new"
echo "2. Select tag: v1.0.0"
echo "3. Copy the release description above"
echo "4. Upload the 8 files from bin/ directory"
echo "5. Mark as 'Latest release'"
echo "6. Click 'Publish release'"

# Build for macOS amd64
echo "Building for macOS amd64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/npm-malicious-v1.0.0-darwin-amd64 ./cmd/npm-malicious

# Build for macOS arm64
echo "Building for macOS arm64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/npm-malicious-v1.0.0-darwin-arm64 ./cmd/npm-malicious

# Build for Windows amd64
echo "Building for Windows amd64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/npm-malicious-v1.0.0-windows-amd64.exe ./cmd/npm-malicious

# Build for Windows 386
echo "Building for Windows 386..."
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -trimpath -ldflags="-s -w" -o bin/npm-malicious-v1.0.0-windows-386.exe ./cmd/npm-malicious

# Generate checksums for all release binaries
echo "Generating checksums for all release binaries..."
sha256sum bin/npm-malicious-v1.0.0-* > bin/checksums.txt
