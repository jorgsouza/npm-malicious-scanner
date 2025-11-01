package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewIoCScanner(t *testing.T) {
	tests := []struct {
		name        string
		patterns    []string
		maxDepth    int
		expectError bool
	}{
		{
			name:        "valid patterns",
			patterns:    []string{"test", "malicious.*code", "\\d+"},
			maxDepth:    5,
			expectError: false,
		},
		{
			name:        "empty patterns",
			patterns:    []string{},
			maxDepth:    3,
			expectError: false,
		},
		{
			name:        "invalid regex pattern",
			patterns:    []string{"[invalid"},
			maxDepth:    5,
			expectError: true,
		},
		{
			name:        "mixed valid and invalid patterns",
			patterns:    []string{"valid", "[invalid"},
			maxDepth:    5,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewIoCScanner(tt.patterns, tt.maxDepth)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if scanner == nil {
				t.Error("Expected scanner but got nil")
				return
			}

			if len(scanner.Patterns) != len(tt.patterns) {
				t.Errorf("Expected %d patterns, got %d", len(tt.patterns), len(scanner.Patterns))
			}

			if scanner.MaxDepth != tt.maxDepth {
				t.Errorf("Expected max depth %d, got %d", tt.maxDepth, scanner.MaxDepth)
			}
		})
	}
}

func TestIoCScanner_Scan(t *testing.T) {
	// Create temporary directory structure for testing
	tempDir := t.TempDir()

	// Create test files
	testFiles := map[string]string{
		"package.json":        `{"name": "test", "scripts": {"postinstall": "malicious_code"}}`,
		"index.js":            `console.log("malicious_code detected");`,
		"postinstall.js":      `eval("some_code");`,
		"bundle.js":           `function clean() { return true; }`,
		"other.txt":           `malicious_code here`, // Should be ignored
		"subdir/package.json": `{"name": "sub", "version": "malicious_code"}`,
	}

	for filePath, content := range testFiles {
		fullPath := filepath.Join(tempDir, filePath)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", fullPath, err)
		}
	}

	tests := []struct {
		name             string
		patterns         []string
		maxDepth         int
		expectedCount    int
		expectedFiles    []string
		expectedEvidence []string
	}{
		{
			name:             "scan for malicious_code",
			patterns:         []string{"malicious_code"},
			maxDepth:         10,
			expectedCount:    3,          // package.json, index.js, subdir/package.json
			expectedFiles:    []string{}, // Don't check order since filepath.Walk order is not guaranteed
			expectedEvidence: []string{},
		},
		{
			name:             "scan for eval pattern",
			patterns:         []string{"eval\\("},
			maxDepth:         10,
			expectedCount:    1, // postinstall.js
			expectedFiles:    []string{},
			expectedEvidence: []string{},
		},
		{
			name:          "no matches",
			patterns:      []string{"nonexistent_pattern"},
			maxDepth:      10,
			expectedCount: 0,
		},
		{
			name:          "multiple patterns",
			patterns:      []string{"malicious_code", "eval\\("},
			maxDepth:      10,
			expectedCount: 4, // 3 malicious_code + 1 eval
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewIoCScanner(tt.patterns, tt.maxDepth)
			if err != nil {
				t.Fatalf("Failed to create scanner: %v", err)
			}

			findings, err := scanner.Scan(tempDir)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(findings) != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, len(findings))
				for i, f := range findings {
					t.Logf("Finding %d: File=%s, Evidence=%s", i, f.File, f.Evidence)
				}
			}

			// Check findings details for specific tests
			if len(tt.expectedFiles) > 0 && len(findings) >= len(tt.expectedFiles) {
				for i, expectedFile := range tt.expectedFiles {
					if i < len(findings) {
						actualFile := filepath.Base(findings[i].File)
						if actualFile != expectedFile {
							t.Errorf("Expected file %s at index %d, got %s", expectedFile, i, actualFile)
						}

						if findings[i].Type != "ioc" {
							t.Errorf("Expected finding type 'ioc', got '%s'", findings[i].Type)
						}

						if findings[i].Reason != "Matched pattern" {
							t.Errorf("Expected reason 'Matched pattern', got '%s'", findings[i].Reason)
						}
					}
				}
			}

			if len(tt.expectedEvidence) > 0 && len(findings) >= len(tt.expectedEvidence) {
				for i, expectedEvidence := range tt.expectedEvidence {
					if i < len(findings) {
						if findings[i].Evidence != expectedEvidence {
							t.Errorf("Expected evidence '%s' at index %d, got '%s'", expectedEvidence, i, findings[i].Evidence)
						}
					}
				}
			}
		})
	}
}

func TestDepth(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected int
	}{
		{
			name:     "root path",
			path:     "/",
			expected: 1,
		},
		{
			name:     "single level",
			path:     "/home",
			expected: 1,
		},
		{
			name:     "multiple levels",
			path:     "/home/user/documents",
			expected: 3,
		},
		{
			name:     "relative path",
			path:     "user/documents",
			expected: 1,
		},
		{
			name:     "path with trailing slash",
			path:     "/home/user/",
			expected: 2,
		},
		{
			name:     "empty path",
			path:     "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := depth(tt.path)
			if result != tt.expected {
				t.Errorf("Expected depth %d for path '%s', got %d", tt.expected, tt.path, result)
			}
		})
	}
}

func TestIsTargetFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{
			name:     "package.json",
			filename: "package.json",
			expected: true,
		},
		{
			name:     "index.js",
			filename: "index.js",
			expected: true,
		},
		{
			name:     "postinstall.js",
			filename: "postinstall.js",
			expected: true,
		},
		{
			name:     "bundle.js",
			filename: "bundle.js",
			expected: true,
		},
		{
			name:     "other.js",
			filename: "other.js",
			expected: false,
		},
		{
			name:     "readme.md",
			filename: "readme.md",
			expected: false,
		},
		{
			name:     "package.json.backup",
			filename: "package.json.backup",
			expected: false,
		},
		{
			name:     "empty filename",
			filename: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTargetFile(tt.filename)
			if result != tt.expected {
				t.Errorf("Expected %v for filename '%s', got %v", tt.expected, tt.filename, result)
			}
		})
	}
}
