package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBlocklist(t *testing.T) {
	// Create a temporary blocklist file
	tempDir := t.TempDir()
	blocklistPath := filepath.Join(tempDir, "test-blocklist.json")

	// Test data
	testEntries := []BlocklistEntry{
		{Name: "malicious-package", Versions: []string{"1.0.0", "1.0.1"}},
		{Name: "evil-package", Versions: []string{}}, // All versions
	}

	// Write test data to file
	data, err := json.Marshal(testEntries)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	err = os.WriteFile(blocklistPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test successful load
	blocklist, err := LoadBlocklist(blocklistPath)
	if err != nil {
		t.Fatalf("LoadBlocklist failed: %v", err)
	}

	if len(blocklist.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(blocklist.Entries))
	}

	if blocklist.Entries[0].Name != "malicious-package" {
		t.Errorf("Expected first entry name 'malicious-package', got '%s'", blocklist.Entries[0].Name)
	}

	if len(blocklist.Entries[0].Versions) != 2 {
		t.Errorf("Expected 2 versions for first entry, got %d", len(blocklist.Entries[0].Versions))
	}

	// Test non-existent file
	_, err = LoadBlocklist("/nonexistent/path.json")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	// Test invalid JSON
	invalidPath := filepath.Join(tempDir, "invalid.json")
	err = os.WriteFile(invalidPath, []byte("invalid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid JSON file: %v", err)
	}

	_, err = LoadBlocklist(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestBlocklist_Match(t *testing.T) {
	blocklist := &Blocklist{
		Entries: []BlocklistEntry{
			{Name: "malicious-package", Versions: []string{"1.0.0", "1.0.1"}},
			{Name: "evil-package", Versions: []string{}}, // All versions
			{Name: "case-test", Versions: []string{"2.0.0"}},
		},
	}

	tests := []struct {
		name           string
		pkg            PackageRef
		expectedCount  int
		expectedReason string
	}{
		{
			name:           "exact match with specific version",
			pkg:            PackageRef{Name: "malicious-package", Version: "1.0.0", Path: "/test/path"},
			expectedCount:  1,
			expectedReason: "Matched blocklist",
		},
		{
			name:          "exact match with non-listed version",
			pkg:           PackageRef{Name: "malicious-package", Version: "2.0.0", Path: "/test/path"},
			expectedCount: 0,
		},
		{
			name:           "match package with all versions blocked",
			pkg:            PackageRef{Name: "evil-package", Version: "3.0.0", Path: "/test/path"},
			expectedCount:  1,
			expectedReason: "Matched blocklist",
		},
		{
			name:           "case insensitive match",
			pkg:            PackageRef{Name: "MALICIOUS-PACKAGE", Version: "1.0.0", Path: "/test/path"},
			expectedCount:  1,
			expectedReason: "Matched blocklist",
		},
		{
			name:           "case insensitive match (mixed case)",
			pkg:            PackageRef{Name: "Case-Test", Version: "2.0.0", Path: "/test/path"},
			expectedCount:  1,
			expectedReason: "Matched blocklist",
		},
		{
			name:          "no match - different package",
			pkg:           PackageRef{Name: "safe-package", Version: "1.0.0", Path: "/test/path"},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := blocklist.Match(tt.pkg)

			if len(findings) != tt.expectedCount {
				t.Errorf("Expected %d findings, got %d", tt.expectedCount, len(findings))
			}

			if tt.expectedCount > 0 {
				finding := findings[0]
				if finding.Type != "blocklist" {
					t.Errorf("Expected finding type 'blocklist', got '%s'", finding.Type)
				}
				if finding.Reason != tt.expectedReason {
					t.Errorf("Expected reason '%s', got '%s'", tt.expectedReason, finding.Reason)
				}
				if finding.Name != tt.pkg.Name {
					t.Errorf("Expected name '%s', got '%s'", tt.pkg.Name, finding.Name)
				}
				if finding.Version != tt.pkg.Version {
					t.Errorf("Expected version '%s', got '%s'", tt.pkg.Version, finding.Version)
				}
				if finding.Path != tt.pkg.Path {
					t.Errorf("Expected path '%s', got '%s'", tt.pkg.Path, finding.Path)
				}
			}
		})
	}
}

func TestContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	tests := []struct {
		name     string
		item     string
		expected bool
	}{
		{
			name:     "item exists",
			item:     "banana",
			expected: true,
		},
		{
			name:     "item does not exist",
			item:     "grape",
			expected: false,
		},
		{
			name:     "empty slice",
			item:     "apple",
			expected: false,
		},
		{
			name:     "exact match",
			item:     "apple",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSlice := slice
			if tt.name == "empty slice" {
				testSlice = []string{}
			}

			result := contains(testSlice, tt.item)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}