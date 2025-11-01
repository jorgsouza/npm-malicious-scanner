package scanner

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewReportWriter(t *testing.T) {
	writer := NewReportWriter()
	if writer == nil {
		t.Error("NewReportWriter returned nil")
	}
}

func TestReportWriter_WritePretty(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	writer := NewReportWriter()

	tests := []struct {
		name     string
		findings []Finding
		expected []string // Expected strings in output
	}{
		{
			name:     "empty findings",
			findings: []Finding{},
			expected: []string{}, // No output expected
		},
		{
			name: "blocklist findings only",
			findings: []Finding{
				{
					Type:    "blocklist",
					Name:    "malicious-package",
					Version: "1.0.0",
					Path:    "/test/package.json",
					Reason:  "Matched blocklist",
				},
				{
					Type:    "blocklist",
					Name:    "evil-package",
					Version: "2.0.0",
					Path:    "/test/evil/package.json",
					Reason:  "Matched blocklist",
				},
			},
			expected: []string{
				"SECURITY FINDINGS:",
				"BLOCKLISTED PACKAGES (2):",
				"malicious-package@1.0.0",
				"evil-package@2.0.0",
				"/test/package.json",
				"/test/evil/package.json",
				"Matched blocklist",
			},
		},
		{
			name: "ioc findings only",
			findings: []Finding{
				{
					Type:     "ioc",
					File:     "/test/index.js",
					Evidence: "eval(",
					Reason:   "Matched pattern",
				},
			},
			expected: []string{
				"SECURITY FINDINGS:",
				"SUSPICIOUS CODE PATTERNS (1):",
				"/test/index.js",
				"eval(",
				"Matched pattern",
			},
		},
		{
			name: "mixed findings",
			findings: []Finding{
				{
					Type:    "blocklist",
					Name:    "bad-package",
					Version: "1.0.0",
					Path:    "/test/package.json",
					Reason:  "Matched blocklist",
				},
				{
					Type:     "ioc",
					File:     "/test/script.js",
					Evidence: "malicious_code",
					Reason:   "Matched pattern",
				},
			},
			expected: []string{
				"SECURITY FINDINGS:",
				"BLOCKLISTED PACKAGES (1):",
				"SUSPICIOUS CODE PATTERNS (1):",
				"bad-package@1.0.0",
				"malicious_code",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write findings
			writer.WritePretty(tt.findings)

			// Close writer and read output
			w.Close()
			output, _ := io.ReadAll(r)
			os.Stdout = oldStdout

			// Reset pipe for next test
			r, w, _ = os.Pipe()
			os.Stdout = w

			outputStr := string(output)

			if len(tt.expected) == 0 {
				if len(outputStr) > 0 {
					t.Errorf("Expected no output for empty findings, got: %s", outputStr)
				}
				return
			}

			// Check that all expected strings are present
			for _, expected := range tt.expected {
				if !strings.Contains(outputStr, expected) {
					t.Errorf("Expected output to contain '%s', but it didn't. Full output:\n%s", expected, outputStr)
				}
			}
		})
	}

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout
}

func TestReportWriter_WriteJSON(t *testing.T) {
	writer := NewReportWriter()
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		findings []Finding
		filename string
		wantErr  bool
	}{
		{
			name: "successful JSON write",
			findings: []Finding{
				{
					Type:    "blocklist",
					Name:    "test-package",
					Version: "1.0.0",
					Path:    "/test/package.json",
					Reason:  "Matched blocklist",
				},
				{
					Type:     "ioc",
					File:     "/test/script.js",
					Evidence: "eval(",
					Reason:   "Matched pattern",
				},
			},
			filename: "report.json",
			wantErr:  false,
		},
		{
			name:     "empty findings",
			findings: []Finding{},
			filename: "empty.json",
			wantErr:  false,
		},
		{
			name: "invalid output path",
			findings: []Finding{
				{Type: "test", Reason: "test"},
			},
			filename: "/invalid/path/report.json",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := filepath.Join(tempDir, tt.filename)
			if tt.wantErr {
				outputPath = tt.filename // Use invalid path as-is
			}

			err := writer.WriteJSON(tt.findings, outputPath)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify file was created and contains correct JSON
			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Errorf("Failed to read output file: %v", err)
				return
			}

			var loadedFindings []Finding
			err = json.Unmarshal(data, &loadedFindings)
			if err != nil {
				t.Errorf("Failed to parse JSON: %v", err)
				return
			}

			if len(loadedFindings) != len(tt.findings) {
				t.Errorf("Expected %d findings in JSON, got %d", len(tt.findings), len(loadedFindings))
			}

			// Verify content matches
			for i, original := range tt.findings {
				if i < len(loadedFindings) {
					loaded := loadedFindings[i]
					if loaded.Type != original.Type {
						t.Errorf("Mismatch in Type at index %d: expected %s, got %s", i, original.Type, loaded.Type)
					}
					if loaded.Name != original.Name {
						t.Errorf("Mismatch in Name at index %d: expected %s, got %s", i, original.Name, loaded.Name)
					}
					if loaded.Version != original.Version {
						t.Errorf("Mismatch in Version at index %d: expected %s, got %s", i, original.Version, loaded.Version)
					}
					if loaded.Path != original.Path {
						t.Errorf("Mismatch in Path at index %d: expected %s, got %s", i, original.Path, loaded.Path)
					}
					if loaded.File != original.File {
						t.Errorf("Mismatch in File at index %d: expected %s, got %s", i, original.File, loaded.File)
					}
					if loaded.Evidence != original.Evidence {
						t.Errorf("Mismatch in Evidence at index %d: expected %s, got %s", i, original.Evidence, loaded.Evidence)
					}
					if loaded.Reason != original.Reason {
						t.Errorf("Mismatch in Reason at index %d: expected %s, got %s", i, original.Reason, loaded.Reason)
					}
				}
			}
		})
	}
}

func TestReportWriter_WriteSARIF(t *testing.T) {
	writer := NewReportWriter()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test.sarif")

	findings := []Finding{
		{Type: "test", Reason: "test"},
	}

	err := writer.WriteSARIF(findings, outputPath)
	if err == nil {
		t.Error("Expected error for unimplemented SARIF generation, got nil")
	}

	expectedMsg := "SARIF generation not implemented"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedMsg, err.Error())
	}
}

// TestReportWriter_WriteJSON_FileCreation tests that the JSON file is actually created
func TestReportWriter_WriteJSON_FileCreation(t *testing.T) {
	writer := NewReportWriter()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-creation.json")

	findings := []Finding{
		{Type: "test", Name: "test-package", Version: "1.0.0"},
	}

	err := writer.WriteJSON(findings, outputPath)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("JSON file was not created")
	}

	// Check file is not empty
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if info.Size() == 0 {
		t.Error("JSON file is empty")
	}
}
