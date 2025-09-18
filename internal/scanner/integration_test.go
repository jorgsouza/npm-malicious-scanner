package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrationScan(t *testing.T) {
	testDir := filepath.Join("testdata", "integration")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	// Create synthetic test files
	os.WriteFile(filepath.Join(testDir, "package.json"), []byte(`{"name": "malicious-package", "version": "1.0.0"}`), 0644)
	os.WriteFile(filepath.Join(testDir, "index.js"), []byte(`console.log('Hello World');`), 0644)

	discoverer, err := NewDiscoverer([]string{})
	if err != nil {
		t.Fatalf("Failed to create discoverer: %v", err)
	}

	targets, err := discoverer.Discover([]string{testDir})
	if err != nil {
		t.Fatalf("Failed to discover targets: %v", err)
	}

	if len(targets) != 1 {
		t.Errorf("Expected 1 target, got %d", len(targets))
	}

	reader := NewDependencyReader()
	packages, err := reader.ReadDependencies(testDir)
	if err != nil {
		t.Fatalf("Failed to read dependencies: %v", err)
	}

	if len(packages) != 1 || packages[0].Name != "malicious-package" {
		t.Errorf("Unexpected package data: %+v", packages[0])
	}
}
