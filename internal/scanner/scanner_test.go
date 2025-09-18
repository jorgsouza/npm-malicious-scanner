package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverer(t *testing.T) {
	exclude := []string{".*\\.git.*"}
	discoverer, err := NewDiscoverer(exclude)
	if err != nil {
		t.Fatalf("Failed to create discoverer: %v", err)
	}

	testDir := filepath.Join("testdata", "discover")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	os.WriteFile(filepath.Join(testDir, "package.json"), []byte("{}"), 0644)

	targets, err := discoverer.Discover([]string{testDir})
	if err != nil {
		t.Fatalf("Failed to discover targets: %v", err)
	}

	if len(targets) != 1 {
		t.Errorf("Expected 1 target, got %d", len(targets))
	}
}

func TestDependencyReader(t *testing.T) {
	reader := NewDependencyReader()
	testDir := filepath.Join("testdata", "dependencies")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	os.WriteFile(filepath.Join(testDir, "package.json"), []byte(`{"name": "test", "version": "1.0.0"}`), 0644)

	packages, err := reader.ReadDependencies(testDir)
	if err != nil {
		t.Fatalf("Failed to read dependencies: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(packages))
	}

	if packages[0].Name != "test" || packages[0].Version != "1.0.0" {
		t.Errorf("Unexpected package data: %+v", packages[0])
	}
}
