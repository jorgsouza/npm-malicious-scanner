package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkIoCMatcher(b *testing.B) {
	testDir := filepath.Join("testdata", "benchmark")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	// Create a large synthetic file for benchmarking
	largeFile := filepath.Join(testDir, "large.js")
	content := make([]byte, 2*1024*1024) // 2MB file
	for i := range content {
		content[i] = 'a'
	}
	os.WriteFile(largeFile, content, 0644)

	patterns := []string{"Shai[-\\s]?Hulud", "eval\\(.{0,80}base64"}
	scanner, err := NewIoCScanner(patterns, 4)
	if err != nil {
		b.Fatalf("Failed to create IoC scanner: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan(testDir)
		if err != nil {
			b.Fatalf("Failed to scan directory: %v", err)
		}
	}
}
