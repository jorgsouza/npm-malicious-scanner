package scanner

import (
	"os"
	"path/filepath"
	"regexp"
)

// Target represents a directory or file to be analyzed.
type Target struct {
	Path string
}

// Discoverer is responsible for finding directories and files to scan.
type Discoverer struct {
	ExcludePatterns []*regexp.Regexp
}

// NewDiscoverer creates a new Discoverer with the given exclude patterns.
func NewDiscoverer(exclude []string) (*Discoverer, error) {
	patterns := make([]*regexp.Regexp, 0, len(exclude))
	for _, pattern := range exclude {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, re)
	}
	return &Discoverer{ExcludePatterns: patterns}, nil
}

// Discover scans the given paths and returns a list of targets.
func (d *Discoverer) Discover(paths []string) ([]Target, error) {
	targets := []Target{}
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip paths with errors (e.g., permission denied)
			}

			// Check if the path matches any exclude pattern
			for _, re := range d.ExcludePatterns {
				if re.MatchString(path) {
					return nil
				}
			}

			// Add directories containing package.json or node_modules
			if info.IsDir() {
				if filepath.Base(path) == "node_modules" || fileExists(filepath.Join(path, "package.json")) {
					targets = append(targets, Target{Path: path})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// fileExists checks if a file exists at the given path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
