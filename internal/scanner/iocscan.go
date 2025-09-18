package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IoCScanner scans files for indicators of compromise.
type IoCScanner struct {
	Patterns []*regexp.Regexp
	MaxDepth int
}

// NewIoCScanner creates a new IoCScanner with the given patterns and max depth.
func NewIoCScanner(patterns []string, maxDepth int) (*IoCScanner, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, re)
	}
	return &IoCScanner{Patterns: compiled, MaxDepth: maxDepth}, nil
}

// Scan scans the given path for IoCs.
func (s *IoCScanner) Scan(path string) ([]Finding, error) {
	findings := []Finding{}

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip paths with errors
		}

		if info.IsDir() {
			if depth(p) > s.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		if isTargetFile(filepath.Base(p)) {
			content, err := os.ReadFile(p)
			if err != nil {
				return nil
			}

			for _, re := range s.Patterns {
				if match := re.Find(content); match != nil {
					findings = append(findings, Finding{
						Type:     "ioc",
						File:     p,
						Reason:   "Matched pattern",
						Evidence: string(match),
					})
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return findings, nil
}

// depth calculates the depth of a path.
func depth(path string) int {
	return strings.Count(filepath.Clean(path), string(os.PathSeparator))
}

// isTargetFile checks if a file is a target for IoC scanning.
func isTargetFile(name string) bool {
	return name == "package.json" || name == "index.js" || name == "postinstall.js" || name == "bundle.js"
}
