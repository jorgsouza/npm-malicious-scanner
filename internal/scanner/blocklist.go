package scanner

import (
	"encoding/json"
	"os"
	"strings"
)

// BlocklistEntry represents a blocklist entry with name and versions.
type BlocklistEntry struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// Blocklist represents a collection of blocklist entries.
type Blocklist struct {
	Entries []BlocklistEntry
}

// LoadBlocklist loads a blocklist from a file.
func LoadBlocklist(path string) (*Blocklist, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []BlocklistEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return nil, err
	}

	return &Blocklist{Entries: entries}, nil
}

// Match checks if a package matches the blocklist.
func (b *Blocklist) Match(pkg PackageRef) []Finding {
	findings := []Finding{}

	for _, entry := range b.Entries {
		if strings.EqualFold(entry.Name, pkg.Name) {
			if len(entry.Versions) == 0 || contains(entry.Versions, pkg.Version) {
				findings = append(findings, Finding{
					Type:    "blocklist",
					Name:    pkg.Name,
					Version: pkg.Version,
					Path:    pkg.Path,
					Reason:  "Matched blocklist",
				})
			}
		}
	}

	return findings
}

// contains checks if a slice contains a string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
