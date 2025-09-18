package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// PackageRef represents a package with its name, version, and path.
type PackageRef struct {
	Name    string
	Version string
	Path    string
}

// DependencyReader reads dependencies from node_modules and package.json.
type DependencyReader struct{}

// NewDependencyReader creates a new DependencyReader.
func NewDependencyReader() *DependencyReader {
	return &DependencyReader{}
}

// ReadDependencies scans the given path for dependencies.
func (r *DependencyReader) ReadDependencies(path string) ([]PackageRef, error) {
	packages := []PackageRef{}

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip paths with errors
		}

		if info.IsDir() && filepath.Base(p) == "node_modules" {
			return filepath.SkipDir // Skip nested node_modules
		}

		if filepath.Base(p) == "package.json" {
			pkg, err := parsePackageJSON(p)
			if err == nil {
				packages = append(packages, pkg)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return packages, nil
}

// parsePackageJSON parses a package.json file and extracts the name and version.
func parsePackageJSON(path string) (PackageRef, error) {
	file, err := os.Open(path)
	if err != nil {
		return PackageRef{}, err
	}
	defer file.Close()

	var data struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return PackageRef{}, err
	}

	return PackageRef{
		Name:    data.Name,
		Version: data.Version,
		Path:    filepath.Dir(path),
	}, nil
}
