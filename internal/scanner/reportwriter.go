package scanner

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReportWriter generates reports in Pretty, JSON, and SARIF formats.
type ReportWriter struct{}

// NewReportWriter creates a new ReportWriter.
func NewReportWriter() *ReportWriter {
	return &ReportWriter{}
}

// WritePretty writes a human-readable report.
func (rw *ReportWriter) WritePretty(findings []Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println("SECURITY FINDINGS:")
	fmt.Println("==================")

	blocklistFindings := []Finding{}
	iocFindings := []Finding{}

	// Categorize findings
	for _, finding := range findings {
		if finding.Type == "blocklist" {
			blocklistFindings = append(blocklistFindings, finding)
		} else if finding.Type == "ioc" {
			iocFindings = append(iocFindings, finding)
		}
	}

	// Report blocklist matches
	if len(blocklistFindings) > 0 {
		fmt.Printf("\n🚨 BLOCKLISTED PACKAGES (%d):\n", len(blocklistFindings))
		for i, finding := range blocklistFindings {
			fmt.Printf("%d. Package: %s@%s\n", i+1, finding.Name, finding.Version)
			fmt.Printf("   Path: %s\n", finding.Path)
			fmt.Printf("   Reason: %s\n", finding.Reason)
			fmt.Println()
		}
	}

	// Report IoC matches
	if len(iocFindings) > 0 {
		fmt.Printf("\n⚠️  SUSPICIOUS CODE PATTERNS (%d):\n", len(iocFindings))
		for i, finding := range iocFindings {
			fmt.Printf("%d. File: %s\n", i+1, finding.File)
			fmt.Printf("   Pattern: %s\n", finding.Evidence)
			fmt.Printf("   Reason: %s\n", finding.Reason)
			fmt.Println()
		}
	}
}

// WriteJSON writes a JSON report.
func (rw *ReportWriter) WriteJSON(findings []Finding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(findings)
}

// WriteSARIF writes a SARIF report.
func (rw *ReportWriter) WriteSARIF(findings []Finding, outputPath string) error {
	// Placeholder for SARIF generation logic
	return fmt.Errorf("SARIF generation not implemented")
}
