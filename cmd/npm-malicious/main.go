package main

import (
	"fmt"
	"log"
	"os"

	"npm-malicious-scanner/internal/scanner"

	"github.com/spf13/cobra"
)

func main() {
	var paths []string
	var exclude []string
	var outputFormat string
	var blocklistPath string

	rootCmd := &cobra.Command{
		Use:   "npm-malicious",
		Short: "Scan for malicious npm packages",
		Run: func(cmd *cobra.Command, args []string) {
			// Create discoverer
			discoverer, err := scanner.NewDiscoverer(exclude)
			if err != nil {
				log.Fatalf("Failed to create discoverer: %v", err)
			}

			// Discover targets
			targets, err := discoverer.Discover(paths)
			if err != nil {
				log.Fatalf("Failed to discover targets: %v", err)
			}

			fmt.Printf("Discovered %d targets to scan\n", len(targets))

			// Create dependency reader
			reader := scanner.NewDependencyReader()

			// Load blocklist if provided
			var blocklist *scanner.Blocklist
			if blocklistPath != "" {
				blocklist, err = scanner.LoadBlocklist(blocklistPath)
				if err != nil {
					log.Printf("Warning: Failed to load blocklist from %s: %v", blocklistPath, err)
				} else {
					fmt.Printf("Loaded blocklist with %d entries\n", len(blocklist.Entries))
				}
			}

			// Create IoC scanner with common malicious patterns
			iocPatterns := []string{
				`eval\(.*\)`,                 // eval() usage
				`child_process`,              // child process spawning
				`fs\.unlinkSync`,             // file deletion
				`process\.env\[.*\]`,         // environment variable access
				`require\(['"]http['"]\)`,    // http requests
				`bitcoin|crypto|wallet`,      // crypto-related
				`password|passwd|credential`, // credential harvesting
				`download|fetch.*\.exe`,      // executable downloads
			}
			iocScanner, err := scanner.NewIoCScanner(iocPatterns, 5)
			if err != nil {
				log.Printf("Warning: Failed to create IoC scanner: %v", err)
			}

			// Scan all targets for packages and IoCs
			allFindings := []scanner.Finding{}
			packagesScanned := 0

			for _, target := range targets {
				// Read dependencies from this target
				packages, err := reader.ReadDependencies(target.Path)
				if err != nil {
					log.Printf("Warning: Failed to read dependencies from %s: %v", target.Path, err)
					continue
				}

				packagesScanned += len(packages)

				// Check packages against blocklist
				if blocklist != nil {
					for _, pkg := range packages {
						findings := blocklist.Match(pkg)
						allFindings = append(allFindings, findings...)
					}
				}

				// Run IoC scan on target
				if iocScanner != nil {
					iocFindings, err := iocScanner.Scan(target.Path)
					if err != nil {
						log.Printf("Warning: IoC scan failed for %s: %v", target.Path, err)
					} else {
						allFindings = append(allFindings, iocFindings...)
					}
				}
			}

			// Generate report
			rw := scanner.NewReportWriter()

			fmt.Printf("\n=== SCAN RESULTS ===\n")
			fmt.Printf("Packages scanned: %d\n", packagesScanned)
			fmt.Printf("Security findings: %d\n", len(allFindings))

			if len(allFindings) == 0 {
				fmt.Println("\n✅ No malicious packages or IoCs detected!")
			} else {
				fmt.Printf("\n⚠️  SECURITY ISSUES FOUND:\n\n")
			}

			if outputFormat == "pretty" {
				rw.WritePretty(allFindings)
			} else if outputFormat == "json" {
				err := rw.WriteJSON(allFindings, "findings.json")
				if err != nil {
					log.Fatalf("Failed to write JSON output: %v", err)
				}
				fmt.Println("\nJSON report written to findings.json")
			} else {
				log.Fatalf("Unsupported output format: %s", outputFormat)
			}

			// Exit with error code if findings detected
			if len(allFindings) > 0 {
				os.Exit(1)
			}
		},
	}

	rootCmd.Flags().StringSliceVar(&paths, "paths", []string{"."}, "Paths to scan")
	rootCmd.Flags().StringSliceVar(&exclude, "exclude", []string{}, "Exclude patterns (regex)")
	rootCmd.Flags().StringVar(&outputFormat, "output", "pretty", "Output format (pretty, json, sarif)")
	rootCmd.Flags().StringVar(&blocklistPath, "blocklist", "", "Path to blocklist JSON file")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
