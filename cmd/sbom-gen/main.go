package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type SPDXDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage  `json:"packages"`
}

type CreationInfo struct {
	Creators []string `json:"creators"`
	Created  string   `json:"created"`
}

type SPDXPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sbom-gen <go.mod path> <output.json path>")
		os.Exit(1)
	}

	goModPath := os.Args[1]
	outputPath := os.Args[2]

	file, err := os.Open(goModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening go.mod: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	doc := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "the-black-hole",
		DocumentNamespace: "https://github.com/olafkfreund/the-black-hole/spdx",
		CreationInfo: CreationInfo{
			Creators: []string{"Tool: BlackHole-SBOM-Gen-1.0"},
			Created:  time.Now().UTC().Format(time.RFC3339),
		},
		Packages: []SPDXPackage{
			{
				Name:             "github.com/calitti/mcp-api-gateway",
				SPDXID:           "SPDXRef-Package-main",
				VersionInfo:      "0.9.0",
				DownloadLocation: "git+https://github.com/olafkfreund/the-black-hole.git",
				LicenseConcluded: "MIT",
			},
		},
	}

	scanner := bufio.NewScanner(file)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == ")" {
			inRequireBlock = false
			continue
		}

		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				addPackage(&doc, parts[1], parts[2])
			}
			continue
		}

		if inRequireBlock {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addPackage(&doc, parts[0], parts[1])
			}
		}
	}

	outBytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling JSON: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outputPath, outBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated SPDX SBOM at: %s\n", outputPath)
}

func addPackage(doc *SPDXDocument, name, version string) {
	// Clean up indirect comments
	version = strings.Split(version, " ")[0]
	
	spdxID := "SPDXRef-Package-" + strings.ReplaceAll(strings.ReplaceAll(name, "/", "-"), ".", "-")
	
	doc.Packages = append(doc.Packages, SPDXPackage{
		Name:             name,
		SPDXID:           spdxID,
		VersionInfo:      version,
		DownloadLocation: "git+https://" + name + ".git",
		LicenseConcluded: "NOASSERTION",
	})
}
