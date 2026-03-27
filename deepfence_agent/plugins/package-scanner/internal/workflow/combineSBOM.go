package workflow

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------- STRUCT ----------------

type CombinedSBOM struct {
	Artifacts             []interface{} `json:"artifacts"`
	ArtifactRelationships []interface{} `json:"artifactRelationships"`
	Files                 []interface{} `json:"files"`
	Source                interface{}   `json:"source"`
	Distro                interface{}   `json:"distro"`
	Descriptor            interface{}   `json:"descriptor"`
	Schema                interface{}   `json:"schema"`
}

// ---------------- GET DISTRO ----------------

func getHostDistro() map[string]interface{} {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return map[string]interface{}{}
	}

	lines := strings.Split(string(data), "\n")
	distro := map[string]string{}

	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := parts[0]
			val := strings.Trim(parts[1], `"`)
			distro[key] = val
		}
	}

	return map[string]interface{}{
		"name":    distro["NAME"],
		"version": distro["VERSION_ID"],
		"id":      distro["ID"],
	}
}

// ---------------- GET FILES ----------------

func getSBOMFilesFromFolder(folderPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// ---------------- PROGRESS BAR ----------------

func printProgressSBOM(current, total int) {
	percent := float64(current) / float64(total) * 100
	barLength := 30

	filled := int(percent / 100 * float64(barLength))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barLength-filled)

	fmt.Printf("\r📊 Progress: [%s] %.1f%% (%d/%d)", bar, percent, current, total)
}

// ---------------- COMBINE ----------------

func combineSBOMs(filePaths []string) (*CombinedSBOM, error) {

	hostname, _ := os.Hostname()

	combined := &CombinedSBOM{
		Artifacts:             []interface{}{},
		ArtifactRelationships: []interface{}{},
		Files:                 []interface{}{},

		// ✅ FIXED SOURCE FOR SYFT v0.80
		Source: map[string]interface{}{
			"id":   "host-" + hostname,
			"name": "host-scan",
			"type": "directory", // 🔥 IMPORTANT FIX
			"metadata": map[string]interface{}{
				"path": "/mounted_chunks",
			},
		},

		Distro: getHostDistro(),

		Descriptor: map[string]interface{}{
			"name":          "syft",
			"version":       "0.80.0",
			"configuration": map[string]interface{}{},
		},

		Schema: map[string]interface{}{
			"version": "11.0.1",
			"url":     "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-11.0.1.json",
		},
	}

	total := len(filePaths)

	for i, filePath := range filePaths {

		printProgressSBOM(i+1, total)

		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("\n❌ Read error: %s\n", filePath)
			continue
		}

		var sbom map[string]interface{}
		if err := json.Unmarshal(data, &sbom); err != nil {
			fmt.Printf("\n❌ JSON error: %s\n", filePath)
			continue
		}

		if a, ok := sbom["artifacts"].([]interface{}); ok {
			combined.Artifacts = append(combined.Artifacts, a...)
		}

		if r, ok := sbom["artifactRelationships"].([]interface{}); ok {
			combined.ArtifactRelationships = append(combined.ArtifactRelationships, r...)
		}

		if f, ok := sbom["files"].([]interface{}); ok {
			combined.Files = append(combined.Files, f...)
		}
	}

	fmt.Println()
	return combined, nil
}

// ---------------- MAIN ----------------

func combineSBOMFiles(cfg *Config) error {

	start := time.Now()

	sbomFolder := cfg.SyftOutputDir
	outputFile := cfg.FinalOutputFile

	fmt.Println("📥 Loading SBOM files...")

	files, err := getSBOMFilesFromFolder(sbomFolder)
	if err != nil {
		fmt.Println("❌ Error:", err)
		return err
	}

	if len(files) == 0 {
		fmt.Println("❌ No SBOM files found")
		return fmt.Errorf("no SBOM files found in %s", sbomFolder)
	}

	fmt.Printf("📦 Found %d SBOM files\n", len(files))

	combined, err := combineSBOMs(files)
	if err != nil {
		fmt.Println("❌ Combine error:", err)
		return err
	}

	jsonData, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		fmt.Println("❌ JSON error:", err)
		return err
	}

	err = ioutil.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		fmt.Println("❌ Write error:", err)
		return err
	}

	fmt.Println("✅ Combined SBOM saved:", outputFile)
	fmt.Println("⏱ Time taken:", time.Since(start))
	return nil
}
