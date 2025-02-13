// Copyright (c) 2025 Valentin Lobstein (Chocapikk) <balgogan@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package wordfence

import (
	"fmt"
	"github.com/goccy/go-json"
	"net/http"
	"os"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

const wordfenceAPI = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"

type Vulnerability struct {
	ID              string `json:"id"`
	Slug            string `json:"slug"`
	SoftwareType    string `json:"type"`
	AffectedVersion string `json:"affected_version"`
	FromVersion     string `json:"from_version"`
	FromInclusive   bool   `json:"from_inclusive"`
	ToVersion       string `json:"to_version"`
	ToInclusive     bool   `json:"to_inclusive"`
	Severity        string `json:"severity"`
	CVE             string `json:"cve"`
	CVELink         string `json:"cve_link"`
}

func UpdateWordfence() error {
	fmt.Println("📥 Fetching Wordfence data...")
	data, err := fetchWordfenceData()
	if err != nil {
		return fmt.Errorf("❌ Failed to retrieve Wordfence data: %v", err)
	}

	fmt.Println("🛠 Processing vulnerabilities...")
	vulnerabilities := processWordfenceData(data)

	fmt.Println("💾 Saving vulnerabilities to file...")
	if err := saveVulnerabilitiesToFile(vulnerabilities); err != nil {
		return fmt.Errorf("❌ Failed to save Wordfence data: %v", err)
	}

	fmt.Println("✅ Wordfence data updated successfully!")
	return nil
}

func fetchWordfenceData() (map[string]interface{}, error) {
	resp, err := http.Get(wordfenceAPI)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to retrieve Wordfence data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("❌ API responded with status code %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("❌ JSON decoding error: %v", err)
	}

	return data, nil
}

func processWordfenceData(wfData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	for vulnID, vulnerability := range wfData {
		vulnMap, ok := vulnerability.(map[string]interface{})
		if !ok {
			continue
		}

		for _, software := range vulnMap["software"].([]interface{}) {
			softMap, ok := software.(map[string]interface{})
			if !ok {
				continue
			}

			slug, _ := softMap["slug"].(string)
			cve, _ := vulnMap["cve"].(string)
			cveLink, _ := vulnMap["cve_link"].(string)
			softwareType, _ := softMap["type"].(string)

			if cve == "" {
				continue
			}

			affectedVersions, ok := softMap["affected_versions"].(map[string]interface{})
			if !ok {
				continue
			}

			for versionLabel, affectedVersionData := range affectedVersions {
				affectedVersion, ok := affectedVersionData.(map[string]interface{})
				if !ok {
					continue
				}

				fromVersion := strings.ReplaceAll(affectedVersion["from_version"].(string), "*", "0.0.0")
				toVersion := strings.ReplaceAll(affectedVersion["to_version"].(string), "*", "999999.0.0")

				vuln := Vulnerability{
					ID:              vulnID,
					Slug:            slug,
					SoftwareType:    softwareType,
					AffectedVersion: versionLabel,
					FromVersion:     fromVersion,
					FromInclusive:   affectedVersion["from_inclusive"].(bool),
					ToVersion:       toVersion,
					ToInclusive:     affectedVersion["to_inclusive"].(bool),
					Severity:        strings.ToLower(vulnMap["cvss"].(map[string]interface{})["rating"].(string)),
					CVE:             cve,
					CVELink:         cveLink,
				}

				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func saveVulnerabilitiesToFile(vulnerabilities []Vulnerability) error {
	outputPath, err := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("❌ Error saving file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(vulnerabilities); err != nil {
		return fmt.Errorf("❌ Error encoding JSON: %v", err)
	}

	fmt.Printf("✅ Wordfence data saved in %s\n", outputPath)
	return nil
}

func loadVulnerabilities(filename string) ([]Vulnerability, error) {
	filePath, err := utils.GetStoragePath(filename)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to open Wordfence JSON: %v", err)
	}
	defer file.Close()

	var vulnerabilities []Vulnerability
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&vulnerabilities); err != nil {
		return nil, fmt.Errorf("❌ JSON decoding error: %v", err)
	}

	return vulnerabilities, nil
}

func GetVulnerabilitiesForPlugin(plugin string, version string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	data, err := loadVulnerabilities("wordfence_vulnerabilities.json")
	if err != nil {
		return vulnerabilities
	}

	for _, vuln := range data {
		if vuln.CVE == "" {
			continue
		}

		if vuln.Slug == plugin {
			if utils.IsVersionVulnerable(version, vuln.FromVersion, vuln.ToVersion) {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}
