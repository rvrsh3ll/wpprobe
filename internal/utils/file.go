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

package utils

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type WriterInterface interface {
	WriteResults(url string, results []PluginEntry)
	Close()
}

type PluginEntry struct {
	Plugin     string   `json:"plugin"`
	Version    string   `json:"version"`
	Severity   string   `json:"severity"`
	CVEs       []string `json:"cves"`
	CVELinks   []string `json:"cve_link"`
	Title      string   `json:"title"`
	AuthType   string   `json:"auth_type"`
	CVSSScore  float64  `json:"cvss_score"`
	CVSSVector string   `json:"cvss_vector"`
}

func authTypeOrder(auth string) int {
	a := strings.ToLower(auth)
	switch a {
	case "unauth":
		return 0
	case "auth":
		return 1
	default:
		return 2
	}
}

//////////////////////////////
// CSV Writer Implementation
//////////////////////////////

type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

func NewCSVWriter(filename string) *CSVWriter {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		DefaultLogger.Error("Failed to open CSV file: " + err.Error())
	}

	writer := csv.NewWriter(file)
	header := []string{
		"URL",
		"Plugin",
		"Version",
		"Severity",
		"AuthType",
		"CVEs",
		"CVE Links",
		"CVSS Score",
		"CVSS Vector",
		"Title",
	}
	_ = writer.Write(header)
	writer.Flush()

	return &CSVWriter{
		file:   file,
		writer: writer,
	}
}

func (c *CSVWriter) WriteResults(url string, results []PluginEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sort.Slice(results, func(i, j int) bool {
		return authTypeOrder(results[i].AuthType) < authTypeOrder(results[j].AuthType)
	})

	for _, entry := range results {
		row := []string{
			url,
			entry.Plugin,
			entry.Version,
			entry.Severity,
			entry.AuthType,
			strings.Join(entry.CVEs, ", "),
			strings.Join(entry.CVELinks, ", "),
			fmt.Sprintf("%.1f", entry.CVSSScore),
			entry.CVSSVector,
			entry.Title,
		}
		_ = c.writer.Write(row)
	}
	c.writer.Flush()
}

func (c *CSVWriter) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writer.Flush()
	_ = c.file.Close()
}

//////////////////////////////
// JSON Writer Implementation
//////////////////////////////

type JSONWriter struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
	first   bool
}

func NewJSONWriter(output string) *JSONWriter {
	file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		DefaultLogger.Error("Failed to open JSON file: " + err.Error())
		os.Exit(1)
	}

	return &JSONWriter{file: file, encoder: json.NewEncoder(file)}
}

func (j *JSONWriter) WriteResults(url string, results []PluginEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()

	groupedResults := make(map[string]map[string]map[string]map[string][]map[string]interface{})

	for _, entry := range results {
		plugin := entry.Plugin
		version := entry.Version
		severity := entry.Severity
		auth := strings.ToLower(entry.AuthType)

		if auth != "auth" && auth != "unauth" && auth != "privileged" {
			auth = "unknown"
		}

		if _, ok := groupedResults[plugin]; !ok {
			groupedResults[plugin] = make(map[string]map[string]map[string][]map[string]interface{})
		}
		if _, ok := groupedResults[plugin][version]; !ok {
			groupedResults[plugin][version] = make(map[string]map[string][]map[string]interface{})
		}
		if severity != "" && severity != "N/A" {
			if _, ok := groupedResults[plugin][version][severity]; !ok {
				groupedResults[plugin][version][severity] = make(
					map[string][]map[string]interface{},
				)
			}

			for i, cve := range entry.CVEs {
				cveLink := ""
				if i < len(entry.CVELinks) {
					cveLink = entry.CVELinks[i]
				}

				groupedResults[plugin][version][severity][auth] = append(
					groupedResults[plugin][version][severity][auth],
					map[string]interface{}{
						"cve":         cve,
						"cve_link":    cveLink,
						"title":       entry.Title,
						"cvss_score":  entry.CVSSScore,
						"cvss_vector": entry.CVSSVector,
					},
				)
			}
		}
	}

	pluginsFormatted := make(map[string][]map[string]interface{})
	desiredAuthOrder := []string{"unauth", "auth", "privileged", "unknown"}

	for plugin, versions := range groupedResults {
		for version, severities := range versions {
			formattedSeverities := make(map[string]interface{})
			hasVulnerabilities := false

			for severity, authMap := range severities {
				ordered := make([]map[string]interface{}, 0)
				for _, a := range desiredAuthOrder {
					if vulns, ok := authMap[a]; ok && len(vulns) > 0 {
						ordered = append(ordered, map[string]interface{}{
							"auth_type":       cases.Title(language.Und).String(a),
							"vulnerabilities": vulns,
						})
					}
				}
				if len(ordered) > 0 {
					formattedSeverities[severity] = ordered
					hasVulnerabilities = true
				}
			}

			entry := map[string]interface{}{"version": version}
			if hasVulnerabilities {
				entry["severities"] = formattedSeverities
			}

			pluginsFormatted[plugin] = append(pluginsFormatted[plugin], entry)
		}
	}

	detectedPlugins := make(map[string]bool)
	for _, entry := range results {
		detectedPlugins[entry.Plugin] = true
	}

	for _, entry := range results {
		if _, exists := pluginsFormatted[entry.Plugin]; !exists {
			pluginsFormatted[entry.Plugin] = []map[string]interface{}{
				{"version": entry.Version},
			}
		}
	}

	outputEntry := map[string]interface{}{
		"url":     url,
		"plugins": pluginsFormatted,
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(outputEntry)

	data := buffer.Bytes()
	if len(data) > 0 {
		data = data[:len(data)-1]
	}

	if !j.first {
		_, _ = j.file.WriteString("\n")
	}
	j.first = false

	_, _ = j.file.Write(data)
}

func (j *JSONWriter) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.file.Close()
}

//////////////////////////////
// Writer Factory
//////////////////////////////

func DetectOutputFormat(outputFile string) string {
	if outputFile == "" {
		return "csv"
	}
	ext := strings.TrimPrefix(filepath.Ext(outputFile), ".")
	supported := []string{"csv", "json"}
	for _, format := range supported {
		if ext == format {
			return format
		}
	}
	fmt.Printf("⚠️ Unsupported output format: %s. Defaulting to CSV.\n", ext)
	return "csv"
}

func GetWriter(outputFile string) WriterInterface {
	format := DetectOutputFormat(outputFile)
	switch format {
	case "json":
		return NewJSONWriter(outputFile)
	default:
		return NewCSVWriter(outputFile)
	}
}

//////////////////////////////
// Utils
//////////////////////////////

func FormatVulnerabilities(vulnMap map[string][]string) string {
	var sections []string
	for severity, cves := range vulnMap {
		sections = append(sections, fmt.Sprintf("%s: %s", severity, strings.Join(cves, ", ")))
	}
	return strings.Join(sections, " | ")
}

func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		DefaultLogger.Error("Failed to open file: " + err.Error())
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		DefaultLogger.Error("Failed to read lines: " + err.Error())
		return nil, err
	}
	return lines, nil
}

func GetStoragePath(filename string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		DefaultLogger.Error("Failed to get config directory: " + err.Error())
		return "", err
	}
	storagePath := filepath.Join(configDir, "wpprobe")
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		DefaultLogger.Error("Failed to create storage directory: " + err.Error())
		return "", err
	}
	return filepath.Join(storagePath, filename), nil
}
