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

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type WriterInterface interface {
	WriteResults(url string, results []PluginEntry)
	Close()
}

type PluginEntry struct {
	Plugin   string   `json:"plugin"`
	Version  string   `json:"version"`
	Severity string   `json:"severity"`
	CVEs     []string `json:"cves"`
	Title    string   `json:"title"`
	AuthType string   `json:"auth_type"`
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
}

func NewCSVWriter(output string) *CSVWriter {
	file, err := os.Create(output)
	if err != nil {
		logger.Error("Failed to create CSV file: " + err.Error())
		return nil
	}

	writer := csv.NewWriter(file)
	header := []string{"URL", "Plugin", "Version", "Severity", "AuthType", "CVEs", "Title"}
	_ = writer.Write(header)
	writer.Flush()

	return &CSVWriter{file: file, writer: writer}
}

func (c *CSVWriter) WriteResults(url string, results []PluginEntry) {
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
			entry.Title,
		}
		_ = c.writer.Write(row)
	}
	c.writer.Flush()
}

func (c *CSVWriter) Close() {
	if c.file != nil {
		c.writer.Flush()
		_ = c.file.Close()
	}
}

//////////////////////////////
// JSON Writer Implementation
//////////////////////////////

type JSONWriter struct {
	file    *os.File
	encoder *json.Encoder
	first   bool
}

func NewJSONWriter(output string) *JSONWriter {
	file, err := os.Create(output)
	if err != nil {
		logger.Error("Failed to create JSON file: " + err.Error())
		os.Exit(1)
	}

	writer := &JSONWriter{
		file:    file,
		encoder: json.NewEncoder(file),
		first:   true,
	}

	return writer
}

func (j *JSONWriter) WriteResults(url string, results []PluginEntry) {
	groupedResults := make(map[string]map[string]map[string]map[string][]string)
	for _, entry := range results {
		plugin := entry.Plugin
		version := entry.Version
		severity := entry.Severity
		auth := strings.ToLower(entry.AuthType)
		if auth != "auth" && auth != "unauth" {
			auth = "unknown"
		}

		if _, ok := groupedResults[plugin]; !ok {
			groupedResults[plugin] = make(map[string]map[string]map[string][]string)
		}
		if _, ok := groupedResults[plugin][version]; !ok {
			groupedResults[plugin][version] = make(map[string]map[string][]string)
		}
		if _, ok := groupedResults[plugin][version][severity]; !ok {
			groupedResults[plugin][version][severity] = make(map[string][]string)
		}
		groupedResults[plugin][version][severity][auth] =
			append(groupedResults[plugin][version][severity][auth], entry.CVEs...)
	}

	pluginsFormatted := make(map[string][]map[string]interface{})
	desiredAuthOrder := []string{"unauth", "auth", "unknown"}
	for plugin, versions := range groupedResults {
		for version, severities := range versions {
			formattedSeverities := make(map[string]interface{})
			for severity, authMap := range severities {
				ordered := make([]map[string]interface{}, 0)
				for _, a := range desiredAuthOrder {
					if cves, ok := authMap[a]; ok && len(cves) > 0 {
						ordered = append(ordered, map[string]interface{}{
							"auth_type": cases.Title(language.Und).String(a),
							"cves":      cves,
						})
					}
				}
				formattedSeverities[severity] = ordered
			}
			pluginsFormatted[plugin] = append(pluginsFormatted[plugin], map[string]interface{}{
				"version":    version,
				"severities": formattedSeverities,
			})
		}
	}

	outputEntry := map[string]interface{}{
		"url":     url,
		"plugins": pluginsFormatted,
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
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
	_ = j.file.Close()
}

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
	fmt.Printf("⚠️ Unsupported output format: %s. Supported: csv, json. Defaulting to CSV.\n", ext)
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
		logger.Error("Failed to open file: " + err.Error())
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		logger.Error("Failed to read lines: " + err.Error())
		return nil, err
	}
	return lines, nil
}

func GetStoragePath(filename string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		logger.Error("Failed to get config directory: " + err.Error())
		return "", err
	}
	storagePath := filepath.Join(configDir, "wpprobe")
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		logger.Error("Failed to create storage directory: " + err.Error())
		return "", err
	}
	return filepath.Join(storagePath, filename), nil
}
