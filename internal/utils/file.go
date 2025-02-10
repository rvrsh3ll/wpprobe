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
	"encoding/csv"
	"path/filepath"

	"fmt"
	"os"
	"strings"
)

type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
}

func NewCSVWriter(output string) *CSVWriter {
	file, err := os.Create(output)
	if err != nil {
		fmt.Printf("❌ Failed to create CSV file: %v\n", err)
		os.Exit(1)
	}

	writer := csv.NewWriter(file)
	header := []string{"URL", "Plugin", "Version", "Severity", "CVEs"}
	if err := writer.Write(header); err != nil {
		fmt.Printf("❌ Failed to write CSV header: %v\n", err)
		os.Exit(1)
	}
	writer.Flush()

	return &CSVWriter{file: file, writer: writer}
}

func (c *CSVWriter) WriteResults(url string, results map[string]map[string]map[string][]string) {
	for plugin, versions := range results {
		for version, vulnMap := range versions {
			for severity, cves := range vulnMap {
				row := []string{
					url,
					plugin,
					version,
					severity,
					strings.Join(cves, ", "),
				}
				_ = c.writer.Write(row)
			}
		}
	}
	c.writer.Flush()
}

func (c *CSVWriter) Close() {
	c.writer.Flush()
	_ = c.file.Close()
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
		return nil, fmt.Errorf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("❌ Failed to read lines: %v", err)
	}

	return lines, nil
}

func GetStoragePath(filename string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("❌ Failed to get config directory: %v", err)
	}

	storagePath := filepath.Join(configDir, "wpprobe")

	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return "", fmt.Errorf("❌ Failed to create storage directory: %v", err)
	}

	return filepath.Join(storagePath, filename), nil
}
