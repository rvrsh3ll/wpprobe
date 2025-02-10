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

package scanner

import (
	"fmt"
	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"log"
	"strings"
	"sync"
)

func ScanTargets(url string, file string, noCheckVersion bool, threads int, output string) {
	var targets []string
	isFileMode := false

	if file != "" {
		lines, err := utils.ReadLines(file)
		if err != nil {
			log.Fatalf("❌ Failed to read file: %v", err)
		}
		targets = lines
		isFileMode = true
	} else if url != "" {
		targets = append(targets, url)
	} else {
		log.Fatalf("❌ No target specified. Use -u or -f.")
	}

	var progress *utils.ProgressManager
	if isFileMode {
		progress = utils.NewProgressBar(len(targets))
	}

	var csvWriter *utils.CSVWriter
	if output != "" {
		csvWriter = utils.NewCSVWriter(output)
		defer csvWriter.Close()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t string) {
			defer wg.Done()
			ScanSite(t, noCheckVersion, csvWriter, isFileMode, output)
			if isFileMode {
				progress.Increment()
			}
			<-sem
		}(target)
	}

	wg.Wait()

	if isFileMode {
		progress.Finish()
	}
}

func ScanSite(target string, noCheckVersion bool, csvWriter *utils.CSVWriter, isFileMode bool, output string) {
	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		if !isFileMode {
			fmt.Printf("\n❌ Failed to load scanned_plugins.json: %v\n", err)
		}
		return
	}

	pluginEndpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		if !isFileMode {
			fmt.Printf("\n❌ Failed to parse scanned_plugins.json: %v\n", err)
		}
		return
	}

	endpoints := FetchEndpoints(target)
	if len(endpoints) == 0 {
		if !isFileMode {
			fmt.Printf("\n❌ No REST endpoints found on %s\n", target)
		}
		return
	}

	pluginMatches, pluginConfidence, pluginAmbiguity, detectedPlugins := DetectPlugins(endpoints, pluginEndpoints)
	if len(detectedPlugins) == 0 {
		if !isFileMode {
			fmt.Printf("\n❌ No plugins detected on %s\n", target)
		}
		return
	}

	results := make(map[string]string)
	resultsCSV := make(map[string]map[string]map[string][]string)
	pluginVulns := make(map[string]VulnCategories)

	for _, plugin := range detectedPlugins {
		version := "unknown"
		if !noCheckVersion {
			version = utils.GetPluginVersion(target, plugin)
		}
		results[plugin] = version

		vulns := wordfence.GetVulnerabilitiesForPlugin(plugin, version)
		vulnCategories := VulnCategories{}
		vulnMap := make(map[string][]string)

		for _, v := range vulns {
			vulnMap[v.Severity] = append(vulnMap[v.Severity], v.CVE)
			switch strings.ToLower(v.Severity) {
			case "critical":
				vulnCategories.Critical = append(vulnCategories.Critical, v.CVE)
			case "high":
				vulnCategories.High = append(vulnCategories.High, v.CVE)
			case "medium":
				vulnCategories.Medium = append(vulnCategories.Medium, v.CVE)
			case "low":
				vulnCategories.Low = append(vulnCategories.Low, v.CVE)
			}
		}
		resultsCSV[plugin] = map[string]map[string][]string{version: vulnMap}
		pluginVulns[plugin] = vulnCategories
	}

	DisplayResults(target, results, pluginMatches, pluginConfidence, pluginAmbiguity, pluginVulns)

	if csvWriter != nil {
		csvWriter.WriteResults(target, resultsCSV)
	}
}
