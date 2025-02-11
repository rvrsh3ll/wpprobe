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
	"math"
	"strings"
	"sync"
)

type ScanOptions struct {
	URL            string
	File           string
	NoCheckVersion bool
	Threads        int
	Output         string
	Verbose        bool
}

func ScanTargets(opts ScanOptions) {
	var targets []string

	if opts.File != "" {
		lines, err := utils.ReadLines(opts.File)
		if err != nil {
			log.Fatalf("❌ Failed to read file: %v", err)
		}
		targets = lines
	} else if opts.URL != "" {
		targets = append(targets, opts.URL)
	} else {
		log.Fatalf("❌ No target specified. Use -u or -f.")
	}

	siteThreads := opts.Threads
	if len(targets) > 1 {
		siteThreads = int(math.Max(1, float64(opts.Threads)/float64(len(targets))))
	}

	var progress *utils.ProgressManager
	if opts.File != "" {
		progress = utils.NewProgressBar(len(targets))
	}

	var csvWriter *utils.CSVWriter
	if opts.Output != "" {
		csvWriter = utils.NewCSVWriter(opts.Output)
		defer csvWriter.Close()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Threads)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t string, scanThreads int) {
			defer wg.Done()
			localOpts := opts
			localOpts.Threads = scanThreads
			ScanSite(t, localOpts, csvWriter, progress)
			if opts.File != "" {
				progress.Increment()
			}
			<-sem
		}(target, siteThreads)
	}

	wg.Wait()

	if opts.File != "" {
		progress.Finish()
	}
}

func ScanSite(target string, opts ScanOptions, csvWriter *utils.CSVWriter, progress *utils.ProgressManager) {
	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		if opts.File == "" {
			fmt.Printf("\n❌ Failed to load scanned_plugins.json: %v\n", err)
		}
		return
	}

	pluginEndpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		if opts.File == "" {
			fmt.Printf("\n❌ Failed to parse scanned_plugins.json: %v\n", err)
		}
		return
	}

	endpoints := FetchEndpoints(target)
	if len(endpoints) == 0 {
		if opts.File == "" {
			fmt.Printf("\n❌ No REST endpoints found on %s\n", target)
		}
		return
	}

	pluginResult := DetectPlugins(endpoints, pluginEndpoints)

	if len(pluginResult.Detected) == 0 {
		if opts.File == "" {
			fmt.Printf("\n❌ No plugins detected on %s\n", target)
		}
		return
	}

	results := make(map[string]string)
	resultsCSV := make(map[string]map[string]map[string][]string)
	pluginVulns := make(map[string]VulnCategories)
	pluginVersions := make(map[string]string)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Threads)

	for _, plugin := range pluginResult.Detected {
		wg.Add(1)
		sem <- struct{}{}

		go func(plugin string) {
			defer wg.Done()
			defer func() { <-sem }()

			version := "unknown"
			if !opts.NoCheckVersion {
				version = utils.GetPluginVersion(target, plugin, opts.Threads)
			}

			vulns := wordfence.GetVulnerabilitiesForPlugin(plugin, version)
			vulnCategories := VulnCategories{}
			vulnMap := make(map[string][]string)

			if len(vulns) == 0 {
				vulnMap["None"] = []string{"No known vulnerabilities"}
			} else {
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
			}

			mu.Lock()
			results[plugin] = version
			pluginVersions[plugin] = version
			resultsCSV[plugin] = map[string]map[string][]string{version: vulnMap}
			pluginVulns[plugin] = vulnCategories
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()

	ambiguousGroups := make(map[string][]string)
	for plugin := range pluginResult.Ambiguity {
		groupKey := fmt.Sprintf("%v", pluginResult.Matches[plugin])
		ambiguousGroups[groupKey] = append(ambiguousGroups[groupKey], plugin)
	}

	for _, group := range ambiguousGroups {
		var hasVersion bool
		for _, plugin := range group {
			if results[plugin] != "unknown" {
				hasVersion = true
				break
			}
		}
		if hasVersion {
			for _, plugin := range group {
				if results[plugin] == "unknown" {
					delete(results, plugin)
					delete(pluginVulns, plugin)
				}
			}
		}
	}

	DisplayResults(target, results, pluginResult, pluginVulns, opts, progress)

	if csvWriter != nil {
		csvWriter.WriteResults(target, resultsCSV)
	}
}
