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
	"math"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

type ScanOptions struct {
	URL            string
	File           string
	NoCheckVersion bool
	Threads        int
	Output         string
	OutputFormat   string
	Verbose        bool
}

func ScanTargets(opts ScanOptions) {
	var targets []string

	if opts.File != "" {
		lines, err := utils.ReadLines(opts.File)
		if err != nil {
			utils.DefaultLogger.Error("Failed to read file: " + err.Error())
			return
		}
		targets = lines
	} else {
		targets = append(targets, opts.URL)
	}

	vulnerabilityData, _ := wordfence.LoadVulnerabilities("wordfence_vulnerabilities.json")

	siteThreads := int(math.Max(1, float64(opts.Threads)/float64(len(targets))))

	var progress *utils.ProgressManager
	if opts.File != "" {
		progress = utils.NewProgressBar(len(targets), "🔎 Scanning...")
	} else {
		progress = utils.NewProgressBar(1, "🔎 Scanning...")
	}

	var writer utils.WriterInterface
	if opts.Output != "" {
		writer = utils.GetWriter(opts.Output)
		defer writer.Close()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Threads)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string, scanThreads int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			localOpts := opts
			localOpts.Threads = scanThreads

			ScanSite(t, localOpts, writer, progress, vulnerabilityData)

			if opts.File != "" && progress != nil {
				progress.Increment()
			}
		}(target, siteThreads)
	}

	wg.Wait()

	if progress != nil {
		progress.Finish()
	}
}

func ScanSite(
	target string,
	opts ScanOptions,
	writer utils.WriterInterface,
	progress *utils.ProgressManager,
	vulnerabilityData []wordfence.Vulnerability,
) {
	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		utils.DefaultLogger.Error("Failed to load scanned_plugins.json: " + err.Error())
		return
	}

	pluginEndpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		utils.DefaultLogger.Error("Failed to parse scanned_plugins.json: " + err.Error())
		return
	}

	endpoints := FetchEndpoints(target)
	if len(endpoints) == 0 {
		if opts.File == "" {
			utils.DefaultLogger.Warning("No REST endpoints found on " + target)
		}
		return
	}

	pluginResult := DetectPlugins(endpoints, pluginEndpoints)
	if len(pluginResult.Detected) == 0 {
		if opts.File == "" {
			utils.DefaultLogger.Warning("No plugins detected on " + target)
		}
		if writer != nil {
			writer.WriteResults(target, []utils.PluginEntry{})
		}
		return
	}

	results := make(map[string]string)
	var resultsList []utils.PluginEntry
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Threads)

	totalTasks := len(pluginResult.Detected)
	if progress != nil && opts.File == "" {
		progress.SetTotal(totalTasks)
	}

	for _, plugin := range pluginResult.Detected {
		wg.Add(1)
		sem <- struct{}{}
		go func(plugin string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			var localResultsList []utils.PluginEntry
			version := "unknown"
			if !opts.NoCheckVersion {
				version = utils.GetPluginVersion(target, plugin, opts.Threads)
			}

			vulns := []wordfence.Vulnerability{}
			for _, vuln := range vulnerabilityData {
				if vuln.Slug == plugin &&
					utils.IsVersionVulnerable(version, vuln.FromVersion, vuln.ToVersion) {
					vulns = append(vulns, vuln)
				}
			}

			if len(vulns) == 0 {
				localResultsList = append(localResultsList, utils.PluginEntry{
					Plugin:     plugin,
					Version:    version,
					Severity:   "N/A",
					AuthType:   "N/A",
					CVEs:       []string{"N/A"},
					CVELinks:   []string{"N/A"},
					Title:      "N/A",
					CVSSScore:  0.0,
					CVSSVector: "N/A",
				})
			} else {
				for _, v := range vulns {
					localResultsList = append(localResultsList, utils.PluginEntry{
						Plugin:     plugin,
						Version:    version,
						Severity:   v.Severity,
						AuthType:   v.AuthType,
						CVEs:       []string{v.CVE},
						CVELinks:   []string{v.CVELink},
						Title:      v.Title,
						CVSSScore:  v.CVSSScore,
						CVSSVector: v.CVSSVector,
					})
				}
			}

			mu.Lock()
			results[plugin] = version
			resultsList = append(resultsList, localResultsList...)

			if progress != nil && opts.File == "" {
				progress.Increment()
			}
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()

	if writer != nil {
		writer.WriteResults(target, resultsList)
	}

	DisplayResults(target, results, pluginResult, resultsList, opts, progress)
}
