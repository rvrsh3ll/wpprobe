package scanner

import (
	"fmt"
	"log"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
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

	detectedPlugins := DetectPlugins(endpoints, pluginEndpoints)
	if len(detectedPlugins) == 0 {
		if !isFileMode {
			fmt.Printf("\n❌ No plugins detected on %s\n", target)
		}
		return
	}

	results := make(map[string]string)
	resultsCSV := make(map[string]map[string]map[string][]string)

	for _, plugin := range detectedPlugins {
		version := "unknown"
		if !noCheckVersion {
			version = GetPluginVersion(target, plugin)
		}

		results[plugin] = version

		vulns := wordfence.GetVulnerabilitiesForPlugin(plugin, version)
		vulnMap := make(map[string][]string)
		for _, v := range vulns {
			vulnMap[v.Severity] = append(vulnMap[v.Severity], v.CVE)
		}

		if _, exists := resultsCSV[plugin]; !exists {
			resultsCSV[plugin] = make(map[string]map[string][]string)
		}
		resultsCSV[plugin][version] = vulnMap
	}

	DisplayResults(target, results)

	if csvWriter != nil {
		csvWriter.WriteResults(target, resultsCSV)
	}
}
