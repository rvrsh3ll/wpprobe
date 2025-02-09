package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

func LoadPluginEndpointsFromData(data []byte) (map[string][]string, error) {
	pluginEndpoints := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		var pluginData map[string][]string
		if err := json.Unmarshal(scanner.Bytes(), &pluginData); err != nil {
			continue
		}

		for plugin, endpoints := range pluginData {
			pluginEndpoints[plugin] = endpoints
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("❌ Error reading embedded JSONL data: %v", err)
	}

	return pluginEndpoints, nil
}

func DetectPlugins(detectedEndpoints []string, pluginEndpoints map[string][]string) []string {
	var detectedPlugins []string

	for plugin, knownRoutes := range pluginEndpoints {
		if len(knownRoutes) == 0 {
			continue
		}

		matchCount := 0
		for _, knownRoute := range knownRoutes {
			for _, endpoint := range detectedEndpoints {
				if endpoint == knownRoute {
					matchCount++
				}
			}
		}

		threshold := max(1, int(float64(len(knownRoutes))*0.15))
		if matchCount >= threshold {
			detectedPlugins = append(detectedPlugins, plugin)
		}
	}

	return detectedPlugins
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
