package scanner

import (
	"time"

	"encoding/json"
	"github.com/Chocapikk/wpprobe/internal/utils"
)

func FetchEndpoints(target string) []string {
	httpClient := utils.NewHTTPClient(30 * time.Second)

	response, err := httpClient.Get(target + "/?rest_route=/")
	if err != nil {
		return []string{}
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonData); err != nil {
		return []string{}
	}

	routes, ok := jsonData["routes"].(map[string]interface{})
	if !ok {
		return []string{}
	}

	endpoints := make([]string, 0, len(routes))
	for route := range routes {
		endpoints = append(endpoints, route)
	}

	return endpoints
}
