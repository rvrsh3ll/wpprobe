package scanner

import (
	"fmt"
	"github.com/Chocapikk/wpprobe/internal/utils"
	"regexp"
	"time"
)

func GetPluginVersion(target, plugin string) string {
	httpClient := utils.NewHTTPClient(30 * time.Second)

	version := fetchVersionFromReadme(httpClient, target, plugin)
	if version == "" {
		version = fetchVersionFromStyle(httpClient, target, plugin)
	}
	if version == "" {
		return "unknown"
	}
	return version
}

func fetchVersionFromReadme(client *utils.HTTPClientManager, target, plugin string) string {
	url := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", target, plugin)
	return fetchVersionFromURL(client, url, `(?:Stable tag|Version):\s*([0-9a-zA-Z.-]+)`)
}

func fetchVersionFromStyle(client *utils.HTTPClientManager, target, plugin string) string {
	url := fmt.Sprintf("%s/wp-content/themes/%s/style.css", target, plugin)
	return fetchVersionFromURL(client, url, `Version:\s*([0-9a-zA-Z.-]+)`)
}

func fetchVersionFromURL(client *utils.HTTPClientManager, url, pattern string) string {
	body, err := client.Get(url)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
