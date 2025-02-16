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
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/Masterminds/semver"
)

const tagsURL = "https://api.github.com/repos/Chocapikk/wpprobe/tags"

func CheckLatestVersion(currentVersion string) (string, bool) {
	resp, err := http.Get(tagsURL)
	if err != nil {
		return "unknown", false
	}
	defer resp.Body.Close()

	var tags []struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "unknown", false
	}

	if len(tags) == 0 {
		return "unknown", false
	}

	var latestVersion *semver.Version
	for _, tag := range tags {
		tagVersionStr := strings.TrimPrefix(tag.Name, "v")
		tagVersion, err := semver.NewVersion(tagVersionStr)
		if err != nil {
			continue
		}

		if latestVersion == nil || tagVersion.Compare(latestVersion) > 0 {
			latestVersion = tagVersion
		}
	}

	if latestVersion == nil {
		return "unknown", false
	}

	currentSemVer, err := semver.NewVersion(strings.TrimPrefix(currentVersion, "v"))
	if err != nil {
		return latestVersion.String(), false
	}

	return latestVersion.String(), currentSemVer.Compare(latestVersion) >= 0
}

func GetPluginVersion(target, plugin string, threads int) string {
	httpClient := NewHTTPClient(10 * time.Second)
	versionChan := make(chan string, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if version := fetchVersionFromReadme(httpClient, target, plugin); version != "" {
			versionChan <- version
		}
	}()

	go func() {
		defer wg.Done()
		if version := fetchVersionFromStyle(httpClient, target, plugin); version != "" {
			versionChan <- version
		}
	}()

	go func() {
		wg.Wait()
		close(versionChan)
	}()

	for version := range versionChan {
		return version
	}

	return "unknown"
}

func fetchVersionFromReadme(client *HTTPClientManager, target, plugin string) string {
	readmes := []string{"readme.txt", "Readme.txt", "README.txt"}
	var version string

	for _, readmeName := range readmes {
		url := fmt.Sprintf("%s/wp-content/plugins/%s/%s", target, plugin, readmeName)
		version = fetchVersionFromURL(client, url, `(?:Stable tag|Version):\s*([0-9a-zA-Z.-]+)`)
		if version != "" {
			break
		}
	}
	return version
}

func fetchVersionFromStyle(client *HTTPClientManager, target, plugin string) string {
	url := fmt.Sprintf("%s/wp-content/themes/%s/style.css", target, plugin)
	return fetchVersionFromURL(client, url, `Version:\s*([0-9a-zA-Z.-]+)`)
}

func fetchVersionFromURL(client *HTTPClientManager, url, pattern string) string {
	body, err := client.Get(url)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func IsVersionVulnerable(version, fromVersion, toVersion string) bool {
	if version == "" || fromVersion == "" || toVersion == "" {
		return false
	}

	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	from, err := semver.NewVersion(fromVersion)
	if err != nil {
		return false
	}
	to, err := semver.NewVersion(toVersion)
	if err != nil {
		return false
	}

	return v.Compare(from) >= 0 && v.Compare(to) <= 0
}
