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
	"time"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/goccy/go-json"
)

func FetchEndpoints(target string) []string {
	httpClient := utils.NewHTTPClient(10 * time.Second)

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
