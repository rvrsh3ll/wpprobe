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
	"reflect"
	"sort"
	"testing"
)

func TestLoadPluginEndpointsFromData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "Valid JSON data",
			data: []byte(`{"plugin1": ["/endpoint1", "/endpoint2"], "plugin2": ["/endpoint3"]}`),
			want: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2"},
				"plugin2": {"/endpoint3"},
			},
			wantErr: false,
		},
		{
			name:    "Invalid JSON data",
			data:    []byte(`{"plugin1": ["/endpoint1", "/endpoint2",]}`),
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name:    "Empty data",
			data:    []byte(``),
			want:    map[string][]string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPluginEndpointsFromData(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPluginEndpointsFromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPluginEndpointsFromData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func sortDetectionResult(result *PluginDetectionResult) {
	sort.Strings(result.Detected)

	for _, matches := range result.Matches {
		sort.Strings(matches)
	}
}

func TestDetectPlugins(t *testing.T) {
	tests := []struct {
		name              string
		detectedEndpoints []string
		pluginEndpoints   map[string][]string
		want              PluginDetectionResult
	}{
		{
			name: "Detect single plugin",
			detectedEndpoints: []string{
				"/endpoint1", "/endpoint2",
			},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2", "/endpoint3"},
			},
			want: PluginDetectionResult{
				Scores:     map[string]int{"plugin1": 2},
				Confidence: map[string]float64{"plugin1": 66.66666666666666},
				Ambiguity:  map[string]bool{},
				Detected:   []string{"plugin1"},
				Matches:    map[string][]string{"plugin1": {"plugin1"}},
			},
		},
		{
			name: "Ambiguous plugins",
			detectedEndpoints: []string{
				"/shared-endpoint",
			},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/shared-endpoint"},
				"plugin2": {"/shared-endpoint"},
			},
			want: PluginDetectionResult{
				Scores:     map[string]int{"plugin1": 1, "plugin2": 1},
				Confidence: map[string]float64{"plugin1": 100.0, "plugin2": 100.0},
				Ambiguity:  map[string]bool{"plugin1": true, "plugin2": true},
				Detected:   []string{"plugin1", "plugin2"},
				Matches: map[string][]string{
					"plugin1": {"plugin1", "plugin2"},
					"plugin2": {"plugin1", "plugin2"},
				},
			},
		},
		{
			name:              "No plugins detected",
			detectedEndpoints: []string{"/unknown-endpoint"},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2"},
			},
			want: PluginDetectionResult{
				Scores:     map[string]int{},
				Confidence: map[string]float64{},
				Ambiguity:  map[string]bool{},
				Detected:   []string{},
				Matches:    map[string][]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectPlugins(tt.detectedEndpoints, tt.pluginEndpoints)

			sortDetectionResult(&got)
			sortDetectionResult(&tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetectPlugins() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
