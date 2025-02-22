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
	"testing"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)

func TestDisplayResults(t *testing.T) {
	type args struct {
		target          string
		detectedPlugins map[string]string
		pluginResult    PluginDetectionResult
		resultsList     []utils.PluginEntry
		opts            ScanOptions
		progress        *utils.ProgressManager
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "BasicDisplay",
			args: args{
				target: "http://example.com",
				detectedPlugins: map[string]string{
					"example-plugin": "1.0",
				},
				pluginResult: PluginDetectionResult{
					Confidence: map[string]float64{"example-plugin": 90.0},
					Ambiguity:  map[string]bool{"example-plugin": false},
				},
				resultsList: []utils.PluginEntry{
					{
						Plugin:   "example-plugin",
						Version:  "1.0",
						Severity: "high",
						CVEs:     []string{"CVE-2023-1234"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DisplayResults(
				tt.args.target,
				tt.args.detectedPlugins,
				tt.args.pluginResult,
				tt.args.resultsList,
				tt.args.opts,
				tt.args.progress,
			)
		})
	}
}

func Test_appendVuln(t *testing.T) {
	type args struct {
		categories *VulnCategories
		severity   string
		cves       []string
	}
	tests := []struct {
		name string
		args args
		want VulnCategories
	}{
		{
			name: "AddCritical",
			args: args{
				categories: &VulnCategories{},
				severity:   "Critical",
				cves:       []string{"CVE-2023-1111"},
			},
			want: VulnCategories{
				Critical: []string{"CVE-2023-1111"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appendVuln(tt.args.categories, tt.args.severity, tt.args.cves)
			if !reflect.DeepEqual(*tt.args.categories, tt.want) {
				t.Errorf("appendVuln() = %v, want %v", *tt.args.categories, tt.want)
			}
		})
	}
}

func Test_formatPluginLabel(t *testing.T) {
	type args struct {
		plugin     string
		version    string
		confidence float64
		ambiguous  bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "KnownVersion",
			args: args{"plugin", "1.0", 90.0, false},
			want: "plugin (1.0)",
		},
		{
			name: "UnknownVersion",
			args: args{"plugin", "unknown", 75.0, false},
			want: "plugin (unknown) [75.00% confidence]",
		},
		{
			name: "Ambiguous",
			args: args{"plugin", "1.0", 90.0, true},
			want: "plugin (1.0) ⚠️",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPluginLabel(tt.args.plugin, tt.args.version, tt.args.confidence, tt.args.ambiguous); got != tt.want {
				t.Errorf("formatPluginLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_addAllVulnNodes(t *testing.T) {
	type args struct {
		pluginNode     *tree.Tree
		vulnCategories VulnCategories
		vulnStyles     map[string]lipgloss.Style
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddVulnNodes",
			args: args{
				pluginNode: tree.Root("plugin"),
				vulnCategories: VulnCategories{
					Critical: []string{"CVE-2023-1111"},
					High:     []string{"CVE-2023-2222"},
				},
				vulnStyles: map[string]lipgloss.Style{
					"Critical": lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
					"High":     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11")),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addAllVulnNodes(tt.args.pluginNode, tt.args.vulnCategories, tt.args.vulnStyles)
		})
	}
}

func Test_sortedPluginsByConfidence(t *testing.T) {
	type args struct {
		detectedPlugins  map[string]string
		pluginConfidence map[string]float64
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "SortByConfidence",
			args: args{
				detectedPlugins: map[string]string{
					"pluginA": "1.0",
					"pluginB": "unknown",
					"pluginC": "2.0",
				},
				pluginConfidence: map[string]float64{
					"pluginA": 90.0,
					"pluginB": 60.0,
					"pluginC": 80.0,
				},
			},
			want: []string{"pluginB", "pluginA", "pluginC"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sortedPluginsByConfidence(tt.args.detectedPlugins, tt.args.pluginConfidence); !reflect.DeepEqual(
				got,
				tt.want,
			) {
				t.Errorf("sortedPluginsByConfidence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPluginColor(t *testing.T) {
	type args struct {
		version        string
		vulnCategories VulnCategories
	}
	tests := []struct {
		name string
		args args
		want lipgloss.Style
	}{
		{
			name: "CriticalVuln",
			args: args{
				version: "1.0",
				vulnCategories: VulnCategories{
					Critical: []string{"CVE-2023-1111"},
				},
			},
			want: criticalStyle,
		},
		{
			name: "NoVuln",
			args: args{
				version:        "1.0",
				vulnCategories: VulnCategories{},
			},
			want: noVulnStyle,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPluginColor(tt.args.version, tt.args.vulnCategories)
			if got.Render("test") != tt.want.Render("test") {
				t.Errorf(
					"getPluginColor() = %v, want %v",
					got.Render("test"),
					tt.want.Render("test"),
				)
			}
		})
	}
}

func Test_cveCompare(t *testing.T) {
	type args struct {
		cve1 string
		cve2 string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "OlderYear",
			args: args{"CVE-2020-1234", "CVE-2023-1234"},
			want: true,
		},
		{
			name: "SameYearLowerID",
			args: args{"CVE-2023-1234", "CVE-2023-5678"},
			want: true,
		},
		{
			name: "SameYearHigherID",
			args: args{"CVE-2023-9999", "CVE-2023-1234"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cveCompare(tt.args.cve1, tt.args.cve2); got != tt.want {
				t.Errorf("cveCompare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_addVulnNode(t *testing.T) {
	type args struct {
		parent   *tree.Tree
		severity string
		vulns    []string
		style    lipgloss.Style
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddVulnNode",
			args: args{
				parent:   tree.Root("Plugin"),
				severity: "Critical",
				vulns:    []string{"CVE-2023-1234", "CVE-2023-5678"},
				style:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addVulnNode(tt.args.parent, tt.args.severity, tt.args.vulns, tt.args.style)
		})
	}
}
