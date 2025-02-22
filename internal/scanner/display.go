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
	"sort"
	"strconv"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	urlStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF"))
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFA500"))
	noVulnStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00"))
	noVersionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#808080"))
	criticalStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0000"))
	highStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4500"))
	mediumStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFA500"))
	lowStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF00"))

	separatorStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FFA500")).
			Padding(0, 2).
			Margin(1, 0)
)

type VulnCategories struct {
	Critical []string
	High     []string
	Medium   []string
	Low      []string
}

func DisplayResults(
	target string,
	detectedPlugins map[string]string,
	pluginResult PluginDetectionResult,
	resultsList []utils.PluginEntry,
	opts ScanOptions,
	progress *utils.ProgressManager,
) {
	vulnTypes := []string{"Critical", "High", "Medium", "Low"}
	vulnStyles := map[string]lipgloss.Style{
		"Critical": criticalStyle,
		"High":     highStyle,
		"Medium":   mediumStyle,
		"Low":      lowStyle,
	}

	vulnSummary := make(map[string]int)
	pluginVulns := make(map[string]VulnCategories)

	for _, entry := range resultsList {
		vulnCategories := pluginVulns[entry.Plugin]
		severity := cases.Title(language.Und, cases.NoLower).String(strings.ToLower(entry.Severity))

		if _, exists := vulnStyles[severity]; exists {
			appendVuln(&vulnCategories, severity, entry.CVEs)
			vulnSummary[severity] += len(entry.CVEs)
		}

		pluginVulns[entry.Plugin] = vulnCategories
	}

	if progress != nil {
		progress.RenderBlank()
	}

	summaryParts := make([]string, len(vulnTypes))
	for i, t := range vulnTypes {
		summaryParts[i] = fmt.Sprintf("%s: %d", vulnStyles[t].Render(t), vulnSummary[t])
	}
	summaryLine := fmt.Sprintf(
		"🔎 %s (%s)",
		urlStyle.Render(target),
		strings.Join(summaryParts, " | "),
	)
	root := tree.Root(titleStyle.Render(summaryLine))

	for _, plugin := range sortedPluginsByConfidence(detectedPlugins, pluginResult.Confidence) {
		version := detectedPlugins[plugin]
		confidence := pluginResult.Confidence[plugin]
		vulnCategories := pluginVulns[plugin]

		pluginLabel := formatPluginLabel(
			plugin,
			version,
			confidence,
			pluginResult.Ambiguity[plugin],
		)
		pluginNode := tree.Root(getPluginColor(version, vulnCategories).Render(pluginLabel))

		addAllVulnNodes(pluginNode, vulnCategories, vulnStyles)

		root.Child(pluginNode)
	}

	if len(pluginResult.Ambiguity) > 0 {
		root.Child(
			tree.Root(
				"⚠️ indicates that multiple plugins share common endpoints; only one of these is likely active.",
			),
		)
	}

	encapsulatedResults := separatorStyle.Render(root.String())
	if progress != nil {
		progress.Bprintln(encapsulatedResults)
	} else {
		fmt.Println(encapsulatedResults)
	}
}

func appendVuln(categories *VulnCategories, severity string, cves []string) {
	switch severity {
	case "Critical":
		categories.Critical = append(categories.Critical, cves...)
	case "High":
		categories.High = append(categories.High, cves...)
	case "Medium":
		categories.Medium = append(categories.Medium, cves...)
	case "Low":
		categories.Low = append(categories.Low, cves...)
	}
}

func formatPluginLabel(plugin, version string, confidence float64, ambiguous bool) string {
	if ambiguous {
		return fmt.Sprintf("%s (%s) ⚠️", plugin, version)
	}
	if version == "unknown" {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence]", plugin, version, confidence)
	}
	return fmt.Sprintf("%s (%s)", plugin, version)
}

func addAllVulnNodes(
	parent *tree.Tree,
	categories VulnCategories,
	vulnStyles map[string]lipgloss.Style,
) {
	vulnTypes := []string{"Critical", "High", "Medium", "Low"}

	for _, severity := range vulnTypes {
		var cves []string

		switch severity {
		case "Critical":
			cves = categories.Critical
		case "High":
			cves = categories.High
		case "Medium":
			cves = categories.Medium
		case "Low":
			cves = categories.Low
		}

		if len(cves) > 0 {
			vulnNode := tree.Root(vulnStyles[severity].Render(severity))

			for i := 0; i < len(cves); i += 4 {
				end := i + 4
				if end > len(cves) {
					end = len(cves)
				}
				vulnNode.Child(strings.Join(cves[i:end], " ⋅ "))
			}

			parent.Child(vulnNode)
		}
	}
}

func sortedPluginsByConfidence(
	detectedPlugins map[string]string,
	pluginConfidence map[string]float64,
) []string {
	type PluginData struct {
		name       string
		confidence float64
		noVersion  bool
		noVuln     bool
	}

	plugins := make([]PluginData, 0, len(detectedPlugins))
	for plugin, version := range detectedPlugins {
		noVersion := version == "unknown"
		plugins = append(plugins, PluginData{
			name:       plugin,
			confidence: pluginConfidence[plugin],
			noVersion:  noVersion,
			noVuln:     true,
		})
	}

	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].noVersion && !plugins[j].noVersion {
			return true
		}
		if !plugins[i].noVersion && plugins[j].noVersion {
			return false
		}
		return plugins[i].confidence > plugins[j].confidence
	})

	sortedPlugins := make([]string, len(plugins))
	for i, p := range plugins {
		sortedPlugins[i] = p.name
	}
	return sortedPlugins
}

func getPluginColor(version string, vulnCategories VulnCategories) lipgloss.Style {
	if version == "unknown" {
		return noVersionStyle
	} else if len(vulnCategories.Critical) > 0 {
		return criticalStyle
	} else if len(vulnCategories.High) > 0 {
		return highStyle
	} else if len(vulnCategories.Medium) > 0 {
		return mediumStyle
	} else if len(vulnCategories.Low) > 0 {
		return lowStyle
	}
	return noVulnStyle
}

func cveCompare(cve1, cve2 string) bool {
	extractCVEData := func(cve string) (int, int) {
		parts := strings.Split(cve, "-")
		if len(parts) != 3 {
			return 0, 0
		}

		year, err1 := strconv.Atoi(parts[1])
		id, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			return 0, 0
		}

		return year, id
	}

	year1, id1 := extractCVEData(cve1)
	year2, id2 := extractCVEData(cve2)

	if year1 != year2 {
		return year1 < year2
	}
	return id1 < id2
}

func addVulnNode(parent *tree.Tree, severity string, vulns []string, style lipgloss.Style) {
	if len(vulns) == 0 {
		return
	}

	sort.SliceStable(vulns, func(i, j int) bool {
		return cveCompare(vulns[i], vulns[j])
	})

	severityNode := tree.Root(style.Render(severity))

	for i := 0; i < len(vulns); i += 4 {
		end := i + 4
		if end > len(vulns) {
			end = len(vulns)
		}
		severityNode.Child(strings.Join(vulns[i:end], " ⋅ "))
	}

	parent.Child(severityNode)
}
