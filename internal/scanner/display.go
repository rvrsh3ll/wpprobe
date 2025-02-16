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
	"strings"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
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
	pluginVulns map[string]VulnCategories,
	opts ScanOptions,
	progress *utils.ProgressManager,
) {
	vulnTypes := []string{"Critical", "High", "Medium", "Low"}
	vulnStyles := []lipgloss.Style{criticalStyle, highStyle, mediumStyle, lowStyle}
	vulnSummary := map[string]int{}

	for _, t := range vulnTypes {
		vulnSummary[t] = 0
	}
	for _, cat := range pluginVulns {
		vulnSummary["Critical"] += len(cat.Critical)
		vulnSummary["High"] += len(cat.High)
		vulnSummary["Medium"] += len(cat.Medium)
		vulnSummary["Low"] += len(cat.Low)
	}

	if progress != nil {
		progress.RenderBlank()
	}

	var summaryParts []string
	for i, t := range vulnTypes {
		summaryParts = append(
			summaryParts,
			fmt.Sprintf("%s: %d", vulnStyles[i].Render(t), vulnSummary[t]),
		)
	}
	summaryLine := fmt.Sprintf(
		"🔎 %s (%s)",
		urlStyle.Render(target),
		strings.Join(summaryParts, " | "),
	)
	root := tree.Root(titleStyle.Render(summaryLine))

	for _, plugin := range sortedPluginsByConfidence(detectedPlugins, pluginResult.Confidence) {
		version := detectedPlugins[plugin]
		vulnCategories := pluginVulns[plugin]
		confidence := pluginResult.Confidence[plugin]
		pluginColor := getPluginColor(version, vulnCategories)
		pluginLabel := fmt.Sprintf("%s (%s)", plugin, version)
		if pluginResult.Ambiguity[plugin] {
			pluginLabel = fmt.Sprintf("%s (%s) ⚠️", plugin, version)
		} else if version == "unknown" {
			pluginLabel = fmt.Sprintf("%s (%s) [%.2f%% confidence]", plugin, version, confidence)
		}

		pluginNode := tree.Root(pluginColor.Render(pluginLabel))

		vulnData := []struct {
			Category string
			Data     []string
			Style    lipgloss.Style
		}{
			{"Critical", vulnCategories.Critical, criticalStyle},
			{"High", vulnCategories.High, highStyle},
			{"Medium", vulnCategories.Medium, mediumStyle},
			{"Low", vulnCategories.Low, lowStyle},
		}

		for _, v := range vulnData {
			addVulnNode(pluginNode, v.Category, v.Data, v.Style)
		}

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

func addVulnNode(parent *tree.Tree, severity string, vulns []string, style lipgloss.Style) {
	if len(vulns) == 0 {
		return
	}

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
