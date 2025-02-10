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

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)

var (
	urlStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF"))
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFA500"))
	pluginStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00BFFF"))
	noVulnStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00"))
	noVersionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#808080"))
	criticalStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0000"))
	highStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4500"))
	mediumStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFA500"))
	lowStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFF00"))
	separator      = strings.Repeat("═", 60)
)

type VulnCategories struct {
	Critical []string
	High     []string
	Medium   []string
	Low      []string
}

func DisplayResults(target string, detectedPlugins map[string]string, pluginMatches map[string]int, pluginConfidence map[string]float64, pluginAmbiguity map[string]bool, pluginVulns map[string]VulnCategories) {

	vulnSummary := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for _, vulnCategories := range pluginVulns {
		vulnSummary["Critical"] += len(vulnCategories.Critical)
		vulnSummary["High"] += len(vulnCategories.High)
		vulnSummary["Medium"] += len(vulnCategories.Medium)
		vulnSummary["Low"] += len(vulnCategories.Low)
	}

	fmt.Println(titleStyle.Render("\n🔎 ") +
		urlStyle.Render(target) + " " +
		fmt.Sprintf("(%s: %d | %s: %d | %s: %d | %s: %d)",
			criticalStyle.Render("Critical"), vulnSummary["Critical"],
			highStyle.Render("High"), vulnSummary["High"],
			mediumStyle.Render("Medium"), vulnSummary["Medium"],
			lowStyle.Render("Low"), vulnSummary["Low"],
		))
	fmt.Println(separator)

	root := tree.New()

	for _, plugin := range sortedPluginsByConfidence(detectedPlugins, pluginConfidence) {
		version := detectedPlugins[plugin]
		vulnCategories := pluginVulns[plugin]
		confidence := pluginConfidence[plugin]

		pluginColor := getPluginColor(version, vulnCategories)

		pluginLabel := fmt.Sprintf("%s (%s)", plugin, version)
		if pluginAmbiguity[plugin] {
			pluginLabel = fmt.Sprintf("%s (%s) ⚠️ Ambiguity detected!", plugin, version)
		} else if version == "unknown" {
			pluginLabel = fmt.Sprintf("%s (%s) [%.2f%% confidence]", plugin, version, confidence)
		}

		pluginNode := tree.Root(pluginColor.Render(pluginLabel))

		addVulnNode(pluginNode, "Critical", vulnCategories.Critical, criticalStyle)
		addVulnNode(pluginNode, "High", vulnCategories.High, highStyle)
		addVulnNode(pluginNode, "Medium", vulnCategories.Medium, mediumStyle)
		addVulnNode(pluginNode, "Low", vulnCategories.Low, lowStyle)

		root.Child(pluginNode)
	}

	fmt.Println(root.String())
	fmt.Println(separator)
}

func sortedPluginsByConfidence(detectedPlugins map[string]string, pluginConfidence map[string]float64) []string {
	sortedPlugins := make([]string, 0, len(detectedPlugins))
	for plugin := range detectedPlugins {
		sortedPlugins = append(sortedPlugins, plugin)
	}
	sort.Slice(sortedPlugins, func(i, j int) bool {
		return pluginConfidence[sortedPlugins[i]] > pluginConfidence[sortedPlugins[j]]
	})
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
