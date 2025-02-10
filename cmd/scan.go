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

package cmd

import (
	"fmt"
	"os"

	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a WordPress site for installed plugins and vulnerabilities",
	Long: `Scans a WordPress site to detect installed plugins 
and check for known vulnerabilities using the Wordfence database.`,
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")
		noCheckVersion, _ := cmd.Flags().GetBool("no-check-version")
		threads, _ := cmd.Flags().GetInt("threads")
		output, _ := cmd.Flags().GetString("output")

		if url == "" && file == "" {
			fmt.Println("❌ You must provide either --url or --file")
			os.Exit(1)
		}

		scanner.ScanTargets(url, file, noCheckVersion, threads, output)
	},
}

func init() {
	scanCmd.Flags().StringP("url", "u", "", "Target URL to scan")
	scanCmd.Flags().StringP("file", "f", "", "File containing a list of URLs")
	scanCmd.Flags().Bool("no-check-version", false, "Skip plugin version checking")
	scanCmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
	scanCmd.Flags().StringP("output", "o", "", "Output file to save results")
}
