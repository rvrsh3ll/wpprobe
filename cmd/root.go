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

	"github.com/spf13/cobra"
)

func PrintBanner() {
	banner := `
 __    __  ___  ___           _          
/ / /\ \ \/ _ \/ _ \_ __ ___ | |__   ___ 
\ \/  \/ / /_)/ /_)/ '__/ _ \| '_ \ / _ \
 \  /\  / ___/ ___/| | | (_) | |_) |  __/
  \/  \/\/   \/    |_|  \___/|_.__/ \___|
                                         

Stealthy WordPress Plugin Scanner - By @Chocapikk
`
	fmt.Println(banner)
}

var rootCmd = &cobra.Command{
	Use:   "wpprobe",
	Short: "A fast WordPress plugin enumeration tool",
	Long: `WPProbe is a high-speed WordPress plugin scanner that detects installed plugins 
and checks for known vulnerabilities using the Wordfence database.`,
}

func Execute() {
	PrintBanner()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(updateCmd)
}
