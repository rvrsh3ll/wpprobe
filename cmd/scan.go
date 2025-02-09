package cmd

import (
	"fmt"
	"github.com/Chocapikk/wpprobe/internal/scanner"
	"os"

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
