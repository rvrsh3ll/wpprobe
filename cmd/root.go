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

	rootCmd.PersistentFlags().StringP("output", "o", "", "Specify output file to save results")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose mode")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(updateCmd)
}
