package cmd

import (
	"github.com/Chocapikk/wpprobe/internal/wordfence"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the Wordfence vulnerability database",
	Long:  "Fetches the latest Wordfence vulnerability database and updates the local JSON file.",
	Run: func(cmd *cobra.Command, args []string) {
		wordfence.UpdateWordfence()
	},
}
