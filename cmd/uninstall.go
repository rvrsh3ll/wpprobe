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
	"os"
	"path/filepath"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/spf13/cobra"
)

var getUserConfigDirFunc = os.UserConfigDir
var getExecutableFunc = os.Executable

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstalls WPProbe and removes all related files and the binary",
	Run: func(cmd *cobra.Command, args []string) {
		uninstall()
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}

func uninstall() {
	configDir := mustGetUserConfigDir(utils.DefaultLogger)
	removeDir(filepath.Join(configDir, "wpprobe"), "WPProbe configuration", utils.DefaultLogger)

	execPath := mustGetExecutable(utils.DefaultLogger)
	removeFile(execPath, "WPProbe binary", utils.DefaultLogger)

	utils.DefaultLogger.Success("WPProbe has been fully uninstalled.")
}

func removeDir(path, description string, DefaultLogger *utils.Logger) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		utils.DefaultLogger.Warning(description + " not found. Nothing to remove.")
		return
	}
	mustErr(os.RemoveAll(path), "Failed to remove "+description, utils.DefaultLogger)
}

func removeFile(path, description string, DefaultLogger *utils.Logger) {
	mustErr(os.Remove(path), "Failed to remove "+description, utils.DefaultLogger)
}

func mustGetUserConfigDir(DefaultLogger *utils.Logger) string {
	dir, err := getUserConfigDirFunc()
	if err != nil {
		utils.DefaultLogger.Error("Failed to get user config directory: " + err.Error())
		os.Exit(1)
	}
	return dir
}

func mustGetExecutable(DefaultLogger *utils.Logger) string {
	execPath, err := getExecutableFunc()
	if err != nil {
		utils.DefaultLogger.Error("Failed to get executable path: " + err.Error())
		os.Exit(1)
	}
	return execPath
}

func mustErr(err error, msg string, DefaultLogger *utils.Logger) {
	if err != nil {
		utils.DefaultLogger.Error(msg + ": " + err.Error())
		os.Exit(1)
	}
}
