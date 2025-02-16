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

package utils

import (
	"net/http"
	"os"

	"github.com/fynelabs/selfupdate"
)

const updateURL = "https://github.com/Chocapikk/wpprobe/releases/latest/download/wpprobe-{{.OS}}-{{.Arch}}{{.Ext}}"

func AutoUpdate() error {
	logger.Info("Downloading WPProbe update...")

	resp, err := http.Get(updateURL)
	if err != nil {
		logger.Error("Failed to download update: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	err = selfupdate.Apply(resp.Body, selfupdate.Options{})
	if err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			logger.Error("Failed to rollback from bad update: " + rerr.Error())
		} else {
			logger.Warning("Update failed but rollback was successful.")
		}
		return err
	}

	logger.Success("Update successful! Restart WPProbe to use the new version.")
	os.Exit(0)
	return nil
}
