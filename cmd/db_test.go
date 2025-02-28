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
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunUpdateWordfence_Success(t *testing.T) {
	originalFunc := updateWordfenceFunc
	updateWordfenceFunc = func() error { return nil }
	defer func() { updateWordfenceFunc = originalFunc }()

	cmd := &cobra.Command{}
	err := runUpdateWordfence(cmd, []string{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestRunUpdateWordfence_Failure(t *testing.T) {
	originalFunc := updateWordfenceFunc
	updateWordfenceFunc = func() error { return errors.New("mock error") }
	defer func() { updateWordfenceFunc = originalFunc }()

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := runUpdateWordfence(cmd, []string{})
	if err == nil || err.Error() != "mock error" {
		t.Errorf("Expected 'mock error', got %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("mock error")) {
		t.Errorf("Expected error message in output, got: %s", output)
	}
}

func Test_runUpdateWordfence(t *testing.T) {
	type args struct {
		cmd  *cobra.Command
		args []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := runUpdateWordfence(tt.args.cmd, tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("runUpdateWordfence() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
