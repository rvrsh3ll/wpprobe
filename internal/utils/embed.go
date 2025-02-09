package utils

import (
	"embed"
	"fmt"
)

//go:embed files/scanned_plugins.json
var embeddedFiles embed.FS

func GetEmbeddedFile(filename string) ([]byte, error) {
	data, err := embeddedFiles.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to read embedded file: %v", err)
	}
	return data, nil
}
