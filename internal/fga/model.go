package fga

import (
	_ "embed"
	"os"
	"path/filepath"
)

// modelDSL is the authorization model DSL, embedded at build time so
// the binary can bootstrap a fresh OpenFGA store without shipping the
// file separately.
//
// To keep the DSL as the single source of truth in migrations/fga/ (so
// it's findable alongside the Postgres migrations), we embed a symlink-
// like copy here via go:embed. The canonical file is in
// migrations/fga/model.fga; this Go file re-exports it.
//
//go:embed model.fga
var modelDSL string

// ModelDSL returns the authorization model DSL as a string. Consumed
// by `idp fga init` to upload to OpenFGA.
func ModelDSL() string {
	return modelDSL
}

// LoadModelFromFile reads a DSL file from disk. Fallback for dev
// iteration when you want to edit the model and re-upload without
// rebuilding the binary.
func LoadModelFromFile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
