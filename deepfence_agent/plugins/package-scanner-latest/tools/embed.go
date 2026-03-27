//go:build !cli
// +build !cli

package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft.bin
	SyftBin []byte

	GrypeBin []byte
)
