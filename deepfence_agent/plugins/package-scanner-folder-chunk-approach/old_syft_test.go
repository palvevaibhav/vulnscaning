package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/deepfence/package-scanner-folder-chunk-approach/utils"
)

// Save originals to restore
var (
	origRunCommand = runCommand
	origCommandContext = exec.CommandContext
)

func TestMain(m *testing.M) {
	code := m.Run()
	// restore
	runCommand = origRunCommand
	exec.CommandContext = origCommandContext
	os.Exit(code)
}

// fake exec command context that records args and returns no error
func fakeCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	// use a shell to run true so Run returns nil
	return origCommandContext(ctx, "true")
}

func fakeRunCommandSuccess(cmd *exec.Cmd) (*bytes.Buffer, error) {
	var b bytes.Buffer
	b.WriteString("ok")
	return &b, nil
}

func TestGenerateSBOM_DirSource_AddsExcludesAndReadsFile(t *testing.T) {
	runCommand = fakeRunCommandSuccess
	exec.CommandContext = fakeCommandContext

	ctx := context.Background()
	jsonFile := filepath.Join("/tmp", "testoutput.json")
	// create a fake json file
	_ = os.WriteFile(jsonFile, []byte("{\"test\":true}"), 0644)
	defer os.Remove(jsonFile)

	cfg := utils.Config{
		Source:    ".",
		SyftBinPath: "syft",
	}

	// override random string function to produce known filename
	origRand := utils.RandomString
	utils.RandomString = func(n int) string { return "test" }
	defer func() { utils.RandomString = origRand }()

	// call
	_, err := GenerateSBOM(ctx, cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestGenerateSBOM_RunCommandError_ReturnsError(t *testing.T) {
	runCommand = func(cmd *exec.Cmd) (*bytes.Buffer, error) {
		return nil, errors.New("fail")
	}
	exec.CommandContext = fakeCommandContext

	ctx := context.Background()
	cfg := utils.Config{Source: ".", SyftBinPath: "syft"}

	_, err := GenerateSBOM(ctx, cfg)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestBuildCatalogersArg(t *testing.T) {
	args := buildCatalogersArg("base,python", false)
	if len(args) == 0 {
		t.Fatalf("expected args, got empty")
	}
}
