package workflow

import (
	"os"
	"path/filepath"
	"testing"
)

func writeMockSyft(t *testing.T, dir string) string {
	t.Helper()

	mockPath := filepath.Join(dir, "mock-syft.sh")
	mockScript := "#!/usr/bin/env sh\n" +
		"echo '{\"artifacts\":[{\"name\":\"mock\"}],\"source\":{\"type\":\"directory\"}}'\n"
	if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("write mock syft: %v", err)
	}
	return mockPath
}

func TestRunSyftOnChunkDir_WithMockSyft(t *testing.T) {
	tmp := t.TempDir()
	mountRoot := filepath.Join(tmp, "mount")
	outputDir := filepath.Join(tmp, "out")
	chunkName := "chunk1"

	if err := os.MkdirAll(filepath.Join(mountRoot, chunkName), 0o755); err != nil {
		t.Fatalf("create mount chunk dir: %v", err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}

	mockSyft := writeMockSyft(t, tmp)
	if err := RunSyftOnChunkDir(chunkName, mountRoot, outputDir, mockSyft, 1, 1); err != nil {
		t.Fatalf("RunSyftOnChunkDir failed: %v", err)
	}

	outFile := filepath.Join(outputDir, chunkName+".json")
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}

	if len(data) == 0 {
		t.Fatalf("expected output file to have content")
	}
}

func TestRunSyftProcess_WithMockSyft(t *testing.T) {
	tmp := t.TempDir()
	mountRoot := filepath.Join(tmp, "mount")
	outputDir := filepath.Join(tmp, "sbom-out")
	chunksJSON := filepath.Join(tmp, "chunks.json")

	for _, chunk := range []string{"chunk1", "chunk2"} {
		if err := os.MkdirAll(filepath.Join(mountRoot, chunk), 0o755); err != nil {
			t.Fatalf("create chunk dir %s: %v", chunk, err)
		}
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}

	content := `{
  "chunk1": [{"path":"/tmp/a","size":1}],
  "chunk2": [{"path":"/tmp/b","size":2}]
}`
	if err := os.WriteFile(chunksJSON, []byte(content), 0o644); err != nil {
		t.Fatalf("write chunks json: %v", err)
	}

	cfg := &Config{
		OutputFile:    chunksJSON,
		MountRoot:     mountRoot,
		SyftOutputDir: outputDir,
		SyftBinPath:   writeMockSyft(t, tmp),
		Workers:       2,
	}

	if err := RunSyftProcess(cfg); err != nil {
		t.Fatalf("RunSyftProcess failed: %v", err)
	}

	for _, chunk := range []string{"chunk1", "chunk2"} {
		if _, err := os.Stat(filepath.Join(outputDir, chunk+".json")); err != nil {
			t.Fatalf("missing output for %s: %v", chunk, err)
		}
	}
}
