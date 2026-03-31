package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"os/exec"
	"strconv"
	"strings"
	"fmt"

	"github.com/deepfence/package-scanner/utils"
)

const MaxDirSize int64 = 50 * 1024 * 1024 * 1024 // 50GB

func getDirSize(path string) (int64, error) {
	cmd := exec.Command("du", "-sb", path)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(out))

	return strconv.ParseInt(fields[0], 10, 64)
}

func processDir(ctx context.Context, dir string, root string, tmpRoot string, config utils.Config) (string, error) {
	size, err := getDirSize(dir)
	if err != nil {
		return "", err
	}

	// compute relative path
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", err
	}
	fmt.Printf("Calculating size for directory: %s, size: %d bytes\n", dir, size)
	// create temp directory for this parent
	tmpDir := filepath.Join(tmpRoot, rel)
	err = os.MkdirAll(tmpDir, 0755)
	if err != nil {
		return "", err
	}


	output := filepath.Join(tmpDir, utils.RandomString(10)+".json")

	// CASE: < 50GB
	if size < MaxDirSize {
		fmt.Printf("Processing directory %s (size: %d bytes) with Syft\n", dir, size)
		// runSyft(ctx, config, []string{"packages", "dir:" + tmpDir, "-o", "json=" + output, "-q"}, []string{}, 0, []error{nil}, output)
		// err := runSBOM(ctx, dir, output, config)
		return output, err
	}

	// CASE: > 50GB
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var sbomFiles []string
	var errs []error

	for _, e := range entries {

		if !e.IsDir() {
			continue
		}

		subPath := filepath.Join(dir, e.Name())

		wg.Add(1)

		go func(p string) {
			defer wg.Done()

			file, err := processDir(ctx, p, root, tmpRoot, config)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}

			mu.Lock()
			sbomFiles = append(sbomFiles, file)
			mu.Unlock()

		}(subPath)
	}

	wg.Wait()

	if len(errs) > 0 {
		return "", errs[0]
	}

	// err = mergeSBOMStream(sbomFiles, output)
	// if err != nil {
	// 	return "", err
	// }

	// cleanupSBOM(sbomFiles)

	return output, nil
}

func main()  {
	config := utils.Config{} // use default config for test
	rootDir := "/"
	tmpRoot := "/tmp"
	ctx := context.Background()
	result, err := processDir(ctx, rootDir, rootDir, tmpRoot, config)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    fmt.Println("Result SBOM file:", result)
}
