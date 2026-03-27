package syft

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func getDirSize(path string) (int64, error) {
	cmd := exec.Command("du", "-sb", path)

	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, fmt.Errorf("failed to parse du output")
	}

	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, err
	}

	return int64(size), nil
}

func makeTempDir() (string, error) {
	return os.MkdirTemp("", "syft-")
}

func getNfsMountsDirs() []string {
	cmdOutput, err := exec.Command("findmnt", "-l", "-t", "nfs4,tmpfs", "-n", "--output=TARGET").CombinedOutput()
	if err != nil {
		return nil
	}
	dirs := strings.Split(string(cmdOutput), "\n")
	var mountDirs []string
	for _, i := range dirs {
		if strings.TrimSpace(i) != "" {
			mountDirs = append(mountDirs, i)
		}
	}
	return mountDirs
}

func getAllHostFilesAndSymlink(dir, tmpDir string) error {
	// Use -maxdepth 1 to list files only in this directory (not subdirs)
	fmt.Println("tmpDir", tmpDir)
	cmd := exec.Command("find", dir, "-maxdepth", "1", "-type", "f", "-exec", "ln", "-sf", "{}", tmpDir+"/"+"{}", ";")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("find command failed: %w", err)
	}

	// Make directory into tempDir and Copy files for /usr/lib/os-release to tempDir
	// src := filepath.Join(dir, "usr", "lib", "os-release")
	// dst := filepath.Join(tmpDir, "usr", "lib", "os-release")
	src := filepath.Join(dir, "etc", "os-release")
	dst := filepath.Join(tmpDir, "os-release")

	// Make sure destination folder exists
	err = os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return err
	}

	err = copyFile(src, dst)
	if err != nil {
		return err
	}

	return nil
}

// copyFile copies src file to dst
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

// chunkDirs splits dirs slice into n chunks (last chunk may be smaller)
func chunkDirs(dirs []string, n int) [][]string {
	var chunks [][]string
	chunkSize := (len(dirs) + n - 1) / n
	for i := 0; i < len(dirs); i += chunkSize {
		end := i + chunkSize
		if end > len(dirs) {
			end = len(dirs)
		}
		chunks = append(chunks, dirs[i:end])
	}
	return chunks
}

func getIncludeDirs(baseDir string, excludeDirs []string) ([]string, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, d := range excludeDirs {
		excludeMap[strings.TrimPrefix(d, "/")] = true // normalize exclude dirs without leading slash
	}

	var includeDirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			name := entry.Name()
			if !excludeMap[name] {
				includeDirs = append(includeDirs, name)
			}
		}
	}
	return includeDirs, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getFirstPathSegment(p, srcDir string) string {
	if strings.HasPrefix(p, srcDir) {
		p = strings.TrimPrefix(p, srcDir)
	}

	trimmed := strings.TrimPrefix(p, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func getExcludeDirs(source string) []string {
	var allExcludeDirs []string

	addWithSource := func(paths []string) {
		for _, p := range paths {
			var fullPath string
			if strings.HasPrefix(p, source) {
				fullPath = p + "/**"
			} else {
				fullPath = path.Clean(path.Join(source, p)) + "/**"
			}
			allExcludeDirs = append(allExcludeDirs, fullPath)
		}
	}

	addWithSource(varExcludeDirs)
	addWithSource(homeExcludeDirs)
	addWithSource(linuxExcludeDirs)
	addWithSource(mntDirs)

	return allExcludeDirs
}

func trimFirstDir(path string) string {
	path = strings.TrimPrefix(path, "/")
	// Split only into two parts: first dir + the rest
	parts := strings.SplitN(path, "/", 2)

	// If we have more than one segment, return everything after the first
	if len(parts) == 2 {
		return parts[1]
	}
	// Otherwise, just return the single segment
	return parts[0]
}
