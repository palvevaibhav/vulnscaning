package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------- STRUCT ----------------

type ChunkNodeInfo struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ---------------- EXCLUDED DIRS ----------------

var linuxExcludeDirs = []string{
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
	"/var/lib/crio", "/var/run/containers", "/home/kubernetes/containerized_mounter",
	"/mnt", "/run", "/proc", "/dev", "/boot", "/sys", "/lost+found",
}

var mntDirs = getNfsMountsDirs()

// ---------------- GET NFS MOUNT DIRS ----------------

func getNfsMountsDirs() []string {
	cmdOutput, err := exec.Command(
		"findmnt", "-l", "-t", "nfs4,tmpfs", "-n", "--output=TARGET",
	).CombinedOutput()
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

// ---------------- LOAD JSON ----------------

func LoadChunks(file string) (map[string][]ChunkNodeInfo, error) {
	var data map[string][]ChunkNodeInfo

	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &data)
	return data, err
}

// ---------------- PROGRESS BAR ----------------

func printProgressBar(percent float64) {
	barSize := 30
	filled := int(percent / 100 * float64(barSize))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barSize-filled)

	fmt.Printf("\r📊 Progress: [%s] %.1f%%", bar, percent)
}

// ---------------- RUN SYFT ON CHUNK ----------------

func RunSyftOnChunkDir(chunkName string, mountRoot string, outputDir string, syftBinPath string, index, total int) error {

	start := time.Now()
	chunkPath := filepath.Join(mountRoot, chunkName)

	fmt.Printf("\n🚀 [%d/%d] Scanning %s\n", index, total, chunkPath)

	// ✅ Stop channel
	stop := make(chan struct{})

	// 📊 Progress goroutine
	go func() {
		progress := 0.0
		for {
			select {
			case <-stop:
				return
			default:
				if progress < 90 {
					progress += 2
				}
				printProgressBar(progress)
				time.Sleep(300 * time.Millisecond)
			}
		}
	}()

	// 🔥 Build syft args
	args := []string{"dir:" + chunkPath, "-o", "json"}

	// 🚫 Exclude linux system dirs
	for _, folder := range linuxExcludeDirs {
		relative := strings.TrimPrefix(folder, "/")
		args = append(args, "--exclude", fmt.Sprintf("./%s/**", relative))
	}

	// 🚫 Exclude NFS / tmpfs mount dirs
	for _, folder := range mntDirs {
		relative := strings.TrimPrefix(folder, "/")
		args = append(args, "--exclude", fmt.Sprintf("./%s/**", relative))
	}

	// 🔍 Log full command for debugging
	if strings.TrimSpace(syftBinPath) == "" {
		syftBinPath = "syft"
	}

	fmt.Printf("\n🔍 Running: %s %s\n", syftBinPath, strings.Join(args, " "))

	cmd := exec.Command(syftBinPath, args...)
	out, err := cmd.CombinedOutput()

	// ✅ Stop progress
	close(stop)

	if err != nil {
		return fmt.Errorf("syft error: %s", string(out))
	}

	// Complete progress
	printProgressBar(100)

	// 💾 Save output
	outFile := filepath.Join(outputDir, chunkName+".json")

	err = os.WriteFile(outFile, out, 0644)
	if err != nil {
		return err
	}

	duration := time.Since(start)

	fmt.Printf("\n✅ SBOM created: %s", outFile)
	fmt.Printf("\n⏱️  Time taken: %s\n", duration)

	return nil
}

// ---------------- MAIN ----------------
func RunSyftProcess(cfg *Config) error {
	start := time.Now()
	jsonFile := cfg.OutputFile
	outputDir := cfg.SyftOutputDir
	mountRoot := cfg.MountRoot

	// Create output dir if not exists
	if err := os.MkdirAll(outputDir, os.ModePerm|0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	fmt.Println("📥 Loading chunks JSON...")

	chunks, err := LoadChunks(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to load chunks JSON: %w", err)
	}

	// ---------------- SORT CHUNKS ----------------
	keys := make([]string, 0, len(chunks))
	for k := range chunks {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		ni, _ := strconv.Atoi(strings.TrimPrefix(keys[i], "chunk"))
		nj, _ := strconv.Atoi(strings.TrimPrefix(keys[j], "chunk"))
		return ni < nj
	})

	totalChunks := len(keys)
	fmt.Printf("📦 Total Chunks: %d\n", totalChunks)

	// ---------------- ASYNC PROCESS ----------------
	sem := make(chan struct{}, cfg.Workers) // limit concurrency
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for i, chunkName := range keys {
		wg.Add(1)
		sem <- struct{}{}

		go func(name string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			if len(chunks[name]) == 0 {
				fmt.Println("⚠️  Empty chunk:", name)
				return
			}

			if err := RunSyftOnChunkDir(name, mountRoot, outputDir, cfg.SyftBinPath, idx+1, totalChunks); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(chunkName, i)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("syft scan errors: %v", errs)
	}

	fmt.Printf("\n🎉 All chunks processed successfully in %s!\n", time.Since(start))
	return nil
}
