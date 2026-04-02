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

	"github.com/deepfence/package-scanner/utils"
)

const (
	HostMountDir   = "/fenced/mnt/host"
	registryPrefix = "registry:"
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

func RunSyftOnChunkDir(chunkName string, mountRoot string, outputDir string, index, total int) error {

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
	fmt.Printf("\n🔍 Running: syft %s\n", strings.Join(args, " "))

	cmd := exec.Command("syft", args...)
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

func syftBuildArgs(config *utils.Config, syftArgs []string, syftEnv []string) ([]string, []string) {
	if config.ScanType != "" && config.ScanType != "all" {
		isRegistry := config.RegistryID != "" && config.NodeType == utils.NodeTypeImage
		syftArgs = append(syftArgs, buildCatalogersArg(config.ScanType, isRegistry)...)
	}

	if config.IsRegistry {
		if !strings.HasPrefix(syftArgs[1], registryPrefix) {
			syftArgs[1] = registryPrefix + syftArgs[1]
		}
	} else {
		syftArgs[1] = strings.ReplaceAll(syftArgs[1], registryPrefix, "")
	}

	if config.RegistryID != "" && config.NodeType == utils.NodeTypeImage {
		if config.RegistryCreds.AuthFilePath != "" {
			syftEnv = append(syftEnv, fmt.Sprintf("DOCKER_CONFIG=%s", config.RegistryCreds.AuthFilePath))
		}
		if config.RegistryCreds.SkipTLSVerify {
			syftEnv = append(syftEnv, fmt.Sprintf("SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=%s", "true"))
		}
		if config.RegistryCreds.UseHTTP {
			syftEnv = append(syftEnv, fmt.Sprintf("SYFT_REGISTRY_INSECURE_USE_HTTP=%s", "true"))
		}
	}

	return syftArgs, syftEnv
}
func buildCatalogersArg(scanType string, isRegistry bool) []string {
	syftArgs := []string{}
	scanTypes := strings.Split(scanType, ",")
	for _, s := range scanTypes {
		switch s {
		case utils.ScanTypeBase:
			syftArgs = append(syftArgs, "--catalogers", "dpkgdb-cataloger", "--catalogers", "rpm-db-cataloger", "--catalogers", "rpm-file-cataloger", "--catalogers", "apkdb-cataloger", "--catalogers", "alpmdb-cataloger", "--catalogers", "linux-kernel-cataloger")
		case utils.ScanTypeRuby:
			syftArgs = append(syftArgs, "--catalogers", "ruby-gemfile-cataloger", "--catalogers", "ruby-gemspec-cataloger")
		case utils.ScanTypePython:
			syftArgs = append(syftArgs, "--catalogers", "python-index-cataloger", "--catalogers", "python-package-cataloger")
		case utils.ScanTypeJavaScript:
			syftArgs = append(syftArgs, "--catalogers", "javascript-lock-cataloger", "--catalogers", "javascript-package-cataloger")
		case utils.ScanTypePhp:
			syftArgs = append(syftArgs, "--catalogers", "php-composer-installed-cataloger", "--catalogers", "php-composer-lock-cataloger")
		case utils.ScanTypeGolang:
			syftArgs = append(syftArgs, "--catalogers", "go-mod-file-cataloger")
		case utils.ScanTypeGolangBinary:
			syftArgs = append(syftArgs, "--catalogers", "go-module-binary-cataloger")
		case utils.ScanTypeJava:
			syftArgs = append(syftArgs, "--catalogers", "java-cataloger", "--catalogers", "java-gradle-lockfile-cataloger", "--catalogers", "java-pom-cataloger")
		case utils.ScanTypeRust:
			syftArgs = append(syftArgs, "--catalogers", "rust-cargo-lock-cataloger")
		case utils.ScanTypeRustBinary:
			syftArgs = append(syftArgs, "--catalogers", "cargo-auditable-binary-cataloger")
		case utils.ScanTypeDotnet:
			syftArgs = append(syftArgs, "--catalogers", "dotnet-deps-cataloger")
		}
	}
	return syftArgs
}

// ---------------- MAIN ----------------
func RunSyftProcess(cfg *utils.Config) error {
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

			if err := RunSyftOnChunkDir(name, mountRoot, outputDir, idx+1, totalChunks); err != nil {
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
