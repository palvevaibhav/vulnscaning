package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config represents all the config for your workflow
type Config struct {
	RootPath        string
	OutputFile      string
	Workers         int
	ChunkSizeGB     int64
	MountRoot       string
	MountWorkers    int
	SyftOutputDir   string
	FinalOutputFile string

	// Deepfence / registry info
	DeepfenceKey          string
	ConsoleURL            string
	ConsolePort           string
	ScanType              string
	VulnerabilityScan     bool
	ScanID                string
	NodeType              string
	NodeID                string
	HostName              string
	ImageID               string
	ContainerName         string
	KubernetesClusterName string
	RegistryID            string
}

func cleanupTargets(cfg *Config) error {
	fmt.Println("🧹 Cleaning only target paths (with enhanced security)")

	criticalPaths := []string{
		"/", "/bin", "/sbin", "/usr", "/lib", "/lib64",
		"/etc", "/var", "/boot", "/dev", "/proc", "/sys",
	}

	// =========================
	// 🔒 ENHANCED SAFETY CHECK
	// =========================
	isCritical := func(path string) bool {
		abs, err := filepath.Abs(path)
		if err != nil {
			return true // Fail-safe: treat errors as critical
		}

		// NEW: Resolve symlinks to get the real path
		realPath, err := filepath.EvalSymlinks(abs)
		if err != nil {
			// If we can't resolve symlinks, check the path as-is
			realPath = abs
		}

		for _, c := range criticalPaths {
			cAbs, _ := filepath.Abs(c)
			// Check both the provided path and the real path
			if realPath == cAbs || abs == cAbs {
				return true
			}
			if strings.HasPrefix(realPath, cAbs+string(os.PathSeparator)) {
				return true
			}
			if strings.HasPrefix(abs, cAbs+string(os.PathSeparator)) {
				return true
			}
		}
		return false
	}

	// =========================
	// 🔧 FIX PATHS
	// =========================
	absRoot, _ := filepath.Abs(cfg.RootPath)
	absMount, _ := filepath.Abs(cfg.MountRoot)

	// NEW: Also check the real path of mount
	realMount, err := filepath.EvalSymlinks(absMount)
	if err != nil {
		realMount = absMount
	}
	if isCritical(realMount) {
		fmt.Printf("🚫 Skipping critical path (may be symlink): %s → %s\n", absMount, realMount)
		fmt.Println("✅ Cleanup done (with critical path safety)")
		return nil
	}

	absSyft := cfg.SyftOutputDir
	if !filepath.IsAbs(absSyft) {
		absSyft = filepath.Join(absRoot, absSyft)
	}
	absSyft, _ = filepath.Abs(absSyft)

	absOutput := cfg.OutputFile
	if !filepath.IsAbs(absOutput) {
		absOutput = filepath.Join(absRoot, absOutput)
	}
	absOutput, _ = filepath.Abs(absOutput)

	// =========================
	// 📁 ENHANCED CLEAN DIR FUNCTION
	// =========================
	cleanDir := func(dir string) {
		if isCritical(dir) {
			fmt.Printf("🚫 Skipping critical dir: %s\n", dir)
			return
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("⚠️ Cannot read dir: %s\n", dir)
			return
		}

		for _, e := range entries {
			full := filepath.Join(dir, e.Name())

			// =========================
			// NEW: Detect and reject symlinks
			// =========================
			info, err := os.Lstat(full) // Lstat doesn't follow symlinks
			if err != nil {
				fmt.Printf("⚠️ Cannot stat: %s\n", full)
				continue
			}

			// If it's a symlink, skip it or remove just the symlink
			if info.Mode()&os.ModeSymlink != 0 {
				fmt.Printf("⚠️ Skipping symlink: %s\n", full)
				// Optionally remove the symlink itself
				// os.Remove(full)
				// fmt.Println("🗑 Removed symlink:", full)
				continue
			}

			// =========================
			// 🚫 Skip critical paths inside
			// =========================
			if isCritical(full) {
				fmt.Printf("🚫 Skipping critical path: %s\n", full)
				continue
			}

			// =========================
			// ⏭ Skip config.json
			// =========================
			if e.Name() == "config.json" {
				fmt.Println("⏭ Skip config.json:", full)
				continue
			}

			// =========================
			// 📂 Process based on type
			// =========================
			if e.IsDir() {
				os.RemoveAll(full)
				fmt.Println("🗑 Removed dir:", full)
			} else if filepath.Ext(e.Name()) == ".json" {
				// NEW: Extra verification that it's a regular file
				if !info.Mode().IsRegular() {
					fmt.Printf("⚠️ Skipping non-regular file: %s\n", full)
					continue
				}

				f, err := os.OpenFile(full, os.O_WRONLY|os.O_TRUNC, 0644)
				if err == nil {
					f.Close()
					fmt.Println("♻️ Truncated JSON:", full)
				} else {
					fmt.Printf("⚠️ Failed to truncate: %s (%v)\n", full, err)
				}
			} else {
				err := os.Remove(full)
				if err != nil {
					fmt.Printf("⚠️ Failed to remove file: %s (%v)\n", full, err)
				} else {
					fmt.Println("🗑 Removed file:", full)
				}
			}
		}
	}

	// =========================
	// 🚀 APPLY CLEANUP
	// =========================
	cleanDir(absMount)
	cleanDir(absSyft)
	if isCritical(absOutput) {
		fmt.Printf("🚫 Skipping critical output file: %s\n", absOutput)
	} else {
		f, err := os.OpenFile(absOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Printf("⚠️ Failed to truncate output file: %s (%v)\n", absOutput, err)
		} else {
			f.Close()
			fmt.Println("♻️ Output file reset:", absOutput)
		}
	}

	fmt.Println("✅ Cleanup done (with enhanced security)")
	return nil
}

// Run executes your full workflow
func Run(cfg *Config) error {
	fmt.Printf("🚀 Running workflow for NodeID: %s, Source: %s\n", cfg.NodeID, cfg.RootPath)
	done, errCh := RunAsync(cfg)

	select {
	case msg := <-done:
		fmt.Println("🎉 Workflow finished:", msg)
	case err := <-errCh:
		return fmt.Errorf("workflow failed: %v", err)
	case <-time.After(30 * time.Minute):
		return fmt.Errorf("workflow timed out")
	}

	return nil
}

// RunAsync is your existing async workflow function
func RunAsync(cfg *Config) (<-chan string, <-chan error) {
	if cfg.ChunkSizeGB <= 0 {
		cfg.ChunkSizeGB = 1
	}
	maxChunkSize := cfg.ChunkSizeGB * 1024 * 1024 * 1024
	done := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		defer close(errCh)
		if cfg.Workers > 100 {
			cfg.Workers = 100
		}
		if cfg.Workers <= 0 {
			cfg.Workers = 16
		}
		RunImprovedScan(cfg.RootPath, cfg.OutputFile, cfg.Workers, maxChunkSize)
		fmt.Println("\n🔗 Starting Mount")

		if cfg.MountWorkers <= 0 {
			cfg.MountWorkers = 8
		}

		if cfg.MountRoot == "" {
			cfg.MountRoot = "/tmp/mounted_chunks"
		}
		err := RunMountProcess(cfg)
		if err != nil {
			errCh <- err
			return
		}

		if cfg.SyftOutputDir == "" {
			cfg.SyftOutputDir = "./sbom-output"
		}
		fmt.Println("\n🔍 Starting Syft Scan...")
		err = RunSyftProcess(cfg)
		if err != nil {
			errCh <- err
			return
		}
		err = unmountChunkFolders(cfg)
		if err != nil {
			errCh <- err
			return
		}
		err = combineSBOMFiles(cfg)
		if err != nil {
			errCh <- err
			return
		}
		err = cleanupTargets(cfg)
		if err != nil {
			errCh <- err
			return
		}

		done <- "SUCCESS"
	}()

	return done, errCh
}
