package workflow
import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==============================
// Data Structures
// ==============================
type FileEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type ChunkData map[string][]FileEntry

type MountJob struct {
	Src       string
	Dst       string
	IsDir     bool
	ChunkName string
}

// ==============================
// Globals
// ==============================
var logMu sync.Mutex
var totalJobs int64
var doneJobs int64

// ==============================
// Check if already mounted
// ==============================
func isMounted(dst string) bool {
	file, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == dst {
			return true
		}
	}
	return false
}

// ==============================
// Progress Bar (FIXED)
// ==============================
func printProgress() {
	done := atomic.LoadInt64(&doneJobs)
	total := atomic.LoadInt64(&totalJobs)

	if total == 0 {
		return
	}

	percent := float64(done) / float64(total) * 100
	barSize := 30
	filled := int(percent / 100 * float64(barSize))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barSize-filled)

	fmt.Printf("\r📊 Progress: [%s] %.1f%% (%d/%d)", bar, percent, done, total)
}

// ==============================
// Mount with Retry (IMPROVED)
// ==============================
func BindMountWithRetry(src, dst string, isDir bool, retries int) error {

	for i := 1; i <= retries; i++ {

		logMu.Lock()
		fmt.Printf("\n🔗 Mounting: %s → %s (Attempt %d/%d)\n", src, dst, i, retries)
		logMu.Unlock()

		if isMounted(dst) {
			return nil
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}

		// Create mount target
		if isDir {
			if err := os.MkdirAll(dst, 0755); err != nil {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			f, err := os.Create(dst)
			if err != nil {
				return err
			}
			f.Close()
		}

		cmd := exec.Command("mount", "--bind", src, dst)
		out, err := cmd.CombinedOutput()

		if err == nil && isMounted(dst) {
			return nil
		}

		logMu.Lock()
		fmt.Printf("⚠️ Retry error: %s\n", string(out))
		logMu.Unlock()

		_ = os.RemoveAll(dst)
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("failed to mount after %d retries: %s → %s", retries, src, dst)
}

// ==============================
// Worker
// ==============================
func worker(id int, jobs <-chan MountJob, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {

		logMu.Lock()
		fmt.Printf("\n👷 Worker %d | %s → %s\n", id, job.Src, job.Dst)
		logMu.Unlock()

		err := BindMountWithRetry(job.Src, job.Dst, job.IsDir, 3)

		if err != nil {
			logMu.Lock()
			fmt.Printf("❌ [%s] Failed: %v\n", job.ChunkName, err)
			logMu.Unlock()
		} else {
			logMu.Lock()
			fmt.Printf("✅ [%s] Mounted: %s\n", job.ChunkName, job.Src)
			logMu.Unlock()
		}

		atomic.AddInt64(&doneJobs, 1)
		printProgress()
	}
}

// ==============================
// MAIN RUN FUNCTION (FIXED)
// ==============================
func RunMountProcess(cfg *Config) error {

	// Reset counters (IMPORTANT)
	atomic.StoreInt64(&totalJobs, 0)
	atomic.StoreInt64(&doneJobs, 0)

	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		return fmt.Errorf("read json failed: %w", err)
	}

	var chunks ChunkData
	if err := json.Unmarshal(data, &chunks); err != nil {
		return fmt.Errorf("json parse failed: %w", err)
	}

	jobs := make(chan MountJob, 100)
	var wg sync.WaitGroup

	// Count jobs
	for _, files := range chunks {
		atomic.AddInt64(&totalJobs, int64(len(files)))
	}

	// Start workers
	for i := 1; i <= cfg.MountWorkers; i++ {
		wg.Add(1)
		go worker(i, jobs, &wg)
	}

	// Send jobs
	for chunkName, files := range chunks {
		for _, file := range files {

			src := file.Path

			info, err := os.Stat(src)
			if err != nil {
				logMu.Lock()
				fmt.Printf("❌ Skip (not found): %s\n", src)
				logMu.Unlock()
				atomic.AddInt64(&doneJobs, 1)
				continue
			}

			// FIX: Handle absolute paths properly
			cleanSrc := strings.TrimPrefix(src, "/")
			dst := filepath.Join(cfg.MountRoot, chunkName, cleanSrc)

			jobs <- MountJob{
				Src:       src,
				Dst:       dst,
				IsDir:     info.IsDir(),
				ChunkName: chunkName,
			}
		}
	}

	close(jobs)
	wg.Wait()

	fmt.Println("\n\n🎉 All mounts completed!")
	return nil
}
