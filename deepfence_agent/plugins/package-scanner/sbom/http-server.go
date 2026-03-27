package sbom

import (
	"encoding/json"
	"fmt"
	"github.com/Jeffail/tunny"
	"github.com/deepfence/package-scanner/internal/workflow"
	"github.com/deepfence/package-scanner/utils"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	scanConcurrency       int
	managementConsoleURL  string
	managementConsolePort string
	workerPool            *tunny.Pool
)

const DefaultPackageScanConcurrency = 5 // Default concurrency for processing registry messages, can be overridden by setting PACKAGE_SCAN_CONCURRENCY env variable

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("PACKAGE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = DefaultPackageScanConcurrency
	}
	workerPool = tunny.NewFunc(scanConcurrency, processRegistryMessage)
	managementConsoleURL = os.Getenv("MGMT_CONSOLE_URL")
	managementConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
	if managementConsolePort == "" {
		managementConsolePort = "443"
	}
}

func RunHTTPServer(config utils.Config) error {
	if config.Port == "" {
		return fmt.Errorf("http-server mode requires port to be set")
	}
	http.HandleFunc("/registry", registryHandler)

	log.Infof("Starting server at port %s", config.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil); err != nil {
		return err
	}
	return nil
}

func processRegistryMessage(rInterface interface{}) interface{} {
	r, ok := rInterface.(utils.Config)
	if !ok {
		log.Error("Error processing input config")
		return false
	}

	source := strings.TrimPrefix(r.Source, "dir:")
	if source == "" {
		log.Error("empty source path for chunk workflow")
		return false
	}

	scanRef := r.ScanID
	if scanRef == "" {
		scanRef = utils.RandomString(12)
	}
	workDir := filepath.Join(os.TempDir(), "package-scanner-chunks", scanRef)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		log.Errorf("failed to create workflow work dir %s: %v", workDir, err)
		return false
	}

	outputFile := filepath.Join(workDir, "chunks.json")
	finalOutputFile := r.Output
	if finalOutputFile == "" {
		finalOutputFile = filepath.Join(workDir, "final-sbom.json")
	}

	// Map full utils.Config into workflow.Config
	cfg := &workflow.Config{
		RootPath:        source,
		OutputFile:      outputFile,
		Workers:         getIntEnv("PACKAGE_SCAN_WORKERS", 8),
		ChunkSizeGB:     getInt64Env("PACKAGE_SCAN_CHUNK_SIZE_GB", 1),
		MountRoot:       filepath.Join(workDir, "mounted_chunks"),
		MountWorkers:    getIntEnv("PACKAGE_SCAN_MOUNT_WORKERS", 8),
		SyftOutputDir:   filepath.Join(workDir, "sbom-output"),
		FinalOutputFile: finalOutputFile,
		SyftBinPath:     r.SyftBinPath,

		// Preserve all Deepfence/management info
		DeepfenceKey:          r.DeepfenceKey,
		ConsoleURL:            r.ConsoleURL,
		ConsolePort:           r.ConsolePort,
		ScanType:              r.ScanType,
		VulnerabilityScan:     r.VulnerabilityScan,
		ScanID:                r.ScanID,
		NodeType:              r.NodeType,
		NodeID:                r.NodeID,
		HostName:              r.HostName,
		ImageID:               r.ImageID,
		ContainerName:         r.ContainerName,
		KubernetesClusterName: r.KubernetesClusterName,
		RegistryID:            r.RegistryID,
	}

	start := time.Now()
	log.Infof("Starting custom workflow for Source: %s, NodeID: %s", r.Source, r.NodeID)

	err := workflow.Run(cfg)
	if err != nil {
		log.Errorf("Error running custom workflow: %s", err)
		return false
	}

	duration := time.Since(start)
	log.Infof("✅ Workflow completed for Source: %s, NodeID: %s in %v", r.Source, r.NodeID, duration)
	return true
}

func getIntEnv(key string, defaultVal int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultVal
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultVal
	}
	return parsed
}

func getInt64Env(key string, defaultVal int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return defaultVal
	}
	return parsed
}

func registryHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(req.Body)
	var config utils.Config
	err := decoder.Decode(&config)
	if err != nil {
		http.Error(w, "Unable to decode input JSON request", http.StatusBadRequest)
		return
	}
	if config.Source == "" {
		config.Source = fmt.Sprintf("registry:%s", config.NodeID)
	}

	go workerPool.Process(config)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Success"))
}
