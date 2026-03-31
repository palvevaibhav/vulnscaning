package sbom

import (
	"encoding/json"
	"fmt"
	"github.com/Jeffail/tunny"
	"context"
	"github.com/deepfence/package-scanner/sbom/syft"
	"github.com/deepfence/package-scanner/utils"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
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

	// Map full utils.Config into workflow.Config
	// cfg := &workflow.Config{
	// 	RootPath:        r.Source,
	// 	OutputFile:      r.Output,              // existing Output
	// 	Workers:         8,                     // default, can be mapped from r if needed
	// 	ChunkSizeGB:     1,                     // default chunk size
	// 	MountRoot:       "/tmp/mounted_chunks", // default mount path
	// 	MountWorkers:    8,                     // default
	// 	SyftOutputDir:   "./sbom-output",
	// 	FinalOutputFile: r.Output, // you can also customize final output

	// 	// Preserve all Deepfence/management info
	// 	DeepfenceKey:          r.DeepfenceKey,
	// 	ConsoleURL:            r.ConsoleURL,
	// 	ConsolePort:           r.ConsolePort,
	// 	ScanType:              r.ScanType,
	// 	VulnerabilityScan:     r.VulnerabilityScan,
	// 	ScanID:                r.ScanID,
	// 	NodeType:              r.NodeType,
	// 	NodeID:                r.NodeID,
	// 	HostName:              r.HostName,
	// 	ImageID:               r.ImageID,
	// 	ContainerName:         r.ContainerName,
	// 	KubernetesClusterName: r.KubernetesClusterName,
	// 	RegistryID:            r.RegistryID,
	// }

	start := time.Now()
	log.Infof("Starting chunked Syft scan for Source: %s, NodeID: %s", r.Source, r.NodeID)

	ctx := context.Background()
	sbom, err := syft.GenerateSBOM(ctx, r)
	if err != nil {
		log.Errorf("Error running chunked Syft: %s", err)
		return false
	}

	err = os.WriteFile(r.Output, sbom, 0644)
	if err != nil {
		log.Errorf("Error writing SBOM to file: %s", err)
		return false
	}

	duration := time.Since(start)
	log.Infof("✅ Chunked Syft scan completed for Source: %s, NodeID: %s in %v", r.Source, r.NodeID, duration)
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
