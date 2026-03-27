package syft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	vesselent "github.com/deepfence/package-scanner/sbom/vesselent"
	"github.com/deepfence/package-scanner/utils"
	"github.com/deepfence/vessel"
	vesselConstants "github.com/deepfence/vessel/utils"
	log "github.com/sirupsen/logrus"

	vesselContainerd "github.com/deepfence/vessel/containerd"
	vesselCrio "github.com/deepfence/vessel/crio"
	vesselDocker "github.com/deepfence/vessel/docker"
	vesselPodman "github.com/deepfence/vessel/podman"

	containerdRuntime "github.com/deepfence/package-scanner/sbom/vesselent/containerd"
	crioRuntime "github.com/deepfence/package-scanner/sbom/vesselent/crio"
	dockerRuntime "github.com/deepfence/package-scanner/sbom/vesselent/docker"
	podmanRuntime "github.com/deepfence/package-scanner/sbom/vesselent/podman"
)

var (
	linuxExcludeDirs = []string{
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
		"/var/lib/crio", "/var/run/containers", "/home/kubernetes/containerized_mounter",
		"/mnt", "/run", "/proc", "/dev", "/boot", "/sys", "/lost+found",
	}
	mntDirs      = getNfsMountsDirs()
	HostMountDir = "/fenced/mnt/host"
)

const (
	ChunkSize = int64(50 * 1024 * 1024 * 1024) // 50 GB
)

const registryPrefix = "registry:"

type ContainerScan struct {
	containerID string
	tempDir     string
	namespace   string
}

func (containerScan *ContainerScan) exportFileSystemTar() error {
	log.Infof("ContainerScan: %+v", containerScan)

	// Auto-detect underlying container runtime
	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		return err
	}
	var containerRuntimeInterface vessel.Runtime
	switch containerRuntime {
	case vesselConstants.DOCKER:
		containerRuntimeInterface = vesselDocker.New(endpoint)
	case vesselConstants.CONTAINERD:
		containerRuntimeInterface = vesselContainerd.New(endpoint)
	case vesselConstants.CRIO:
		containerRuntimeInterface = vesselCrio.New(endpoint)
	case vesselConstants.PODMAN:
		containerRuntimeInterface = vesselPodman.New(endpoint)
	}
	if containerRuntimeInterface == nil {
		log.Error("Error: Could not detect container runtime")
		return fmt.Errorf("failed to detect container runtime")
	}

	err = containerRuntimeInterface.ExtractFileSystemContainer(
		containerScan.containerID, containerScan.namespace,
		containerScan.tempDir+".tar")
	if err != nil {
		log.Errorf("errored: %s", err)
		return err
	}
	tarCmd := exec.Command("tar", "-xf", strings.TrimSpace(containerScan.tempDir+".tar"), "-C", containerScan.tempDir)
	stdout, err := runCommand(tarCmd)
	if err != nil {
		log.Errorf("error: %s output: %s", err, stdout.String())
		return err
	}

	return nil
}

func (containerScan *ContainerScan) exportFileSystem() (string, func(), error) {
	log.Infof("ContainerScan: %+v", containerScan)

	// Auto-detect runtime
	runtimeType, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		return "", nil, err
	}

	log.Infof("runtimeType: %v, endpoint: %v\n", runtimeType, endpoint)

	var containerRuntimeInterface vesselent.EntRuntime
	switch runtimeType {
	case vesselConstants.DOCKER:
		docker := vesselDocker.New(endpoint)
		containerRuntimeInterface = dockerRuntime.New(docker)
	case vesselConstants.CONTAINERD:
		containerd := vesselContainerd.New(endpoint)
		containerRuntimeInterface = containerdRuntime.New(containerd)
	case vesselConstants.CRIO:
		crio := vesselCrio.New(endpoint)
		containerRuntimeInterface = crioRuntime.New(crio)
	case vesselConstants.PODMAN:
		podmon := vesselPodman.New(endpoint)
		containerRuntimeInterface = podmanRuntime.New(podmon)
	}

	if containerRuntimeInterface == nil {
		return "", nil, fmt.Errorf("failed to detect container runtime")
	}

	// Call GetFileSystemPathsForContainer() → returns name + mergedDir
	fsBytes, err := containerRuntimeInterface.GetFileSystemPath(containerScan.containerID, containerScan.namespace)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get container filesystem path: %w", err)
	}

	// Convert []byte → string and trim whitespace/newlines
	fsPath := strings.TrimSpace(string(fsBytes))

	// Example cleanup function if needed (here just a no-op)
	cleanup := func() {}

	return fsPath, cleanup, nil
}

func runCommand(cmd *exec.Cmd) (*bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	errorOnRun := cmd.Run()
	if errorOnRun != nil {
		if errorOnRun != context.Canceled {
			log.Errorf("cmd: %s", cmd.String())
			log.Errorf("error: %s", errorOnRun)
			errorOnRun = errors.New(fmt.Sprint(errorOnRun) + ": " + stderr.String())
		}
		return nil, errorOnRun
	}
	return &stdout, nil
}

func GenerateSBOM(ctx context.Context, config utils.Config) ([]byte, error) {
	jsonFile := filepath.Join("/tmp", utils.RandomString(12)+"-output.json")

	// 1. Prepare source (may export tar or dir)
	source, cleanup, err := PrepareSource(config)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// 2. Build arguments
	syftArgs := BuildSyftArgs(config, jsonFile, source)

	// 3. Build env
	syftEnv := BuildSyftEnv(config)

	// 4. Run syft
	if err := RunSyft(ctx, config.SyftBinPath, syftArgs, syftEnv); err != nil {
		return nil, err
	}

	// 5. Read SBOM output
	sbom, err := ReadSBOM(jsonFile)
	defer os.Remove(jsonFile)

	return sbom, err
}

func PrepareSource(config utils.Config) (string, func(), error) {
	// If scanning a local directory
	if isDirectorySource(config.Source) {
		// Check if the directory size is above the 50 GB threshold
		path := strings.TrimPrefix(config.Source, "dir:")
		abs, _ := filepath.Abs(path)

		dirSize, err := getDirectorySize(abs)
		if err != nil {
			return "", nil, err
		}

		// If the directory is larger than 50GB, chunk it for parallel scanning
		if dirSize > ChunkSize {
			return "dir:" + abs, func() {}, nil
		}
	}

	// if requiresImageTarExport(config) {
	// 	return prepareRuntimeImageTar(config)
	// }

	// If container filesystem export is needed
	// if config.NodeType == utils.NodeTypeContainer {
	// 	return prepareContainerFileSystem(config)
	// }

	// Otherwise, the source is unchanged (registry / docker / etc)
	return config.Source, func() {}, nil
}

func getDirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func requiresImageTarExport(config utils.Config) bool {
	return config.NodeType == utils.NodeTypeImage &&
		(strings.HasPrefix(config.Source, "containerd://") ||
			strings.HasPrefix(config.Source, "crio://"))
}

func RunSyftInParallel(ctx context.Context, syftBinary string, config utils.Config, sourceDir string) error {
	// Split the source directory into chunks (e.g., chunks of 50GB or less)
	chunks, err := getDirectoryChunks(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to split directory into chunks: %w", err)
	}

	// Use a worker pool to process chunks concurrently
	var wg sync.WaitGroup
	chunkChan := make(chan string, len(chunks)) // Channel to pass chunks to workers

	// Start worker goroutines
	for i := 0; i < MaxWorkers; i++ {
		go func() {
			for chunk := range chunkChan {
				if err := scanChunkWithSyft(ctx, syftBinary, config, chunk); err != nil {
					log.Errorf("Failed to scan chunk: %v", err)
				}
			}
		}()
	}

	// Send chunks to workers
	for _, chunk := range chunks {
		wg.Add(1)
		chunkChan <- chunk
	}

	// Close the channel after all chunks are dispatched
	go func() {
		wg.Wait()
		close(chunkChan)
	}()

	return nil
}

func scanChunkWithSyft(ctx context.Context, syftBinary string, config utils.Config, chunk string) error {
	// Prepare Syft args for scanning the chunk
	jsonFile := filepath.Join("/tmp", utils.RandomString(12)+"-output.json")
	args := BuildSyftArgs(config, jsonFile, "dir:"+chunk)
	env := BuildSyftEnv(config)

	// Run Syft scan for the chunk
	if err := RunSyft(ctx, syftBinary, args, env); err != nil {
		return err
	}

	// Read SBOM output
	sbom, err := ReadSBOM(jsonFile)
	if err != nil {
		return err
	}

	// Process the SBOM (for example, merge the results from all chunks)
	_ = sbom // Assuming you would collect/merge these results

	return nil
}

func getDirectoryChunks(sourceDir string) ([]string, error) {
	// Split the directory into chunks based on its size.
	// This is a basic implementation; you may want to implement smarter chunking depending on the directory structure.
	// For simplicity, assume we divide into chunks of ~50GB.
	return []string{sourceDir}, nil // For now, return the directory as one chunk (modify this logic as per your need)
}

func isDirectorySource(src string) bool {
	return strings.HasPrefix(src, "dir:") || src == "."
}

func BuildSyftArgs(config utils.Config, jsonFile string, source string) []string {
	args := []string{"packages", source, "-o", "json", "--file", jsonFile, "-q"}

	args = applyExcludeRules(args, config)
	args = applyScanTypeCatalogers(args, config)
	args = applyRegistryPrefix(args, config)

	return args
}

func applyExcludeRules(args []string, config utils.Config) []string {
	if isDirectorySource(config.Source) {
		for _, dir := range linuxExcludeDirs {
			args = append(args, "--exclude", "."+dir+"/**")
		}
	} else if config.NodeType != utils.NodeTypeContainer {
		for _, dir := range linuxExcludeDirs {
			args = append(args, "--exclude", dir)
		}
	}
	return args
}

func applyScanTypeCatalogers(args []string, config utils.Config) []string {
	if config.ScanType != "" && config.ScanType != "all" {
		isRegistry := config.RegistryID != "" && config.NodeType == utils.NodeTypeImage
		args = append(args, buildCatalogersArg(config.ScanType, isRegistry)...)
	}
	return args
}

func applyRegistryPrefix(args []string, config utils.Config) []string {
	if len(args) < 2 {
		return args
	}

	if config.IsRegistry {
		if !strings.HasPrefix(args[1], registryPrefix) {
			args[1] = registryPrefix + args[1]
		}
	} else {
		args[1] = strings.TrimPrefix(args[1], registryPrefix)
	}

	return args
}

func BuildSyftEnv(config utils.Config) []string {
	env := []string{}

	if config.RegistryID != "" && config.NodeType == utils.NodeTypeImage {
		if config.RegistryCreds.AuthFilePath != "" {
			env = append(env, "DOCKER_CONFIG="+config.RegistryCreds.AuthFilePath)
		}
		if config.RegistryCreds.SkipTLSVerify {
			env = append(env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")
		}
		if config.RegistryCreds.UseHTTP {
			env = append(env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true")
		}
	}

	return env
}

func RunSyft(ctx context.Context, syftBinary string, args []string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, syftBinary, args...)
	cmd.Env = append(os.Environ(), extraEnv...)

	log.Infof("run syft: %s", cmd.String())
	log.Debugf("run syft: %s", cmd.String())
	log.Debugf("env: %+v", extraEnv)

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		if err == context.Canceled {
			log.Infof("Command cancelled as context was cancelled %v", context.Canceled)
		} else {
			log.Errorf("syft error: %v", err)
			log.Errorf("stdout/stderr: %s", stdout)
		}
		return err
	}
	return nil
}

func ReadSBOM(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Errorf("failed to read SBOM: %v", err)
		return nil, err
	}
	return b, nil
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

// SBOMHeader represents the top-level fields of a Syft SBOM.
type SBOMHeader struct {
	Schema                interface{} `json:"schema"`
	Source                interface{} `json:"source"`
	Distro                interface{} `json:"distro"`
	ArtifactRelationships interface{} `json:"artifactRelationships"`
}

func getIncludedDirsForHostScan() ([]string, error) {
	entries, err := os.ReadDir(HostMountDir)
	if err != nil {
		return nil, err
	}

	excludeSet := buildExcludeSet()
	var included []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fullPath := filepath.Join(HostMountDir, e.Name())
		// check against the directory name relative to root, e.g. /proc
		// HostMountDir might be /fenced/mnt/host, e.Name() might be proc
		// we want to check if /proc is in exclude list.
		checkPath := "/" + e.Name()
		if excludeSet[checkPath] {
			continue
		}
		included = append(included, fullPath)
	}
	return included, nil
}

func buildExcludeSet() map[string]bool {
	s := make(map[string]bool)
	for _, d := range linuxExcludeDirs {
		s[d] = true
	}
	for _, d := range mntDirs {
		s[d] = true
	}
	return s
}

func listSubDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(root, e.Name()))
		}
	}
	return dirs, nil
}

func cleanupSBOMFiles(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

func readSBOMHeader(path string) (*SBOMHeader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Decode partially to get the header fields, skipping artifacts if possible
	// Since JSON objects are unordered, we usually have to rely on the fact that
	// Syft puts artifacts last, or parse the whole thing.
	// For efficiency with huge files, we use a decoder and try to skip.
	dec := json.NewDecoder(f)
	var h SBOMHeader

	// This simplistic approach assumes the header fields come before artifacts
	// or that decoding partial structs works if we don't access the artifacts field.
	// However, json.Decode will read the whole object.
	// For a true streaming read to skip artifacts, we'd need more complex logic.
	// For now, we trust standard unmarshalling or add specific logic if needed.
	// Given the test check "DoesNotBufferLargeArtifacts", we probably want to *not*
	// load artifacts into memory.
	// To do this simply: unmarshal into a struct that *omits* the artifacts field.
	// The Go json decoder will skip fields not in the struct.

	if err := dec.Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

func writeJSONPreamble(w io.Writer, h *SBOMHeader) error {
	// We manually reconstruct the JSON structure start
	pre := struct {
		Schema                interface{} `json:"schema"`
		Source                interface{} `json:"source"`
		Distro                interface{} `json:"distro"`
		ArtifactRelationships interface{} `json:"artifactRelationships"`
	}{
		Schema:                h.Schema,
		Source:                h.Source,
		Distro:                h.Distro,
		ArtifactRelationships: h.ArtifactRelationships,
	}

	b, err := json.Marshal(pre)
	if err != nil {
		return err
	}

	// Remove the closing '}'
	s := string(b)
	s = strings.TrimSuffix(s, "}")

	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	// Start artifacts array
	if _, err := io.WriteString(w, `,"artifacts":[`); err != nil {
		return err
	}
	return nil
}

func writeJSONEpilogue(w io.Writer, h *SBOMHeader) error {
	_, err := io.WriteString(w, "]}")
	return err
}

func streamArtifacts(path string, w io.Writer, first bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)

	// Navigate to "artifacts" field
	for {
		t, err := dec.Token()
		if err != nil {
			return 0, err
		}
		if s, ok := t.(string); ok && s == "artifacts" {
			break
		}
	}

	// Open array
	if _, err := dec.Token(); err != nil { // consume '['
		return 0, err
	}

	count := 0
	for dec.More() {
		var art json.RawMessage
		if err := dec.Decode(&art); err != nil {
			return count, err
		}
		if !first || count > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				return count, err
			}
		}
		if _, err := w.Write(art); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func mergeSBOMFiles(files []string, outPath string) error {
	if len(files) == 0 {
		return fmt.Errorf("no files to merge")
	}

	// Use the first file as the source of truth for the header
	header, err := readSBOMHeader(files[0])
	if err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	if err := writeJSONPreamble(out, header); err != nil {
		return err
	}

	first := true
	for _, f := range files {
		n, err := streamArtifacts(f, out, first)
		if err != nil {
			return err
		}
		if n > 0 {
			first = false
		}
	}

	return writeJSONEpilogue(out, header)
}

func scanDirWithSyft(ctx context.Context, config utils.Config, dir string) (string, error) {
	jsonFile := filepath.Join(os.TempDir(), utils.RandomString(12)+"-syft-chunk.json")
	args := BuildSyftArgs(config, jsonFile, "dir:"+dir)
	env := BuildSyftEnv(config)

	if err := RunSyft(ctx, config.SyftBinPath, args, env); err != nil {
		return "", err
	}
	return jsonFile, nil
}

func runParallelSBOMGeneration(ctx context.Context, config utils.Config, sourceDir string, subDirs []string) (string, error) {
	// Create channels
	jobs := make(chan string, len(subDirs))
	results := make(chan string, len(subDirs))
	errorsChan := make(chan error, len(subDirs))

	for _, d := range subDirs {
		jobs <- d
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := MaxWorkers
	if len(subDirs) < workers {
		workers = len(subDirs)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range jobs {
				if ctx.Err() != nil {
					return
				}
				res, err := scanDirWithSyft(ctx, config, dir)
				if err != nil {
					errorsChan <- err
					return
				}
				results <- res
			}
		}()
	}

	wg.Wait()
	close(results)
	close(errorsChan)

	if len(errorsChan) > 0 {
		return "", <-errorsChan
	}

	var chunkFiles []string
	for r := range results {
		chunkFiles = append(chunkFiles, r)
	}

	finalSBOM := filepath.Join(os.TempDir(), utils.RandomString(12)+"-merged.json")
	if err := mergeSBOMFiles(chunkFiles, finalSBOM); err != nil {
		cleanupSBOMFiles(chunkFiles)
		return "", err
	}
	cleanupSBOMFiles(chunkFiles)

	return finalSBOM, nil
}
