package syft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/deepfence/package-scanner/utils"
	"github.com/deepfence/vessel"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	podmanRuntime "github.com/deepfence/vessel/podman"
	vesselConstants "github.com/deepfence/vessel/utils"
	log "github.com/sirupsen/logrus"
    "github.com/deepfence/package-scanner/internal/workflow"
)

var (
	varExcludeDirs = []string{
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
		"/var/lib/crio", "/var/run/containers",
	}
	homeExcludeDirs = []string{
		"/home/kubernetes/containerized_mounter",
	}

	linuxExcludeDirs = []string{
		"/mnt", "/run", "/proc", "/dev", "/boot", "/sys", "/lost+found",
	}
	mntDirs = getNfsMountsDirs()
)

const (
	HostMountDir   = "/fenced/mnt/host"
	registryPrefix = "registry:"
)

const MaxDirSize int64 = 50 * 1024 * 1024 * 1024

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
		containerRuntimeInterface = dockerRuntime.New(endpoint)
	case vesselConstants.CONTAINERD:
		containerRuntimeInterface = containerdRuntime.New(endpoint)
	case vesselConstants.CRIO:
		containerRuntimeInterface = crioRuntime.New(endpoint)
	case vesselConstants.PODMAN:
		containerRuntimeInterface = podmanRuntime.New(endpoint)
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
	log.Infof("Extracted tar file %s to %s", containerScan.tempDir+".tar", containerScan.tempDir)
	return nil
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

func syftBuildArgs(config utils.Config, syftArgs []string, syftEnv []string) ([]string, []string) {
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

func runSyft(ctx context.Context, config utils.Config, syftArgs []string, syftEnv []string, idx int, errs []error, jsonFile string) {
	cmd := exec.CommandContext(ctx, config.SyftBinPath, syftArgs...)
	log.Infof("execute command: %s", cmd.String())
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, syftEnv...)

	log.Infof("execute command: %s", cmd.String())
	log.Infof("execute command with env: %s", syftEnv)
	stdout, err := runCommand(cmd)
	if err != nil {
		if err == context.Canceled {
			log.Debugf("Command cacelled as context was cancelled %v", context.Canceled)
		} else {
			log.Errorf("failed command: %s", cmd.String())
			log.Errorf("failed command Env: %s", cmd.Env)
			log.Errorf("err: %s", err)
			log.Errorf("stdout: %s", stdout.String())
		}
		errs[idx] = fmt.Errorf("err: %s", err)
		return
	}
	log.Infof("Finished generating SBOM for %s", jsonFile)
}

func generateNormalSBOM(ctx context.Context, config utils.Config) ([]byte, error) {
	jsonFile := filepath.Join("/tmp", utils.RandomString(12)+"output.json")
	syftArgs := []string{"packages", config.Source, "-o", "json", "--file", jsonFile, "-q"}

	if config.NodeType != utils.NodeTypeContainer {
		excludes := append(append(varExcludeDirs, homeExcludeDirs...), linuxExcludeDirs...)
		for _, excludeDir := range excludes {
			syftArgs = append(syftArgs, "--exclude", excludeDir)
		}
	}

	if (config.ContainerRuntimeName == vesselConstants.CONTAINERD ||
		config.ContainerRuntimeName == vesselConstants.CRIO) &&
		config.ContainerRuntime != nil {
		// This means the underlying container runtime is containerd
		// in case of image scan, we need to generate image tar file and
		// feed it to syft, since syft does not support listing images from containerd
		// ref: https://github.com/anchore/syft/issues/1048
		//
		// TODO : Remove this commit after anchore/syft#1048 is resolved
		//
		// create a temp directory for tar
		tmpDir, err := os.MkdirTemp("", "syft-")
		if err != nil {
			log.Errorf("Error creating temp directory: %v", err)
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		// create a tar file for the image
		tarFile := filepath.Join(tmpDir, "image.tar")
		_, err = config.ContainerRuntime.Save(config.Source, tarFile)
		if err != nil {
			log.Errorf("Error creating tar file: %v", err)
			return nil, err
		}
		// feed the tar file to syft
		switch config.ContainerRuntimeName {
		case vesselConstants.CONTAINERD:
			syftArgs[1] = "oci-archive:" + tarFile
		case vesselConstants.CRIO:
			syftArgs[1] = "docker-archive:" + tarFile
		}
	} else if config.NodeType == utils.NodeTypeContainer {
		tmpDir, err := os.MkdirTemp("", "syft-")
		if err != nil {
			log.Errorf("Error creating temp directory: %v", err)
			return nil, err
		}

		defer os.RemoveAll(tmpDir)
		defer os.Remove(tmpDir + ".tar")

		var containerScan ContainerScan
		if config.KubernetesClusterName != "" {
			containerScan = ContainerScan{containerID: config.ContainerID, tempDir: tmpDir, namespace: ""}
		} else {
			containerScan = ContainerScan{containerID: config.ContainerID, tempDir: tmpDir, namespace: "default"}
		}

		err = containerScan.exportFileSystemTar()
		if err != nil {
			log.Error(err)
			return nil, err
		}
		syftArgs[1] = "dir:" + tmpDir
	}
	syftEnv := []string{}
	syftArgs, syftEnv = syftBuildArgs(config, syftArgs, syftEnv)

	var errs []error
	runSyft(ctx, config, syftArgs, syftEnv, 0, errs, jsonFile)
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	sbom, err := os.ReadFile(jsonFile)
	if err != nil {
		log.Error("error reading internal file", err)
		return nil, err
	}
	defer os.RemoveAll(jsonFile)

	return sbom, nil
}

func runSBOM(ctx context.Context, dir string, output string, config utils.Config) error {
	syftArgs := []string{
		"packages",
		"dir:" + dir,
		"-o",
		"json=" + output,
		"-q",
	}

	cmd := exec.CommandContext(ctx, config.SyftBinPath, syftArgs...)

	stdout, err := runCommand(cmd)
	if err != nil {
		return fmt.Errorf("syft failed: %v %s", err, stdout.String())
	}

	return nil
}

func ProcessDir(ctx context.Context, dir string, root string, tmpRoot string, config utils.Config) (string, error) {

	size, err := getDirSize(dir)
	if err != nil {
		return "", err
	}

	// compute relative path
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", err
	}

	// create temp directory for this parent
	tmpDir := filepath.Join(tmpRoot, rel)
	err = os.MkdirAll(tmpDir, 0755)
	if err != nil {
		return "", err
	}

	output := filepath.Join(tmpDir, utils.RandomString(10)+".json")

	// CASE: < 50GB
	if size < MaxDirSize {

		runSyft(ctx, config, []string{"packages", "dir:" + tmpDir, "-o", "json=" + output, "-q"}, []string{}, 0, []error{nil}, output)
		err := runSBOM(ctx, dir, output, config)
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

			file, err := ProcessDir(ctx, p, root, tmpRoot, config)
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

	err = mergeSBOMStream(sbomFiles, output)
	if err != nil {
		return "", err
	}

	cleanupSBOM(sbomFiles)

	return output, nil
}

func GenerateSBOM(ctx context.Context, config utils.Config) ([]byte, error) {
	if !strings.HasPrefix(config.Source, "dir:") {
		return generateNormalSBOM(ctx, config)
	}

	return workflow.Run(ctx, &config)
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
