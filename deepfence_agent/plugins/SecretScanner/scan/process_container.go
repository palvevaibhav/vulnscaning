package scan

import (
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	tasks "github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/vessel"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	podmanRuntime "github.com/deepfence/vessel/podman"
	vesselConstants "github.com/deepfence/vessel/utils"
	log "github.com/sirupsen/logrus"
)

type ContainerScan struct {
	containerId string
	tempDir     string
	namespace   string
	numSecrets  uint
	mergedDir   string
}

func GetContainerFileSystemPath(containerId string) ([]byte, error) {
	return exec.Command(
		"docker",
		"inspect",
		strings.TrimSpace(containerId),
		"--format",
		"{{ .GraphDriver.Data.MergedDir }}",
	).Output()
}

// Function to retrieve contents of container
// @parameters
// containerScan - Structure with details of the container to scan
// @returns
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) extractFileSystem() (string, error) {
	// Auto-detect underlying container runtime
	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		return "", err
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
		os.Exit(1)
	}
	
	if containerRuntime == vesselConstants.DOCKER {
		containerPathBytes, err := GetContainerFileSystemPath(containerScan.containerId)
		if err != nil {
			return "", err
		}
		containerPath := strings.TrimSpace(string(containerPathBytes))
		return containerPath, nil
	}

	err = containerRuntimeInterface.ExtractFileSystemContainer(
		containerScan.containerId, containerScan.namespace,
		containerScan.tempDir+".tar")

	if err != nil {
		return "", err
	}
	runCommand("mkdir", containerScan.tempDir)
	_, stdErr, retVal := runCommand("tar", "-xf", containerScan.tempDir+".tar", "-C"+containerScan.tempDir)
	if retVal != 0 {
		return "", errors.New(stdErr)
	}
	runCommand("rm", containerScan.tempDir+".tar")
	return "", nil
}

// Function to scan extracted layers of container file system for secrets file by file
// @parameters
// containerScan - Structure with details of the container  to scan
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) scan(scanCtx *tasks.ScanContext) ([]output.SecretFound, error) {
	var isFirstSecret bool = true
	// secrets, err := ScanSecretsInDir("", containerScan.mergedDir, containerScan.mergedDir,
	// 	&isFirstSecret, scanCtx)

	var secrets []output.SecretFound
	var err error

	if containerScan.mergedDir != "" {
		secrets, err = ScanSecretsInDir("", containerScan.mergedDir, containerScan.mergedDir, &isFirstSecret, scanCtx)
	} else {
		secrets, err = ScanSecretsInDir("", containerScan.tempDir, containerScan.tempDir, &isFirstSecret, scanCtx)
	}

	if err != nil {
		log.Errorf("findSecretsInContainer: %s", err)
		return nil, err
	}

	var tempPath string
	if containerScan.mergedDir != "" {
		tempPath = containerScan.mergedDir
	} else {
		tempPath = containerScan.tempDir
	}

	for _, secret := range secrets {
		secret.CompleteFilename = strings.Replace(secret.CompleteFilename, tempPath , "", 1)
	}

	return secrets, nil
}

// Function to scan extracted layers of container file system for secrets file by file
// @parameters
// containerScan - Structure with details of the container  to scan
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) scanStream(scanCtx *tasks.ScanContext) (chan output.SecretFound, error) {
	var isFirstSecret bool = true
	// stream, err := ScanSecretsInDirStream("", containerScan.tempDir, containerScan.tempDir, &isFirstSecret, scanCtx)
	var stream chan output.SecretFound
	var err error

	if containerScan.mergedDir != "" {
		stream, err = ScanSecretsInDirStream("", containerScan.mergedDir, containerScan.mergedDir, &isFirstSecret, scanCtx)
	} else {
		stream, err = ScanSecretsInDirStream("", containerScan.tempDir, containerScan.tempDir, &isFirstSecret, scanCtx)
	}
	
	if err != nil {
		log.Errorf("findSecretsInContainer: %s", err)
		return nil, err
	}

	return stream, nil
}

type ContainerExtractionResult struct {
	Secrets     []output.SecretFound
	ContainerId string
}

func ExtractAndScanContainer(containerId string, namespace string,
	scanCtx *tasks.ScanContext) (*ContainerExtractionResult, error) {

	tempDir, err := core.GetTmpDir(containerId)
	if err != nil {
		return nil, err
	}
	defer core.DeleteTmpDir(tempDir)

	containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace, mergedDir: ""}
	// err = containerScan.extractFileSystem()

	// if err != nil {
	// 	return nil, err
	// }

	tempPath, err := containerScan.extractFileSystem();
	
	if err != nil {
		return nil, err
	} 

	if tempPath != "" {
      containerScan.mergedDir = "/fenced/mnt/host" + tempPath
	} 
	
	secrets, err := containerScan.scan(scanCtx)

	if err != nil {
		return nil, err
	}
	return &ContainerExtractionResult{ContainerId: containerScan.containerId, Secrets: secrets}, nil
}

func ExtractAndScanContainerStream(containerId string, namespace string,
	scanCtx *tasks.ScanContext) (chan output.SecretFound, error) {
	tempDir, err := core.GetTmpDir(containerId)
	if err != nil {
		return nil, err
	}
	containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace, mergedDir : ""}
	// err = containerScan.extractFileSystem()

	// if err != nil {
	// 	core.DeleteTmpDir(tempDir)
	// 	return nil, err
	// }
	
	tempPath, err := containerScan.extractFileSystem();
	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	} 

	if tempPath != "" {
      containerScan.mergedDir = "/fenced/mnt/host" + tempPath
	} 
	
	stream, err := containerScan.scanStream(scanCtx)
	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	}
	res := make(chan output.SecretFound, secret_pipeline_size)

	go func() {
		defer core.DeleteTmpDir(tempDir)
		defer close(res)
		for i := range stream {
			res <- i
		}
	}()

	return res, nil
}
