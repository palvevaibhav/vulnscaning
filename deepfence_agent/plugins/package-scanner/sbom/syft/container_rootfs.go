package syft

import (
        "encoding/json"
        "fmt"
        "os/exec"
        "strings"

        vessel "github.com/deepfence/vessel"
        vesselConstants "github.com/deepfence/vessel/utils"
)

func GetContainerRootFS(containerID string) (string, error) {
        runtime, _, err := vessel.AutoDetectRuntime()
	if err != nil {
		return "", err
	}

        switch runtime {
        case vesselConstants.DOCKER:
                return dockerMergedPath(containerID)
        case vesselConstants.CONTAINERD:
                return containerdSnapshotFS(containerID)
        case vesselConstants.CRIO, vesselConstants.PODMAN:
                return podmanMergedPath(containerID)
        }

        return "", fmt.Errorf("unsupported runtime: %s", runtime)
}


func dockerMergedPath(containerID string) (string, error) {
        out, err := exec.Command(
                "docker", "inspect", containerID, "--format",
                "{{ .GraphDriver.Data.MergedDir }}",
        ).Output()

        if err != nil {
                return "", fmt.Errorf("docker inspect failed: %w", err)
        }

        return strings.TrimSpace(string(out)), nil
}

func containerdSnapshotFS(containerID string) (string, error) {
        out, err := exec.Command(
                "ctr", "-n", "k8s.io", "containers", "info", containerID,
        ).Output()

        if err != nil {
                return "", fmt.Errorf("ctr info failed: %w", err)
        }

        var info struct {
                SnapshotKey string `json:"snapshotKey"`
        }

        if err := json.Unmarshal(out, &info); err != nil {
                return "", fmt.Errorf("failed to parse ctr info: %w", err)
        }

        if info.SnapshotKey == "" {
                return "", fmt.Errorf("snapshotKey missing in ctr output")
        }

        rootfs := "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/" +
                info.SnapshotKey + "/fs"

        return rootfs, nil
}

func podmanMergedPath(containerID string) (string, error) {
        out, err := exec.Command(
                "podman", "inspect", containerID, "--format",
                "{{ .GraphDriver.Data.MergedDir }}",
        ).Output()

        if err != nil {
                return "", fmt.Errorf("podman inspect failed: %w", err)
        }

        return strings.TrimSpace(string(out)), nil
}

