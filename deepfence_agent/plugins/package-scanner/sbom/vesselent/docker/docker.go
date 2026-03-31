package docker

import (
	"os/exec"
	"strings"

	dockerRuntime "github.com/deepfence/vessel/docker"
	vesselent "github.com/deepfence/package-scanner/sbom/vesselent"
)


// You OWN this type, so you can add methods
type ExtendedDocker struct {
    *dockerRuntime.Docker
}

// Constructor
func New(d *dockerRuntime.Docker) *ExtendedDocker {
    return &ExtendedDocker{Docker: d}
}

func (d ExtendedDocker) GetFileSystemPath(containerId string, namespace string) ([]byte, error) {
	return exec.Command("docker", "inspect", strings.TrimSpace(containerId), "--format", "{{ .GraphDriver.Data.MergedDir }}").Output();
}

var _ vesselent.EntRuntime = (*ExtendedDocker)(nil)
