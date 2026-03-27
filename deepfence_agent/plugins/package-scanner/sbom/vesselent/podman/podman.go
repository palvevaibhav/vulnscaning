package podman

import (
	"os/exec"
	"strings"

	vesselent "github.com/deepfence/package-scanner/sbom/vesselent"
	podmanRuntime "github.com/deepfence/vessel/podman"
)

// You OWN this type, so you can add methods
type ExtendedPodman struct {
	*podmanRuntime.Podman
}

// Constructor
func New(p *podmanRuntime.Podman) *ExtendedPodman {
	return &ExtendedPodman{Podman: p}
}

func (p ExtendedPodman) GetFileSystemPath(containerId string, namespace string) ([]byte, error) {
	return exec.Command("podman", "--remote", "--url", p.GetSocket(), "inspect", strings.TrimSpace(containerId), "--format", "{{ .GraphDriver.Data.MergedDir }}").Output()
}

var _ vesselent.EntRuntime = (*ExtendedPodman)(nil)
