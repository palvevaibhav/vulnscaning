package vesselent

import (
	"github.com/deepfence/vessel"
)

type EntRuntime interface {
	vessel.Runtime

	GetFileSystemPath(containerId string, namespace string) ([]byte, error)
}
