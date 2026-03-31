package crio

import (
	"context"
	"strings"

	crioRuntime "github.com/deepfence/vessel/crio"
	containerdApi "github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	vesselConstants "github.com/deepfence/vessel/utils"
	"github.com/sirupsen/logrus"
	vesselent "github.com/deepfence/package-scanner/sbom/vesselent"
)

// You OWN this type, so you can add methods
type ExtendedCrio struct {
    *crioRuntime.CRIO
}

// Constructor
func New(c *crioRuntime.CRIO) *ExtendedCrio {
    return &ExtendedCrio{CRIO: c}
}


func (c ExtendedCrio) GetFileSystemPath(containerId string, namespace string) ([]byte, error) {
	// create a new client connected to the default socket path for containerd
	client, err := containerdApi.New(strings.Replace(c.GetSocket(), "unix://", "", 1))
	if err != nil {
		return []byte(""), err
	}
	defer client.Close()
	// create a new context with namespace
	if len(namespace) == 0 {
		namespace = vesselConstants.CONTAINERD_K8S_NS
	}
	ctx := namespaces.WithNamespace(context.Background(), namespace)
	container, err := client.LoadContainer(ctx, containerId)
	if err != nil {
		logrus.Error("Error while getting container")
		return []byte(""), err
	}
	info, _ := container.Info(ctx)
	snapshotter := client.SnapshotService(info.Snapshotter)
	mounts, err := snapshotter.Mounts(ctx, info.SnapshotKey)
	if err != nil {
		logrus.Errorf("Error mount snapshot %s: %s", info.SnapshotKey, err.Error())
	}

	logrus.Infof("mount command: %+v", mounts)

	// var mountStatement = fmt.Sprintf("mount -t %s %s %s -o %s\n", mounts[0].Type, mounts[0].Source, target, strings.Join(mounts[0].Options, ","))
	// cmd := exec.Command("bash", "-c", mountStatement)
	// logrus.Infof("mount command: %s", cmd.String())
	// _, err = cmd.Output()
	// if err != nil {
	// 	mountedHostPath := "/fenced/mnt/host"
	// 	logrus.Warnf("error while mounting image on temp target dir %s %s %s \n", mountStatement, " err: ", err.Error())
	// 	logrus.Infof("Reattempting mount from %s \n", mountedHostPath)
	// 	var containerdTmpDirs = []string{"/tmp", "/var/lib"}
	// 	var workDir, upperDir, lowerDir string
	// 	for index, option := range mounts[0].Options {
	// 		for _, tmpDir := range containerdTmpDirs {
	// 			if strings.Contains(option, tmpDir) {
	// 				mounts[0].Options[index] = strings.Replace(option, tmpDir, mountedHostPath+tmpDir, -1)
	// 				if strings.Index(mounts[0].Options[index], "upperdir") >= 0 {
	// 					upperDir = strings.Split(mounts[0].Options[index], "=")[1]
	// 				} else if strings.Index(mounts[0].Options[index], "workdir") >= 0 {
	// 					workDir = strings.Split(mounts[0].Options[index], "=")[1]
	// 				} else if strings.Index(mounts[0].Options[index], "lowerdir") >= 0 {
	// 					lowerDir = strings.Split(mounts[0].Options[index], "=")[1]
	// 				}
	// 			}
	// 		}
	// 	}
	// 	mountStatement = fmt.Sprintf("mount -t %s %s %s -o index=off,lowerdir=%s \n",
	// 		mounts[0].Type, mounts[0].Source, target, workDir+":"+upperDir+":"+lowerDir)
	// 	cmd := exec.Command("bash", "-c", mountStatement)
	// 	logrus.Infof("mount command: %s", cmd.String())
	// 	_, err = cmd.Output()
	// 	if err != nil {
	// 		logrus.Errorf("error while mounting image on temp target dir 2nd attempt %s %s %s \n", mountStatement, " err: ", err.Error())
	// 		return []byte(""), err
	// 	}
	// 	logrus.Info("mount success \n")
	// }
	// _, err = exec.Command("tar", "-cvf", outputTarPath, "-C", target, ".").Output()
	// if !vesselConstants.CheckTarFileValid(outputTarPath) {
	// 	if err != nil {
	// 		logrus.Errorf("Error while packing tar %s %s %s \n", outputTarPath, target, err.Error())
	// 		return []byte(""), err
	// 	}
	// }
	return []byte(""), nil
}

// Ensure it implements EntRuntime
var _ vesselent.EntRuntime = (*ExtendedCrio)(nil)
