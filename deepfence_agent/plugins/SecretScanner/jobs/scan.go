package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"os"
	"context"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	log "github.com/sirupsen/logrus"
	"github.com/deepfence/golang_deepfence_sdk/utils/http"
)

var ScanMap sync.Map

func DispatchScan(r *pb.FindRequest) {
	fmt.Printf("Secret Request ScanId: %v, path: %+v, image: %+v, container: %+v", r.ScanId, r.GetPath(), r.GetImage(), r.GetContainer())
	go func() {
		fmt.Println("Secrete Scanner reached here DispatchScanstageinner")
		startScanJob()
		defer stopScanJob()

		var err error
		res, scanCtx := tasks.StartStatusReporter(
			r.ScanId,
			func(ss tasks.ScanStatus) error {
				return writeSecretScanStatus(ss.ScanStatus, ss.ScanId, ss.ScanMessage)
			},
			tasks.StatusValues{
				IN_PROGRESS: "IN_PROGRESS",
				CANCELLED:   "CANCELLED",
				FAILED:      "ERROR",
				SUCCESS:     "COMPLETE",
			},
			time.Minute*20,
		)

		ScanMap.Store(r.ScanId, scanCtx)

		defer func() {
			ScanMap.Delete(r.ScanId)
			res <- err
			close(res)
		}()

		fmt.Println("In-progress secret scan for request: stage2")
		var secrets chan output.SecretFound

		if r.GetPath() != "" {
			var isFirstSecret bool = true
			secrets, err = scan.ScanSecretsInDirStream("", r.GetPath(), r.GetPath(),
				&isFirstSecret, scanCtx)
			if err != nil {
				return
			}
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			secrets, err = scan.ExtractAndScanImageStream(r.GetImage().Name, scanCtx)
			if err != nil {
				return
			}
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			secrets, err = scan.ExtractAndScanContainerStream(r.GetContainer().Id,
				r.GetContainer().Namespace, scanCtx)
			if err != nil {
				return
			}
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}
		
		fmt.Println("Completed secret scan for request: stage2")
		go func() {
			writeSecretScanProgressStatus(r.ScanId, "SecretScan", "stage2")
		}()

		fmt.Println("In-progress secret scan for request: stage3")
		var prevSecret output.SecretFound
		var hasPrev bool
		
		for secret := range secrets {
			if hasPrev {
				writeSingleScanData(output.SecretToSecretInfo(prevSecret), r.ScanId, "")
			}

			prevSecret = secret
			hasPrev = true
		}

		/**
		if hasPrev {
			writeSingleScanData(output.SecretToSecretInfo(prevSecret), r.ScanId, "stage4")
		}
		*/

		fmt.Println("Completed secret scan for request: stage3")
		go func() {
			if hasPrev {
				writeSecretScanProgressStatus(r.ScanId, "SecretScan", "stage3")
				writeSingleScanData(output.SecretToSecretInfo(prevSecret), r.ScanId, "stage4")
			}else{
				fmt.Println("Completed secret scan for request: stage4")
				writeSecretScanProgressStatus(r.ScanId, "SecretScan", "stage4")
			}
		}()
	}()
}


type SecretScanDoc struct {
	pb.SecretInfo
	ScanID string `json:"scan_id,omitempty"`
	ProgressStatus string `json:"progress_status,omitempty"`
}

func writeMultiScanData(secrets []*pb.SecretInfo, scan_id string) {
	fmt.Printf("Writing %d secrets to scan file for scan_id: %s\n", len(secrets), scan_id)
	for _, secret := range secrets {
		if SecretScanDir == HostMountDir {
			secret.GetMatch().FullFilename = strings.Replace(secret.GetMatch().GetFullFilename(), SecretScanDir, "", 1)
		}
		secretScanDoc := SecretScanDoc{
			SecretInfo: *secret,
			ScanID:     scan_id,
		}
		fmt.Printf("writeMultiScanData byteJson value:: %s", scan_id)

		byteJson, err := json.Marshal(secretScanDoc)
		if err != nil {
			log.Errorf("Error marshalling json: ", err)
			continue
		}
		fmt.Printf("writeMultiScanData byteJson value: %v", string(byteJson))

		err = writeScanDataToFile(string(byteJson), scanFilename)
		if err != nil {
			log.Errorf("Error in sending data to secretScanIndex:" + err.Error())
			continue
		}
	}
}

func writeSingleScanData(secret *pb.SecretInfo, scan_id string, progressStatus string) {
	if SecretScanDir == HostMountDir {
		secret.GetMatch().FullFilename = strings.Replace(secret.GetMatch().GetFullFilename(), SecretScanDir, "", 1)
	}
	secretScanDoc := SecretScanDoc{
		SecretInfo: *secret,
		ScanID:     scan_id,
		ProgressStatus: progressStatus,
	}

	byteJson, err := json.Marshal(secretScanDoc)
	if err != nil {
		log.Errorf("Error marshalling json: ", err)
		return
	}

//	fmt.Printf("writeSingleScanData scanId: %v,  (byteJson value): %v", scan_id, string(byteJson))

	err = writeScanDataToFile(string(byteJson), scanFilename)
	if err != nil {
		log.Errorf("Error in sending data to secretScanIndex:" + err.Error())
		return
	}
}

func writeSecretScanProgressStatus(scanId,scanType, status string) {	
url := os.Getenv("MGMT_CONSOLE_URL")
	if url == "" {
		fmt.Printf("MGMT_CONSOLE_URL not set")
		return
	}
	port := os.Getenv("MGMT_CONSOLE_PORT")
	if port == "" {
		fmt.Printf("MGMT_CONSOLE_PORT not set")
		return
	}

	apiToken := os.Getenv("DEEPFENCE_KEY")
	if strings.Trim(apiToken, "\"") == "" && http.IsConsoleAgent(url) {
		internalURL := os.Getenv("MGMT_CONSOLE_URL_INTERNAL")
		internalPort := os.Getenv("MGMT_CONSOLE_PORT_INTERNAL")
		fmt.Printf("fetch console agent token")
		var err error
		if apiToken, err = http.GetConsoleApiToken(internalURL, internalPort); err != nil {
			fmt.Printf("Error in fetching console agent token: %v", err)
			return
		}
	} else if apiToken == "" {
		fmt.Printf("DEEPFENCE_KEY not set")
		return
	}
	fmt.Printf("console_url: %v, port: %v, key: %v", url, port, apiToken)
	pub, err := output.NewPublisher(url, port, apiToken)
	if err != nil {
		log.Error(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = pub.IngestScanProgressStatus(ctx, scanId, scanType, status)
	if err != nil {
		log.Errorf("Error in sending scan progress status: %v", err)
	}	
}
