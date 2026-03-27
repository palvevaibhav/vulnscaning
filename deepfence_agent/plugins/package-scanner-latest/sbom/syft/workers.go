package syft

import (
	"context"
	"sync"

	"github.com/deepfence/package-scanner/utils"
)
// Bounded concurrency prevents CPU spikes.

const MaxWorkers = 8

func RunWorkers(
	ctx context.Context,
	tasks []ScanTask,
	config utils.Config,
) ([]string, error) {

	var wg sync.WaitGroup

	jobs := make(chan ScanTask)
	results := make(chan string)

	for i := 0; i < MaxWorkers; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			for task := range jobs {

				file, err := RunSyftTask(ctx, task, config)
				if err == nil {
					results <- file
				}
			}
		}()
	}

	go func() {

		for _, t := range tasks {
			jobs <- t
		}

		close(jobs)

		wg.Wait()
		close(results)

	}()

	var files []string

	for r := range results {
		files = append(files, r)
	}

	return files, nil
}