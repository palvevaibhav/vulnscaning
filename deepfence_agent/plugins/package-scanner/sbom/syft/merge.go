
package syft

import (
	"bufio"
	"os"
	"strings"
)

func cleanupSBOM(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

func mergeSBOMStream(files []string, output string) error {

	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()

	writer.WriteString(`{"artifacts":[`)

	first := true

	for _, file := range files {

		f, err := os.Open(file)
		if err != nil {
			return err
		}

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {

			line := scanner.Text()

			if strings.Contains(line, `"artifacts":`) {
				continue
			}

			if !first {
				writer.WriteString(",")
			}

			writer.WriteString(line)
			first = false
		}

		f.Close()
	}

	writer.WriteString(`]}`)

	return nil
}
