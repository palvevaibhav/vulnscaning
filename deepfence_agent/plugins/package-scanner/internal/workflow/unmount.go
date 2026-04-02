package workflow

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"github.com/deepfence/package-scanner/utils"

)

// 🔍 Get all mounted paths under root
func getMountedPaths(root string) ([]string, error) {
	file, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mounts []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		mountPoint := fields[1]

		// check if under our root
		if strings.HasPrefix(mountPoint, root) {
			mounts = append(mounts, mountPoint)
		}
	}

	return mounts, nil
}

// 🔻 Lazy unmount
func lazyUnmount(path string) error {
	cmd := exec.Command("umount", "-l", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount failed: %s", string(out))
	}
	return nil
}

func unmountChunkFolders(cfg *utils.Config) error {
	mountRoot := cfg.MountRoot

	fmt.Println("🔍 Finding mounted paths...")

	mounts, err := getMountedPaths(mountRoot)
	if err != nil {
		fmt.Println("❌ Error:", err)
		return err
	}

	if len(mounts) == 0 {
		fmt.Println("⚠️ No mounts found")
		return nil
	}

	// 🔥 Important: unmount deepest paths first
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) > len(mounts[j])
	})

	fmt.Printf("📦 Found %d mount points\n", len(mounts))

	// 🚀 Unmount
	for _, m := range mounts {
		fmt.Printf("🔻 Unmounting: %s\n", m)

		err := lazyUnmount(m)
		if err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
			continue
		}

		fmt.Printf("✅ Unmounted: %s\n", m)
	}

	fmt.Println("\n🎉 Lazy unmount completed!")
	return nil
}

