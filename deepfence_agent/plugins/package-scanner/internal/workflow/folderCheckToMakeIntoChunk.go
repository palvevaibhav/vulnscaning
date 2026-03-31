// Problem:- Large filesystem → millions of files → RAM explosion
package workflow
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------- GLOBAL PROGRESS ----------------

var totalBytes int64
var totalFiles int64

// ---------------- SKIP RULES ----------------
var skipAlways = map[string]struct{}{
	"proc":       {},
	"sys":        {},
	"dev":        {},
	"mnt":        {},
	"tmp":        {},
	"lost+found": {},
}

// skipRootOnly: skip ONLY when the directory is a direct child of the scan root.
//
// Why root-only?
//
//	"data", "data1", "media" are common project folder names.
//	/home/data          → skip  (top-level data dump, not useful to scan)
//	/home/project/data  → keep  (project-specific data inside a real project)
//
// Skipping "data" at every depth would silently drop real project content.
var skipRootOnly = map[string]struct{}{
	"data":  {},
	"data1": {},
	"media": {},
}

type NodeInfo struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ---------------- SKIP FUNCTION ----------------

// shouldSkip returns true when path should be excluded from scanning.
//
// Rules:
//  1. Name is in skipAlways  → skip at any depth
//  2. Name is in skipRootOnly → skip ONLY if direct child of scanRoot
//  3. Everything else        → do not skip
func shouldSkip(path, scanRoot string) bool {
	name := strings.ToLower(filepath.Base(path))

	// Rule 1: always skip these regardless of depth
	if _, ok := skipAlways[name]; ok {
		return true
	}

	// Rule 2: root-only — skip only when parent == scanRoot
	if _, ok := skipRootOnly[name]; ok {
		parent := filepath.Dir(filepath.Clean(path))
		if filepath.Clean(parent) == filepath.Clean(scanRoot) {
			return true
		}
	}

	return false
}

// ---------------- NODE ----------------

type Node struct {
	Path     string
	IsDir    bool
	Size     int64
	Children []*Node
}

// ---------------- BUILD ROOT ----------------

func BuildTreeParallel(root string, workers int) *Node {
	sem := make(chan struct{}, workers)
	return buildSafe(root, root, sem) // pass root for shouldSkip root-only check
}

// ---------------- SAFE RECURSION ----------------

func buildSafe(path, scanRoot string, sem chan struct{}) *Node {

	// Skip early — pass scanRoot so root-only rules work correctly
	if shouldSkip(path, scanRoot) {
		return nil
	}

	info, err := os.Lstat(path)
	if err != nil {
                fmt.Println("⚠️ Error:", path, err)
		return nil
	}
        if info.Mode() & os.ModeSymlink != 0 {
	        return nil
        }

	node := &Node{
		Path:  path,
		IsDir: info.IsDir(),
		Size:  info.Size(),
	}

	// 🔥 File → update progress
	if !node.IsDir {
		atomic.AddInt64(&totalBytes, node.Size)
		atomic.AddInt64(&totalFiles, 1)
		return node
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return node
	}

	children := make([]*Node, 0, len(entries))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, e := range entries {

		full := filepath.Join(path, e.Name())

		if shouldSkip(full, scanRoot) {
			continue
		}

		wg.Add(1)

		select {
		case sem <- struct{}{}:
			go func(p string) {
				defer wg.Done()
				child := buildSafe(p, scanRoot, sem)
				if child != nil {
					mu.Lock()
					children = append(children, child)
					mu.Unlock()
				}
				<-sem
			}(full)

		default:
			child := buildSafe(full, scanRoot, sem)
			if child != nil {
				children = append(children, child)
			}
			wg.Done()
		}
	}

	wg.Wait()
	node.Children = children
	return node
}

// ---------------- COMPUTE SIZE ----------------

func ComputeSize(node *Node) int64 {
	if node == nil {
		return 0
	}

	if !node.IsDir {
		return node.Size
	}

	var total int64
	for _, c := range node.Children {
		total += ComputeSize(c)
	}

	node.Size = total
	return total
}
type Chunk struct {
	Nodes []*Node
	Size  int64
}

// ---------------- CHUNK TREE ----------------

func ChunkTree(node *Node, maxChunkSize int64) []Chunk {

	if node == nil {
		return nil
	}

	if node.Size <= maxChunkSize {
		return []Chunk{{Nodes: []*Node{node}, Size: node.Size}}
	}

	var chunks []Chunk
	var current Chunk

	for _, child := range node.Children {

		if child == nil {
			continue
		}

		if child.Size > maxChunkSize {
			fmt.Println("\n⚠️ Splitting:", child.Path)
			chunks = append(chunks, ChunkTree(child, maxChunkSize)...)
			continue
		}

		if current.Size+child.Size > maxChunkSize {
			chunks = append(chunks, current)
			current = Chunk{}
		}

		current.Nodes = append(current.Nodes, child)
		current.Size += child.Size
	}

	if len(current.Nodes) > 0 {
		chunks = append(chunks, current)
	}

	return chunks
}

// ---------------- PROGRESS ----------------

func StartProgress() chan struct{} {
	done := make(chan struct{})

	go func() {
		start := time.Now()

		for {
			select {
			case <-done:
				return
			case <-time.After(500 * time.Millisecond):

				bytes := atomic.LoadInt64(&totalBytes)
				files := atomic.LoadInt64(&totalFiles)

				elapsed := time.Since(start).Seconds()
                                if elapsed == 0 {
	                                elapsed = 1
                                }
				speed := float64(bytes) / (1024 * 1024 * 1024) / elapsed

				fmt.Printf(
					"\r📊 Scanned: %.2f GB | Files: %d | Speed: %.2f GB/s",
					float64(bytes)/(1024*1024*1024),
					files,
					speed,
				)
			}
		}
	}()

	return done
}

// --------------------Save chunk into json file -------------------------------------

func SaveChunksToJSON(chunks []Chunk, outputFile string) error {
	result := make(map[string][]NodeInfo)

	for i, c := range chunks {
		key := fmt.Sprintf("chunk%d", i+1)

		var nodes []NodeInfo
		for _, n := range c.Nodes {
			nodes = append(nodes, NodeInfo{
				Path: n.Path,
				Size: n.Size,
			})
		}

		result[key] = nodes
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputFile, data, 0644)
}

// ---------------- MAIN ----------------

func RunImprovedScan(root string, outputFile string, workers int, maxChunkSize int64){
	start := time.Now()

	fmt.Println("🚀 Building SAFE tree (skip + progress + parallel)...")

	done := StartProgress()
        defer close(done)

	tree := BuildTreeParallel(root, workers)
	fmt.Println()

	fmt.Println("⚡ Computing size...")
	total := ComputeSize(tree)

	fmt.Printf("📊 Total Size: %.2f GB\n", float64(total)/(1024*1024*1024))

	fmt.Println("📦 Creating chunks...")
        chunks := ChunkTree(tree, maxChunkSize)

	fmt.Printf("\n📦 Total Chunks: %d\n\n", len(chunks))

	for i, c := range chunks {
		fmt.Printf("🧱 Chunk %d → Size: %.2f GB | Nodes: %d\n",
			i+1,
			float64(c.Size)/(1024*1024*1024),
			len(c.Nodes),
		)
	}

	err := SaveChunksToJSON(chunks, outputFile)
	if err != nil {
		fmt.Println("❌ Failed to save JSON:", err)
	} else {
		fmt.Println("✅ Chunks saved to:", outputFile)
	}

	fmt.Println("\n⏱ Total Time:", time.Since(start))
}

