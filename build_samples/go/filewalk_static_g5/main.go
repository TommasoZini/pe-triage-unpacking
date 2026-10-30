// filewalk_static_g5 - Go build variant: PURE STATIC (CGO_ENABLED=0).
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	byExt := map[string]int{}
	var files, dirs int
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			dirs++
			return nil
		}
		files++
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		ext := filepath.Ext(p)
		if ext == "" {
			ext = "(none)"
		}
		byExt[ext]++
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk error:", err)
		os.Exit(1)
	}
	fmt.Printf("root=%s dirs=%d files=%d bytes=%d\n", root, dirs, files, total)
	exts := make([]string, 0, len(byExt))
	for e := range byExt {
		exts = append(exts, e)
	}
	sort.Slice(exts, func(i, j int) bool { return byExt[exts[i]] > byExt[exts[j]] })
	for _, e := range exts {
		fmt.Printf("  %-8s %d\n", e, byExt[e])
	}
}
