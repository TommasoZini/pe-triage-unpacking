// sysinfo_default_g2 - Go build variant: DEFAULT build (go build).
package main

import (
	"fmt"
	"runtime"
)

func main() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Println("=== Go runtime info ===")
	fmt.Printf("GOOS/GOARCH : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Go version  : %s\n", runtime.Version())
	fmt.Printf("NumCPU      : %d\n", runtime.NumCPU())
	fmt.Printf("Goroutines  : %d\n", runtime.NumGoroutine())
	fmt.Printf("HeapAlloc   : %d KiB\n", m.HeapAlloc/1024)
	fmt.Printf("Sys         : %d KiB\n", m.Sys/1024)
}
