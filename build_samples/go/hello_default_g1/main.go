// hello_default_g1 - Go build variant: DEFAULT build (go build).
package main

import (
	"fmt"
	"os"
	"strings"
)

func factorial(n uint64) uint64 {
	r := uint64(1)
	for i := uint64(2); i <= n; i++ {
		r *= i
	}
	return r
}

func main() {
	name := "world"
	if len(os.Args) > 1 {
		name = strings.Join(os.Args[1:], " ")
	}
	fmt.Printf("Hello, %s!\n", name)
	for i := uint64(1); i <= 10; i++ {
		fmt.Printf("%2d! = %d\n", i, factorial(i))
	}
}
