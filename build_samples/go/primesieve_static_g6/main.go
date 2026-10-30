// primesieve_static_g6 - Go build variant: PURE STATIC (CGO_ENABLED=0).
package main

import (
	"fmt"
	"os"
	"strconv"
)

func sieve(n int) []int {
	if n < 2 {
		return nil
	}
	composite := make([]bool, n+1)
	var primes []int
	for i := 2; i <= n; i++ {
		if composite[i] {
			continue
		}
		primes = append(primes, i)
		for j := i * i; j <= n; j += i {
			composite[j] = true
		}
	}
	return primes
}

func main() {
	limit := 100
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			limit = v
		}
	}
	primes := sieve(limit)
	var sum int
	for _, p := range primes {
		sum += p
	}
	fmt.Printf("primes up to %d: count=%d sum=%d\n", limit, len(primes), sum)
	if len(primes) > 0 {
		fmt.Printf("largest=%d\n", primes[len(primes)-1])
	}
}
