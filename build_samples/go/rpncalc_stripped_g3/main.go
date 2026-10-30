// rpncalc_stripped_g3 - Go build variant: STRIPPED (-ldflags="-s -w").
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func evalRPN(tokens []string) (float64, error) {
	var st []float64
	pop := func() float64 {
		v := st[len(st)-1]
		st = st[:len(st)-1]
		return v
	}
	for _, t := range tokens {
		switch t {
		case "+", "-", "*", "/":
			if len(st) < 2 {
				return 0, fmt.Errorf("stack underflow at %q", t)
			}
			b, a := pop(), pop()
			switch t {
			case "+":
				st = append(st, a+b)
			case "-":
				st = append(st, a-b)
			case "*":
				st = append(st, a*b)
			case "/":
				st = append(st, a/b)
			}
		default:
			n, err := strconv.ParseFloat(t, 64)
			if err != nil {
				return 0, fmt.Errorf("bad token %q", t)
			}
			st = append(st, n)
		}
	}
	if len(st) != 1 {
		return 0, fmt.Errorf("malformed expression")
	}
	return st[0], nil
}

func main() {
	expr := "3 4 + 5 *"
	if len(os.Args) > 1 {
		expr = strings.Join(os.Args[1:], " ")
	}
	res, err := evalRPN(strings.Fields(expr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("%s = %g\n", expr, res)
}
