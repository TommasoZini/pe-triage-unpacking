// textcipher_stripped_g4 - Go build variant: STRIPPED (-ldflags="-s -w").
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func caesar(s string, shift int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			b.WriteRune('A' + (r-'A'+rune(shift))%26)
		case unicode.IsLower(r):
			b.WriteRune('a' + (r-'a'+rune(shift))%26)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func main() {
	shift := 3
	text := "The quick brown fox"
	if len(os.Args) > 1 {
		text = strings.Join(os.Args[1:], " ")
	}
	enc := caesar(text, shift)
	words := len(strings.Fields(text))
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "input : %s\n", text)
	fmt.Fprintf(w, "words : %d\n", words)
	fmt.Fprintf(w, "cipher: %s\n", enc)
	fmt.Fprintf(w, "back  : %s\n", caesar(enc, 26-shift))
}
