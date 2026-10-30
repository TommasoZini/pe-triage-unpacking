// netjson_deps_g9 - Go build variant: REAL DEPENDENCIES (HTTP + JSON + crypto).
// stdlib net/http + encoding/json + crypto/sha256, plus the third-party
// module github.com/google/uuid to make this a genuine module build.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

type todo struct {
	UserID    int    `json:"userId"`
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Completed bool   `json:"completed"`
}

func main() {
	url := "https://jsonplaceholder.typicode.com/todos/1"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Request-ID", uuid.NewString())

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	sum := sha256.Sum256(body)

	var t todo
	if err := json.Unmarshal(body, &t); err != nil {
		fmt.Fprintln(os.Stderr, "json error:", err)
		os.Exit(1)
	}
	fmt.Printf("status : %s\n", resp.Status)
	fmt.Printf("title  : %s\n", t.Title)
	fmt.Printf("sha256 : %s\n", hex.EncodeToString(sum[:]))
}
