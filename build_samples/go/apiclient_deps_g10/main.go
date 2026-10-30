// apiclient_deps_g10 - Go build variant: REAL DEPENDENCIES (HTTP + JSON + crypto).
// Builds a JSON payload, AES-GCM encrypts it, and would POST it over HTTP.
// Uses the third-party module github.com/google/uuid.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

type event struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
}

func seal(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func main() {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	ev := event{ID: uuid.NewString(), Kind: "sample", Payload: "hello from apiclient"}
	raw, _ := json.Marshal(ev)

	enc, err := seal(key, raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encrypt error:", err)
		os.Exit(1)
	}
	fmt.Printf("event id   : %s\n", ev.ID)
	fmt.Printf("ciphertext : %s\n", enc)

	url := "https://httpbin.org/post"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "post skipped (offline?):", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("post status: %s\n", resp.Status)
}
