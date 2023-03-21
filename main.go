package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type Payload struct {
	Action string `json:"action"`
}

func main() {
	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
		if secret == "" {
			http.Error(w, "Secret not set", http.StatusInternalServerError)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		signature := r.Header.Get("X-Hub-Signature")
		if signature == "" {
			http.Error(w, "Signature not set", http.StatusBadRequest)
			return
		}

		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(body)
		expectedMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature[5:]), []byte(expectedMAC)) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		var payload Payload
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Printf("Received event: %s", payload.Action)
	})

	log.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
