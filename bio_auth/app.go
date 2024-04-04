package main

import (
	"fmt"
	"net/http"
)

type FingerprintAuthenticator interface {
	CheckFingerprint(username string) bool
}

func (m *MockFingerprintAuthenticator) CheckFingerprint() bool {
	// Placeholder implementation, always returns true
	return true
}

type MockFingerprintAuthenticator struct{}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func authenticationHandler(w http.ResponseWriter, req *http.Request) {
	fingerprintAuthenticator := &MockFingerprintAuthenticator{}
	if fingerprintAuthenticator.CheckFingerprint() {
		w.Write([]byte("Authentication completed"))
	}
}

func main() {
	http.HandleFunc("/", headers)
	http.HandleFunc("/auth", authenticationHandler)

	http.ListenAndServe(":3002", nil)
}
