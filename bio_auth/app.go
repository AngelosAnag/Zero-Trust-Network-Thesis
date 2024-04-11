package main

import (
	"fmt"
	"net/http"
)

type FingerprintAuthenticator interface {
	// Interface w/ required methods for an MFA authenticator
	CheckFingerprint(username string) bool
}

func (m *FingerprintAuthenticatorMFA) CheckFingerprint() bool {
	// Placeholder implementation, always returns true
	return true
}

type FingerprintAuthenticatorMFA struct{}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func authenticationHandler(w http.ResponseWriter, req *http.Request) {
	// Run MFA on the user and update his cookie
	fingerprintAuthenticator := &FingerprintAuthenticatorMFA{}
	fmt.Println(req.Header)
	if fingerprintAuthenticator.CheckFingerprint() {
		cookie := http.Cookie{
			Name:  "user-session",
			Value: "authenticated",
			Path:  "/",
		}
		req.AddCookie(&cookie)
		http.SetCookie(w, &cookie)
		redirectTo := req.URL.Query().Get("redirect")
		http.Redirect(w, req, redirectTo, http.StatusTemporaryRedirect)
	}
}

func main() {
	http.HandleFunc("/", headers)
	http.HandleFunc("/auth", authenticationHandler)

	http.ListenAndServe(":3002", nil)
}
