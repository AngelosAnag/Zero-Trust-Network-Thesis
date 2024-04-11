// A simple webpage with protected endpoints in Go, admin and user accounts have different access levels

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

var routesMap = map[string]string{
	"/admin-resource": "protected",
	"/user-resource":  "unprotected",
}

func mfaHandler(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/bio-mfa/auth", http.StatusTemporaryRedirect)
}

func protectedResourceHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello from protected resource\nFor admin eyes only!"))
}

func unprotectedResourceHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello from unprotected resource\nPlain for all to see!"))
}

func MFAMiddleware(next http.Handler) http.Handler {
	// Check if the user is authenticated with MFA via his cookie
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("user-session")
		if err != nil {
			http.Error(w, "No cookie found", http.StatusUnauthorized)
			return
		}
		passedMFA := cookie.Value
		clickedLink := req.Header.Get("X-Forwarded-Path")

		if passedMFA == "authenticated" {
			next.ServeHTTP(w, req)
		} else {
			http.Redirect(w, req, "/bio-mfa/auth?redirect="+clickedLink, http.StatusSeeOther)
			return
		}
	})
}

func authorizationMiddleware(next http.Handler) http.Handler {
	// Check the user type and his access level
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Println(req.Header)
		userType := req.Header.Get("X-Consumer-Custom-Id")
		resourceTag := routesMap[req.URL.Path]

		// This serves as our ACL but is a simple OR statement since we only have 2 users
		if (resourceTag == "unprotected") || (resourceTag == "protected" && userType == "admin") {
			next.ServeHTTP(w, req)
		} else {
			http.Error(w, "Not an admin", http.StatusForbidden)
			return
		}

	})
}

func main() {

	router := mux.NewRouter()

	//Serves an html page with server's resources
	fs := http.FileServer(http.Dir("./static"))
	router.Handle("/", fs)

	router.Handle("/mfa-redirect", http.HandlerFunc(mfaHandler))

	// This is where basic IAM is performed, however both user types (admin/user)
	// have to pass MFA in order to view resources
	router.Handle("/admin-resource", MFAMiddleware(authorizationMiddleware(http.HandlerFunc(protectedResourceHandler))))
	router.Handle("/user-resource", MFAMiddleware(authorizationMiddleware(http.HandlerFunc(unprotectedResourceHandler))))

	http.Handle("/", router)

	http.ListenAndServe(":3001", nil)
}
