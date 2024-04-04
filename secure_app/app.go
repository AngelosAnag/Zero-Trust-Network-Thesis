// A simple read/write web interface for Postgres in Go, only admin access allowed

package main

import (
	"fmt"
	"net/http"
)

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {
	http.HandleFunc("/", headers)

	http.ListenAndServe(":3001", nil)
}
