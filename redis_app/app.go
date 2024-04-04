// A simple read/write web interface for Redis in Go, all users should have access to this

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	redis "github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // no password set
	DB:       0,  // use default DB
})

func readHandler(w http.ResponseWriter, req *http.Request) {
	// Read the url query and extract key to read
	key := req.URL.RawQuery
	val, err := rdb.Get(ctx, key).Result()

	if err == redis.Nil {
		fmt.Fprintf(w, "%s does not exist", key)
	} else if err != nil {
		panic(err)
	} else {
		fmt.Fprintf(w, "Key: %s \t Value: %s\n", key, val)
	}

}

func writeHandler(w http.ResponseWriter, req *http.Request) {
	// Read the url query and extract key to write
	data := strings.Split(req.URL.RawQuery, "?")
	err := rdb.Set(ctx, data[0], data[1], 0).Err()
	if err != nil {
		panic(err)
	}
}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {

	http.HandleFunc("/read", readHandler)
	http.HandleFunc("/write", writeHandler)

	http.HandleFunc("/", headers)

	http.ListenAndServe(":3000", nil)
}
