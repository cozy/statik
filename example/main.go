//go:generate statik -src=./public

package main

import (
	"log"
	"net/http"

	_ "github.com/cozy/statik/example/statik"
	"github.com/cozy/statik/fs"
)

// Before buildling, run go generate.
// Then, run the main program and visit http://localhost:8080/public/hello.txt
func main() {
	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/public/", statikFS.Handler("/public"))
	http.ListenAndServe(":8080", nil)
}
