//go:generate statik -src=./public

package main

import (
	"net/http"

	_ "github.com/cozy/statik/example/statik"
	statikFS "github.com/cozy/statik/fs"
)

// Before buildling, run go generate.
// Then, run the main program and visit http://localhost:8080/public/hello.txt
func main() {
	http.Handle("/public/", statikFS.Handler("/public"))
	http.ListenAndServe(":8080", nil)
}
