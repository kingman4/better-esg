package server

import (
	"io/fs"
	"net/http"
)

// staticFileServer returns an http.Handler that serves static files from the given filesystem.
func staticFileServer(staticFiles fs.FS) http.Handler {
	return http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles)))
}
