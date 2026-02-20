// Package web embeds static assets for the web UI.
package web

import "embed"

//go:embed all:static
var StaticFS embed.FS
