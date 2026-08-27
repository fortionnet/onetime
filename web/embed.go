// Package webassets carries the frontend into the binary.
//
// The embed directives have to live beside the files they embed, which is why
// this package sits here rather than under internal/. Everything that uses it
// goes through internal/web.
package webassets

import "embed"

// Templates holds the HTML templates.
//
//go:embed templates/*.gohtml
var Templates embed.FS

// Static holds the stylesheet, scripts and images.
//
//go:embed static
var Static embed.FS
