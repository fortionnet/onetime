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

// Brand holds the default brand: brand.json and the files it names. An
// operator replaces it as a whole by pointing ONETIME_BRAND_DIR at a directory
// of the same shape; see internal/brand.
//
//go:embed brand
var Brand embed.FS
