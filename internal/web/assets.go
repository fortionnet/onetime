package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
)

// assets serves the embedded static files with content-addressed URLs.
//
// The hash is computed once at startup from the embedded bytes, which is all
// the cache busting a single binary needs — no build step, no manifest file to
// keep in sync, and nothing that can drift from what is actually being served.
type assets struct {
	fsys    fs.FS
	hashed  map[string]string // "css/app.css" -> "/static/css/app.<hash>.css"
	byPath  map[string]string // "css/app.<hash>.css" -> "css/app.css"
	etag    map[string]string // "css/app.css" -> `"<hash>"`
	once    sync.Once
	handler http.Handler
}

func newAssets(fsys fs.FS) *assets {
	a := &assets{
		fsys:   fsys,
		hashed: map[string]string{},
		byPath: map[string]string{},
		etag:   map[string]string{},
	}
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])[:10]
		ext := path.Ext(p)
		stem := strings.TrimSuffix(p, ext)
		hashedRel := stem + "." + digest + ext
		a.hashed[p] = "/static/" + hashedRel
		a.byPath[hashedRel] = p
		a.etag[p] = `"` + digest + `"`
		return nil
	})
	return a
}

// URL returns the content-addressed URL for a logical asset path.
func (a *assets) URL(logical string) string {
	if u, ok := a.hashed[logical]; ok {
		return u
	}
	return "/static/" + logical
}

// ServeHTTP serves a static file, resolving the content hash back to the real
// name.
//
// Two caching regimes, and the difference matters. A hashed URL names exactly
// one version of one file, so it is immutable and can be cached for a year.
// An unhashed URL cannot be: the entry script is content-addressed, but the
// page modules it reaches with a relative import('./create.js') are not, so
// caching those by time means a browser can run last week's JavaScript against
// this week's markup for as long as the freshness window lasts.
//
// Every response therefore carries an ETag built from the same content digest
// used for the hashed name. Unhashed files are served no-cache, which means
// revalidate — not "do not store" — so the usual outcome is a 304 with no body
// rather than a full re-download.
func (a *assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.once.Do(func() {
		a.handler = http.FileServer(http.FS(a.fsys))
	})

	rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/static/")

	real, hashedURL := a.byPath[rel]
	if !hashedURL {
		real = rel
	}
	// The ETag has to be set before delegating: http.ServeContent evaluates
	// If-None-Match against whatever is already on the response header.
	if tag, ok := a.etag[real]; ok {
		w.Header().Set("ETag", tag)
	}
	if hashedURL {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	r = r.Clone(r.Context())
	r.URL.Path = "/" + real
	a.handler.ServeHTTP(w, r)
}
