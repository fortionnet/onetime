package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// SecurityHeaders applies the response headers every route needs.
//
// A per-response nonce is generated for the content security policy so that
// templates can inline the small amount of bootstrap script they need without
// opening the door to 'unsafe-inline'. Templates read it with NonceFrom.
func SecurityHeaders(baseURL string) Middleware {
	connectSrc := "'self'"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := randomNonce()
			h := w.Header()
			h.Set("Content-Security-Policy", strings.Join([]string{
				"default-src 'self'",
				"script-src 'self' 'nonce-" + nonce + "'",
				"style-src 'self' 'nonce-" + nonce + "' https://fonts.googleapis.com",
				"font-src 'self' https://fonts.gstatic.com",
				"img-src 'self' data:",
				"connect-src " + connectSrc,
				"form-action 'self'",
				"frame-ancestors 'none'",
				"base-uri 'none'",
				"object-src 'none'",
			}, "; "))
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), interest-cohort=()")
			if strings.HasPrefix(baseURL, "https://") {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxNonce, nonce)))
		})
	}
}

// NoStore marks a response as never cacheable and never indexable. It applies
// to every route that touches a secret, including the HTML shells: a cached
// copy of a recipient page in a corporate proxy is a copy of something that was
// supposed to exist once.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
		next.ServeHTTP(w, r)
	})
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "static"
	}
	return base64.RawStdEncoding.EncodeToString(buf)
}
