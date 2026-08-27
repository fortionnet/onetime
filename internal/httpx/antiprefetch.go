package httpx

import (
	"net/http"
	"strings"
)

// Link preview bots. This list only ever guards HTML routes, never the API:
// blocking by user agent on /api would break exactly the CLI and agent use
// cases the service exists for, which is the mistake the reference
// implementation makes when it denies "curl" outright.
var previewBots = []string{
	"slackbot", "facebookexternalhit", "twitterbot", "whatsapp", "telegrambot",
	"discordbot", "linkedinbot", "skypeuripreview", "microsoft office existence discovery",
	"google-read-aloud", "bingbot", "googlebot", "applebot", "yandexbot",
	"embedly", "quora link preview", "outbrain", "vkshare", "redditbot",
}

// IsPreviewBot reports whether a user agent belongs to a known link unfurler.
func IsPreviewBot(ua string) bool {
	ua = strings.ToLower(ua)
	for _, bot := range previewBots {
		if strings.Contains(ua, bot) {
			return true
		}
	}
	return false
}

// IsPrefetch reports whether the client announced that this request is
// speculative rather than a person acting.
func IsPrefetch(r *http.Request) bool {
	h := r.Header
	if p := h.Get("Sec-Purpose"); p != "" && strings.Contains(strings.ToLower(p), "prefetch") {
		return true
	}
	if strings.EqualFold(h.Get("Purpose"), "prefetch") {
		return true
	}
	if strings.EqualFold(h.Get("X-Moz"), "prefetch") {
		return true
	}
	if strings.EqualFold(h.Get("X-Purpose"), "preview") {
		return true
	}
	return false
}

// AntiPrefetch guards the endpoints that consume a secret.
//
// The strongest protection is not here at all: the decryption key lives in the
// URL fragment, which browsers never transmit, so a preview bot fetching the
// link has nothing to submit. This middleware is the backstop for the rest.
//
// The Sec-Fetch rules are enforced only when those headers are present. Every
// current browser sends them, and nothing else does — so a browser is held to
// same-origin scripted requests, while curl and an AI agent, which send no such
// headers, pass through untouched. Enforcing them unconditionally would break
// every non-browser client; ignoring them would let a bot navigate straight to
// a consuming endpoint.
func AntiPrefetch(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsPrefetch(r) {
				// Say nothing and touch nothing.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
				dest := r.Header.Get("Sec-Fetch-Dest")
				mode := r.Header.Get("Sec-Fetch-Mode")
				if site != "same-origin" && site != "none" {
					reject(w, r, "This endpoint only accepts same-origin requests from a browser.")
					return
				}
				// A real reveal is fetch() from our own page. A bot that follows
				// the link arrives as a document navigation.
				if dest != "empty" || mode != "cors" {
					reject(w, r, "This endpoint is not reachable by navigating to it.")
					return
				}
			}
			if origin := r.Header.Get("Origin"); origin != "" && allowedOrigin != "" && origin != allowedOrigin {
				reject(w, r, "Origin not allowed.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func reject(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, Problem{
		Status: http.StatusForbidden,
		Code:   CodeCrossOriginRejected,
		Title:  "Request rejected",
		Detail: detail,
	})
}
