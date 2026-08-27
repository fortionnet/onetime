// Package httpx holds the HTTP plumbing: middleware, security headers, the
// anti-prefetch gate and the error format.
package httpx

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Problem is an RFC 9457 error document.
//
// Code is the contract: a stable machine-readable string that the web UI, the
// CLI examples and the docs all key off, so one failure is described the same
// way everywhere. Detail is for humans and never echoes anything the client
// sent, because the things clients send here are secrets.
type Problem struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
	Example  string `json:"example,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Error codes. These are part of the public API surface.
const (
	CodeNotFound            = "not_found"
	CodeAlreadyRevealed     = "already_revealed"
	CodeBurned              = "burned"
	CodeDestroyed           = "destroyed"
	CodePassphraseRequired  = "passphrase_required"
	CodeBadPassphrase       = "bad_passphrase"
	CodeTooManyAttempts     = "too_many_attempts"
	CodeConfirmationNeeded  = "confirmation_required"
	CodePayloadTooLarge     = "payload_too_large"
	CodeEmpty               = "empty"
	CodeStorageFull         = "storage_full"
	CodeFilesDisabled       = "files_disabled"
	CodeReadOnly            = "read_only"
	CodeQuotaExceeded       = "quota_exceeded"
	CodeTicketExpired       = "ticket_expired"
	CodeInvalidTTL          = "invalid_ttl"
	CodeRateLimited         = "rate_limited"
	CodeSecretInQuery       = "secret_in_query"
	CodeBadRequest          = "bad_request"
	CodeMethodNotAllowed    = "method_not_allowed"
	CodeUnsupportedMedia    = "unsupported_media_type"
	CodeInternal            = "internal"
	CodeServiceUnavailable  = "service_unavailable"
	CodeCrossOriginRejected = "cross_origin_rejected"
)

// DocsURL is advertised on every response so that a client which guessed wrong
// can find the right shape without a second round trip.
var DocsURL = "/llms.txt"

// WriteProblem renders an error.
//
// Content negotiation matters here beyond neatness: a shell one-liner piping
// through `curl -f` wants one line it can print, not JSON to parse, and an AI
// agent that gets a usage example back in the error body corrects itself
// without another request.
func WriteProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Onetime-Docs", DocsURL)

	if prefersPlainText(r) {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(p.Status)
		body := p.Title
		if p.Detail != "" {
			body += ": " + p.Detail
		}
		body += "\n"
		if p.Example != "" {
			body += "\n" + p.Example + "\n"
		}
		_, _ = w.Write([]byte(body))
		return
	}

	h.Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteRateLimited renders a throttling response with the retry hint clients
// and proxies both understand.
func WriteRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	secs := int(retryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	WriteProblem(w, r, Problem{
		Status: http.StatusTooManyRequests,
		Code:   CodeRateLimited,
		Title:  "Too many requests",
		Detail: "Wait " + strconv.Itoa(secs) + "s and try again.",
	})
}

// WriteJSON renders a success response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Onetime-Docs", DocsURL)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WritePlain renders a bare text response, used when a caller asked for
// text/plain and just wants the link on one line.
func WritePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Onetime-Docs", DocsURL)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// PrefersPlainText reports whether the caller wants a bare text response.
func PrefersPlainText(r *http.Request) bool { return prefersPlainText(r) }

func prefersPlainText(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || strings.Contains(accept, "application/problem+json") {
		return false
	}
	if strings.Contains(accept, "text/plain") {
		return true
	}
	// A bare curl sends "Accept: */*" and almost certainly wants to print the
	// result rather than parse it.
	if accept == "" || accept == "*/*" {
		return isCommandLineClient(r.UserAgent())
	}
	return false
}

func isCommandLineClient(ua string) bool {
	ua = strings.ToLower(ua)
	for _, prefix := range []string{"curl/", "wget/", "httpie/", "powershell/", "python-requests/", "go-http-client/"} {
		if strings.HasPrefix(ua, prefix) {
			return true
		}
	}
	return false
}
