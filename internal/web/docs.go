package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"text/template"

	"github.com/fortionnet/onetime/docs"
)

// llmsDoc renders the agent-facing usage text.
//
// It is rendered once at first use from the running configuration rather than
// shipped as a static file, so the limits and hostname it quotes are the ones
// this instance actually enforces. An agent that reads a stale limit fails in a
// confusing way instead of a clear one.
type llmsDoc struct {
	once sync.Once
	body []byte
	err  error
}

func (h *Handler) handleLLMs(w http.ResponseWriter, _ *http.Request) {
	h.llms.once.Do(func() {
		tmpl, err := template.ParseFS(docs.FS, "llms.txt")
		if err != nil {
			h.llms.err = err
			return
		}
		host := baseHost(h.cfg.BaseURL)
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, map[string]any{
			"BaseURL": h.cfg.BaseURL,
			"Host":    host,
			// Formatted with the same helper the UI uses, so the documentation
			// cannot drift from what the interface tells people.
			"MaxFile":    humanBytes(h.cfg.MaxFileBytes, "en"),
			"MaxText":    humanBytes(h.cfg.MaxTextBytes, "en"),
			"TTLMin":     h.cfg.TTLMinDays,
			"TTLMax":     h.cfg.TTLMaxDays,
			"TTLDefault": h.cfg.TTLDefaultDays,
		})
		if err != nil {
			h.llms.err = err
			return
		}
		h.llms.body = buf.Bytes()
	})

	if h.llms.err != nil {
		h.log.Error("could not render llms.txt", "error", h.llms.err)
		http.Error(w, "documentation unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeBody(w, h.llms.body)
}

// specPlaceholder is the server URL written into docs/openapi.json. It is
// replaced with this instance's base URL when served, so a client generated
// from the spec talks to the instance it was fetched from.
const specPlaceholder = `"https://onetime.invalid"`

func (h *Handler) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	body, err := docs.FS.ReadFile("openapi.json")
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	if quoted, err := json.Marshal(h.cfg.BaseURL); err == nil {
		body = bytes.Replace(body, []byte(specPlaceholder), quoted, 1)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeBody(w, body)
}
