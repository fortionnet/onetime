package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Health answers the Kubernetes probes.
//
// The split between the two probes matters. Liveness reports only whether the
// process is functioning, with no dependency checks at all: if it consulted
// Redis, a brief Redis blip would kill the pod, and restarting the pod does
// nothing to fix Redis. Readiness is where dependencies belong, because taking
// the pod out of rotation while a dependency is down is exactly right.
type Health struct {
	checks   map[string]CheckFunc
	mu       sync.Mutex
	cache    map[string]cachedResult
	cacheFor time.Duration
	ready    func() bool
}

// CheckFunc reports whether one dependency is usable.
type CheckFunc func(context.Context) error

type cachedResult struct {
	err error
	at  time.Time
}

// NewHealth builds a health reporter.
func NewHealth() *Health {
	return &Health{
		checks:   map[string]CheckFunc{},
		cache:    map[string]cachedResult{},
		cacheFor: 10 * time.Second,
	}
}

// Register adds a readiness check.
func (h *Health) Register(name string, fn CheckFunc) {
	h.checks[name] = fn
}

// SetStarted registers a predicate for the startup probe.
func (h *Health) SetStarted(fn func() bool) { h.ready = fn }

// Live handles the liveness probe.
func (h *Health) Live(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeBody(w, `{"status":"ok"}`)
}

// Started handles the startup probe.
func (h *Health) Started(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if h.ready != nil && !h.ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeBody(w, `{"status":"starting"}`)
		return
	}
	writeBody(w, `{"status":"ok"}`)
}

// Ready handles the readiness probe, reporting each dependency separately so
// that a failing probe says which one is at fault.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	results := make(map[string]string, len(h.checks))
	healthy := true
	for name, fn := range h.checks {
		if err := h.run(ctx, name, fn); err != nil {
			healthy = false
			results[name] = "fail: " + err.Error()
			continue
		}
		results[name] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSONBody(w, map[string]any{
		"status": statusWord(healthy),
		"checks": results,
	})
}

// writeBody and writeJSONBody send a probe response whose headers have already
// gone out. A write failure here cannot be turned into a different answer, and
// the only realistic cause is a kubelet that gave up before we replied — which
// it will treat as a failed probe regardless of what we do next.
func writeBody(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body + "\n")) //nolint:errcheck // response already in flight; nothing actionable
}

func writeJSONBody(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // response already in flight; nothing actionable
}

// run applies a short cache so that a probe every few seconds does not turn
// into a filesystem probe every few seconds.
func (h *Health) run(ctx context.Context, name string, fn CheckFunc) error {
	h.mu.Lock()
	if got, ok := h.cache[name]; ok && time.Since(got.at) < h.cacheFor {
		h.mu.Unlock()
		return got.err
	}
	h.mu.Unlock()

	err := fn(ctx)

	h.mu.Lock()
	h.cache[name] = cachedResult{err: err, at: time.Now()}
	h.mu.Unlock()
	return err
}

func statusWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "degraded"
}
