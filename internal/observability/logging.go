package observability

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger builds the application logger.
//
// The redaction guarantee this service makes does not live here — it lives in
// the types, which implement slog.LogValuer and render as [REDACTED]. That is
// deliberate: a handler-level filter has to guess which fields are sensitive,
// whereas a type that refuses to render itself is correct at every call site,
// including ones written later by someone who has not read this comment.
func NewLogger(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	if strings.EqualFold(format, "text") {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
