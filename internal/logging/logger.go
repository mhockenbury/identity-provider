// Package logging is the shared slog setup for the three IdP binaries
// (idp, docs-api, outbox-worker).
//
// Format selection via FormatFromEnv() reading LOG_FORMAT:
//   - "json" (default) — one JSON object per line; production / log-aggregation friendly.
//   - "pretty"         — colorized human-readable lines via lmittmann/tint;
//                        intended for `make dev-up` and standalone foreground runs.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lmittmann/tint"
)

// Format is the chosen output shape.
type Format int

const (
	FormatJSON Format = iota
	FormatPretty
)

// FormatFromEnv reads LOG_FORMAT and returns the matching Format.
// Anything other than "pretty" maps to FormatJSON (the safe default).
func FormatFromEnv() Format {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LOG_FORMAT")), "pretty") {
		return FormatPretty
	}
	return FormatJSON
}

// New builds the slog.Logger. w is typically os.Stdout.
func New(w io.Writer, level slog.Level, format Format) *slog.Logger {
	var h slog.Handler
	switch format {
	case FormatPretty:
		// NoColor: false forces ANSI emission even when stdout isn't a
		// TTY. We need this because `make dev-up` runs each binary as
		// `nohup ... > file.log`, which is a pipe — tint's default
		// auto-detection would strip colors. The downstream multitail
		// consumes the escapes and renders them.
		h = tint.NewHandler(w, &tint.Options{
			Level:      level,
			TimeFormat: time.TimeOnly, // 21:30:42 — date is noise during a dev session
			NoColor:    false,
		})
	default:
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	}
	return slog.New(h)
}
