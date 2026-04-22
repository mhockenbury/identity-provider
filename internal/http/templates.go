package http

import (
	"embed"
	"fmt"
	"html/template"
)

// Templates live in templates/ next to this file and are embedded at
// build time so the binary has no filesystem dependency.
//
// We use html/template (not text/template) exclusively. That's the
// whole point — it context-aware-escapes user data we pass in. A future
// handler that tries to .Execute a text/template with user input would
// be an XSS vector, so keep this as the single chokepoint.

//go:embed templates/*.html
var templateFS embed.FS

// Templates bundles the parsed template set. Construct once at startup
// via ParseTemplates; handlers get a pointer and call methods that wrap
// ExecuteTemplate with their specific page.
type Templates struct {
	set *template.Template
}

// ParseTemplates parses all HTML files in the embedded FS. Returns an
// error if any template fails to parse — callers should fail startup,
// not continue with a broken template set.
func ParseTemplates() (*Templates, error) {
	// ParseFS treats the pattern as a glob. Each file becomes a named
	// template (by basename), so we can ExecuteTemplate("login.html", ...).
	t, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Templates{set: t}, nil
}
