// Package docs carries the agent-facing documentation into the binary.
//
// llms.txt is a Go template rather than a static file so that the limits it
// quotes are the limits the running instance actually enforces. Documentation
// that drifts from the deployment is worse than none: an agent that trusts a
// stale size limit produces a confusing failure instead of a clear one.
package docs

import "embed"

// FS holds the documentation sources.
//
//go:embed llms.txt openapi.json
var FS embed.FS
