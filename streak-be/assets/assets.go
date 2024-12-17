package assets

import "embed"

// The assets are embedded into the build at compile time.
//
//go:embed public templates
var FS embed.FS
