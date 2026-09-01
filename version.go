// Package tsvvpn holds the release version and embedded changelog; it lives at
// the module root so CHANGELOG.md can be embedded.
package tsvvpn

import _ "embed"

// Versioning: year.major.minor.patch.
const Version = "2026.1.0.0"

//go:embed CHANGELOG.md
var Changelog string
