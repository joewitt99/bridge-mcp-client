// Package version exposes the build version of okta-mcp-bridge.
package version

// Version is the bridge version. It is overridden at build time via:
//
//	-ldflags "-X github.com/joewitt99/bridge-mcp-client/internal/version.Version=<tag>"
//
// and falls back to this value for `go run` / un-stamped builds.
var Version = "0.1.0"
