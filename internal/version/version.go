// Package version holds the PortcullisMCP suite version.
// Update Version on every change before committing.
// The Makefile overrides this at build time via:
//
//	go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=x.y.z"
package version

var Version = "0.1.0"
