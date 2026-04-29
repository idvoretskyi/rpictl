package version

// Version is injected at build time via ldflags:
// -X github.com/idvoretskyi/rpictl/internal/version.Version=v0.1.0
var Version = "dev"
