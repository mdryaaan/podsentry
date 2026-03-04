// Package version holds build-time version metadata for podsentry.
package version

import "fmt"

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Info bundles the version metadata reported by the version command.
type Info struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
	Platform  string
}

// String renders the version info as a single human-readable line.
func (i Info) String() string {
	return fmt.Sprintf("podsentry %s (commit %s, built %s) %s %s", i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}
