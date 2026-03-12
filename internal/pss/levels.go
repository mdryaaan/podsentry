package pss

import (
	"encoding/json"
	"fmt"
)

// Level identifies one of the three official Pod Security Standard
// profiles, ordered from least to most restrictive.
type Level int

const (
	LevelPrivileged Level = iota
	LevelBaseline
	LevelRestricted
)

// String renders the level using the canonical lowercase name used in the
// upstream Pod Security Standards documentation.
func (l Level) String() string {
	switch l {
	case LevelPrivileged:
		return "privileged"
	case LevelBaseline:
		return "baseline"
	case LevelRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the level as its canonical lowercase name.
func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// ParseLevel converts a user-supplied level name into a Level.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "privileged":
		return LevelPrivileged, nil
	case "baseline":
		return LevelBaseline, nil
	case "restricted":
		return LevelRestricted, nil
	default:
		return LevelPrivileged, fmt.Errorf("unknown pod security standard level %q, expected privileged, baseline or restricted", s)
	}
}

// AtMost returns the levels up to and including l, ordered from most to
// least restrictive, matching how a pod is evaluated against a target
// level: it must satisfy every rule at that level and below.
func (l Level) AtMost() []Level {
	levels := make([]Level, 0, l+1)
	for i := l; i >= LevelPrivileged; i-- {
		levels = append(levels, i)
	}
	return levels
}
