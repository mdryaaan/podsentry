package pss

// PrivilegedRules returns the rules enforced at the Privileged level, which
// is intentionally unrestricted: it exists so callers always have a
// baseline profile to compare against, not because it imposes any checks
// of its own.
func PrivilegedRules() []Rule {
	return nil
}
