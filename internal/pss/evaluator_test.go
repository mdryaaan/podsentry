package pss

import "testing"

func TestHighestCompliantLevel(t *testing.T) {
	if got := HighestCompliantLevel(compliantRestrictedSpec()); got != LevelRestricted {
		t.Errorf("expected restricted spec to report LevelRestricted, got %v", got)
	}

	if got := HighestCompliantLevel(compliantBaselineSpec()); got != LevelBaseline {
		t.Errorf("expected baseline-only spec to report LevelBaseline, got %v", got)
	}

	privileged := compliantBaselineSpec()
	privileged.HostNetwork = true
	if got := HighestCompliantLevel(privileged); got != LevelPrivileged {
		t.Errorf("expected non-compliant spec to fall back to LevelPrivileged, got %v", got)
	}
}

func TestRulesForAccumulatesLowerLevels(t *testing.T) {
	rules := RulesFor(LevelRestricted)
	if len(rules) != len(BaselineRules())+len(RestrictedRules()) {
		t.Errorf("expected restricted rule set to include baseline rules, got %d rules", len(rules))
	}
}
