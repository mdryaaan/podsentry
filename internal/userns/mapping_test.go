package userns

import "testing"

func boolPtr(b bool) *bool { return &b }

func TestModeDefaultsToHostShared(t *testing.T) {
	if got := Mode(nil); got != MappingHostShared {
		t.Errorf("expected nil hostUsers to default to host-shared, got %v", got)
	}
}

func TestModeExplicitTrueIsHostShared(t *testing.T) {
	if got := Mode(boolPtr(true)); got != MappingHostShared {
		t.Errorf("expected hostUsers=true to be host-shared, got %v", got)
	}
}

func TestModeExplicitFalseIsIsolated(t *testing.T) {
	if got := Mode(boolPtr(false)); got != MappingIsolated {
		t.Errorf("expected hostUsers=false to be isolated, got %v", got)
	}
}
