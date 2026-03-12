package pss

import "testing"

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"privileged": LevelPrivileged,
		"baseline":   LevelBaseline,
		"restricted": LevelRestricted,
	}
	for input, want := range cases {
		got, err := ParseLevel(input)
		if err != nil {
			t.Fatalf("ParseLevel(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", input, got, want)
		}
	}

	if _, err := ParseLevel("unknown"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestLevelString(t *testing.T) {
	if LevelBaseline.String() != "baseline" {
		t.Errorf("expected baseline, got %s", LevelBaseline.String())
	}
}

func TestLevelAtMost(t *testing.T) {
	got := LevelRestricted.AtMost()
	want := []Level{LevelRestricted, LevelBaseline, LevelPrivileged}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
