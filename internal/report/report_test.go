package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mdryaaan/podsentry/internal/pss"
)

func TestHasFailuresPSS(t *testing.T) {
	r := PodReport{PSS: &PSSSection{Compliant: false, Findings: []pss.Finding{{RuleID: "x"}}}}
	if !r.HasFailures() {
		t.Error("expected non-compliant PSS section to be a failure")
	}
}

func TestHasFailuresCompliant(t *testing.T) {
	r := PodReport{PSS: &PSSSection{Compliant: true}}
	if r.HasFailures() {
		t.Error("expected compliant report to have no failures")
	}
}

func TestHasFailuresUserNSConflicts(t *testing.T) {
	r := PodReport{UserNS: &UserNSSection{Conflicts: []string{"conflict"}}}
	if !r.HasFailures() {
		t.Error("expected user namespace conflicts to be a failure")
	}
}

func TestSummarize(t *testing.T) {
	reports := []PodReport{
		{PSS: &PSSSection{Compliant: true}},
		{PSS: &PSSSection{Compliant: false}},
	}
	s := Summarize(reports)
	if s.Total != 2 || s.Passed != 1 || s.Failed != 1 {
		t.Errorf("unexpected summary: %+v", s)
	}
}

func TestWriteJSON(t *testing.T) {
	reports := []PodReport{{PodName: "app", Path: "pod.yaml", PSS: &PSSSection{Compliant: true, TargetLevel: "baseline"}}}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, reports); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var decoded []PodReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode written json: %v", err)
	}
	if len(decoded) != 1 || decoded[0].PodName != "app" {
		t.Errorf("unexpected decoded reports: %+v", decoded)
	}
}
