package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool { return &b }

func compliantBaselineSpec() corev1.PodSpec {
	return corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CHOWN"}},
				},
			},
		},
	}
}

func TestBaselinePrivilegedContainer(t *testing.T) {
	spec := compliantBaselineSpec()
	spec.Containers[0].SecurityContext.Privileged = boolPtr(true)

	result := Evaluate(spec, LevelBaseline)
	if result.Compliant {
		t.Fatal("expected privileged container to violate baseline")
	}
	assertHasRule(t, result.Findings, "baseline-privileged-containers")
}

func TestBaselineHostNamespaces(t *testing.T) {
	spec := compliantBaselineSpec()
	spec.HostNetwork = true

	result := Evaluate(spec, LevelBaseline)
	if result.Compliant {
		t.Fatal("expected hostNetwork to violate baseline")
	}
	assertHasRule(t, result.Findings, "baseline-host-namespaces")
}

func TestBaselineHostPathVolume(t *testing.T) {
	spec := compliantBaselineSpec()
	spec.Volumes = []corev1.Volume{
		{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
	}

	result := Evaluate(spec, LevelBaseline)
	if result.Compliant {
		t.Fatal("expected hostPath volume to violate baseline")
	}
	assertHasRule(t, result.Findings, "baseline-hostpath-volumes")
}

func TestBaselineDisallowedCapability(t *testing.T) {
	spec := compliantBaselineSpec()
	spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}

	result := Evaluate(spec, LevelBaseline)
	if result.Compliant {
		t.Fatal("expected SYS_ADMIN capability to violate baseline")
	}
	assertHasRule(t, result.Findings, "baseline-capabilities")
}

func TestBaselineCompliantSpecPasses(t *testing.T) {
	result := Evaluate(compliantBaselineSpec(), LevelBaseline)
	if !result.Compliant {
		t.Fatalf("expected compliant spec to pass baseline, findings: %+v", result.Findings)
	}
}

func assertHasRule(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Errorf("expected a finding for rule %q, got %+v", ruleID, findings)
}
