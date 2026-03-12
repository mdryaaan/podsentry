package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func int64Ptr(i int64) *int64 { return &i }

func compliantRestrictedSpec() corev1.PodSpec {
	return corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   boolPtr(true),
			RunAsUser:      int64Ptr(1000),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: boolPtr(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			},
		},
	}
}

func TestRestrictedRequiresNonRoot(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.SecurityContext.RunAsNonRoot = boolPtr(false)

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected runAsNonRoot=false to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-run-as-non-root")
}

func TestRestrictedRequiresPrivilegeEscalationFalse(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected missing allowPrivilegeEscalation to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-privilege-escalation")
}

func TestRestrictedRequiresDropAll(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{}

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected missing capabilities.drop=ALL to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-capabilities")
}

func TestRestrictedRejectsRunAsRoot(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.Containers[0].SecurityContext.RunAsUser = int64Ptr(0)

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected runAsUser=0 to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-run-as-user")
}

func TestRestrictedRejectsBadSeccomp(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected Unconfined seccomp to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-seccomp")
}

func TestRestrictedRejectsDisallowedVolumeType(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.Volumes = []corev1.Volume{
		{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
	}

	result := Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected hostPath volume to violate restricted")
	}
	assertHasRule(t, result.Findings, "restricted-volume-types")
}

func TestRestrictedCompliantSpecPasses(t *testing.T) {
	result := Evaluate(compliantRestrictedSpec(), LevelRestricted)
	if !result.Compliant {
		t.Fatalf("expected compliant spec to pass restricted, findings: %+v", result.Findings)
	}
}

func TestRestrictedOnlyAllowsNetBindServiceAdd(t *testing.T) {
	spec := compliantRestrictedSpec()
	spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}

	result := Evaluate(spec, LevelRestricted)
	if !result.Compliant {
		t.Fatalf("expected NET_BIND_SERVICE add-back to be allowed, findings: %+v", result.Findings)
	}

	spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
	result = Evaluate(spec, LevelRestricted)
	if result.Compliant {
		t.Fatal("expected SYS_ADMIN add-back to violate restricted")
	}
}
