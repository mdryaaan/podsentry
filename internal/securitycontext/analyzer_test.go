package securitycontext

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func hardenedSpec() corev1.PodSpec {
	return corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: boolPtr(false),
					RunAsNonRoot:             boolPtr(true),
					RunAsUser:                int64Ptr(1000),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			},
		},
	}
}

func TestAnalyzeHardenedContainerHasNoWarnings(t *testing.T) {
	audit := Analyze(hardenedSpec())
	if len(audit.Containers) != 1 {
		t.Fatalf("expected 1 container audit, got %d", len(audit.Containers))
	}
	if warnings := audit.Containers[0].Warnings; len(warnings) != 0 {
		t.Errorf("expected no warnings for hardened container, got %v", warnings)
	}
}

func TestAnalyzeFlagsPrivilegedContainer(t *testing.T) {
	spec := hardenedSpec()
	spec.Containers[0].SecurityContext.Privileged = boolPtr(true)

	audit := Analyze(spec)
	if !containsWarning(audit.Containers[0].Warnings, "container runs as privileged") {
		t.Errorf("expected privileged warning, got %v", audit.Containers[0].Warnings)
	}
}

func TestAnalyzeFlagsMissingSeccomp(t *testing.T) {
	spec := hardenedSpec()
	spec.SecurityContext.SeccompProfile = nil

	audit := Analyze(spec)
	if !containsWarning(audit.Containers[0].Warnings, "no seccomp profile configured") {
		t.Errorf("expected missing seccomp warning, got %v", audit.Containers[0].Warnings)
	}
}

func TestAnalyzeHostNamespace(t *testing.T) {
	spec := hardenedSpec()
	spec.HostNetwork = true
	spec.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 9090}}

	audit := Analyze(spec)
	if !audit.HostNamespace.HostNetwork {
		t.Error("expected HostNetwork to be true")
	}
	if len(audit.HostNamespace.HostPorts) != 1 || audit.HostNamespace.HostPorts[0] != 9090 {
		t.Errorf("expected host port 9090, got %v", audit.HostNamespace.HostPorts)
	}
}

func containsWarning(warnings []string, want string) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}
