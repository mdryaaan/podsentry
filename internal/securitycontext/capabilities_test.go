package securitycontext

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAnalyzeCapabilitiesNoSecurityContext(t *testing.T) {
	report := AnalyzeCapabilities(corev1.Container{Name: "app"})
	if report.DropsAll {
		t.Error("expected DropsAll false when no security context is set")
	}
	if len(report.Added) != 0 {
		t.Errorf("expected no added capabilities, got %v", report.Added)
	}
}

func TestAnalyzeCapabilitiesDropsAll(t *testing.T) {
	c := corev1.Container{
		Name: "app",
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_BIND_SERVICE"}},
		},
	}
	report := AnalyzeCapabilities(c)
	if !report.DropsAll {
		t.Error("expected DropsAll true")
	}
	if len(report.DisallowedAdded) != 0 {
		t.Errorf("expected NET_BIND_SERVICE to be allowed, got disallowed: %v", report.DisallowedAdded)
	}
}

func TestAnalyzeCapabilitiesFlagsDisallowedAdd(t *testing.T) {
	c := corev1.Container{
		Name: "app",
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"SYS_ADMIN"}},
		},
	}
	report := AnalyzeCapabilities(c)
	if len(report.DisallowedAdded) != 1 || report.DisallowedAdded[0] != "SYS_ADMIN" {
		t.Errorf("expected SYS_ADMIN flagged as disallowed, got %v", report.DisallowedAdded)
	}
}
