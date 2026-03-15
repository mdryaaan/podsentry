package userns

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestInspectIsolatedNoConflicts(t *testing.T) {
	spec := corev1.PodSpec{
		HostUsers:  boolPtr(false),
		Containers: []corev1.Container{{Name: "app"}},
	}

	report := Inspect(spec)
	if report.Mode != MappingIsolated {
		t.Errorf("expected isolated mode, got %v", report.Mode)
	}
	if len(report.Conflicts) != 0 {
		t.Errorf("expected no conflicts, got %v", report.Conflicts)
	}
	if len(report.Implications) == 0 {
		t.Error("expected implications to be populated")
	}
}

func TestInspectHostSharedHasNoConflictChecks(t *testing.T) {
	spec := corev1.PodSpec{
		HostNetwork: true,
		Containers:  []corev1.Container{{Name: "app"}},
	}

	report := Inspect(spec)
	if report.Mode != MappingHostShared {
		t.Errorf("expected host-shared mode, got %v", report.Mode)
	}
	if len(report.Conflicts) != 0 {
		t.Errorf("expected no conflicts to be reported for host-shared mode, got %v", report.Conflicts)
	}
}

func TestDetectConflictsPrivilegedContainer(t *testing.T) {
	spec := corev1.PodSpec{
		HostUsers: boolPtr(false),
		Containers: []corev1.Container{
			{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}},
		},
	}

	conflicts := DetectConflicts(spec)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", conflicts)
	}
}

func TestDetectConflictsHostNamespacesAndHostPath(t *testing.T) {
	spec := corev1.PodSpec{
		HostUsers:   boolPtr(false),
		HostNetwork: true,
		HostPID:     true,
		Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
		},
		Containers: []corev1.Container{{Name: "app"}},
	}

	conflicts := DetectConflicts(spec)
	if len(conflicts) != 3 {
		t.Fatalf("expected 3 conflicts (hostNetwork, hostPID, hostpath volume), got %v", conflicts)
	}
}
