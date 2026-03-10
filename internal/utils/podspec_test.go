package utils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func TestUsesHostNamespace(t *testing.T) {
	cases := []struct {
		name string
		spec corev1.PodSpec
		want bool
	}{
		{"none", corev1.PodSpec{}, false},
		{"hostNetwork", corev1.PodSpec{HostNetwork: true}, true},
		{"hostPID", corev1.PodSpec{HostPID: true}, true},
		{"hostIPC", corev1.PodSpec{HostIPC: true}, true},
	}
	for _, c := range cases {
		if got := UsesHostNamespace(c.spec); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHostPorts(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "a", Ports: []corev1.ContainerPort{{HostPort: 8080}, {ContainerPort: 80}}},
		},
	}
	ports := HostPorts(spec)
	if len(ports) != 1 || ports[0] != 8080 {
		t.Errorf("unexpected host ports: %v", ports)
	}
}

func TestHostPathVolumes(t *testing.T) {
	spec := corev1.PodSpec{
		Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}},
			{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
		},
	}
	names := HostPathVolumes(spec)
	if len(names) != 1 || names[0] != "data" {
		t.Errorf("unexpected hostpath volumes: %v", names)
	}
}

func TestEffectiveRunAsNonRootFallsBackToPod(t *testing.T) {
	spec := corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
	}
	container := corev1.Container{Name: "app"}

	got := EffectiveRunAsNonRoot(spec, container)
	if got == nil || !*got {
		t.Fatalf("expected true from pod-level fallback, got %v", got)
	}

	container.SecurityContext = &corev1.SecurityContext{RunAsNonRoot: boolPtr(false)}
	got = EffectiveRunAsNonRoot(spec, container)
	if got == nil || *got {
		t.Fatalf("expected container override to win, got %v", got)
	}
}

func TestEffectiveRunAsUserFallsBackToPod(t *testing.T) {
	spec := corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{RunAsUser: int64Ptr(1000)}}
	container := corev1.Container{Name: "app"}

	got := EffectiveRunAsUser(spec, container)
	if got == nil || *got != 1000 {
		t.Fatalf("expected 1000 from pod-level fallback, got %v", got)
	}
}

func TestEffectiveSeccompProfileFallsBackToPod(t *testing.T) {
	podProfile := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	spec := corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{SeccompProfile: podProfile}}
	container := corev1.Container{Name: "app"}

	got := EffectiveSeccompProfile(spec, container)
	if got == nil || got.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("expected RuntimeDefault from pod-level fallback, got %v", got)
	}

	containerProfile := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost}
	container.SecurityContext = &corev1.SecurityContext{SeccompProfile: containerProfile}
	got = EffectiveSeccompProfile(spec, container)
	if got == nil || got.Type != corev1.SeccompProfileTypeLocalhost {
		t.Fatalf("expected container override to win, got %v", got)
	}
}
