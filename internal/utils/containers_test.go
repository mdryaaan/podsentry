package utils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAllContainersOrdersInitAppEphemeral(t *testing.T) {
	spec := corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init-1"}},
		Containers:     []corev1.Container{{Name: "app-1"}, {Name: "app-2"}},
		EphemeralContainers: []corev1.EphemeralContainer{
			{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-1"}},
		},
	}

	refs := AllContainers(spec)
	if len(refs) != 4 {
		t.Fatalf("expected 4 containers, got %d", len(refs))
	}

	want := []struct {
		name string
		kind string
	}{
		{"init-1", ContainerKindInit},
		{"app-1", ContainerKindApp},
		{"app-2", ContainerKindApp},
		{"debug-1", ContainerKindEphemeral},
	}
	for i, w := range want {
		if refs[i].Container.Name != w.name || refs[i].Kind != w.kind {
			t.Errorf("index %d: got name=%s kind=%s, want name=%s kind=%s", i, refs[i].Container.Name, refs[i].Kind, w.name, w.kind)
		}
	}
}

func TestContainerNames(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{{Name: "a"}, {Name: "b"}},
	}
	names := ContainerNames(spec)
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Errorf("unexpected names: %v", names)
	}
}
