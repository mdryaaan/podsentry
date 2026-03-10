package utils

import corev1 "k8s.io/api/core/v1"

// ContainerRef pairs a container with a human-readable label describing
// which section of the PodSpec it came from.
type ContainerRef struct {
	Container corev1.Container
	Kind      string
}

const (
	ContainerKindInit      = "init"
	ContainerKindApp       = "app"
	ContainerKindEphemeral = "ephemeral"
)

// AllContainers returns every container defined in the pod spec, spanning
// init containers, regular containers and ephemeral containers, in that
// order.
func AllContainers(spec corev1.PodSpec) []ContainerRef {
	refs := make([]ContainerRef, 0, len(spec.InitContainers)+len(spec.Containers)+len(spec.EphemeralContainers))

	for _, c := range spec.InitContainers {
		refs = append(refs, ContainerRef{Container: c, Kind: ContainerKindInit})
	}
	for _, c := range spec.Containers {
		refs = append(refs, ContainerRef{Container: c, Kind: ContainerKindApp})
	}
	for _, ec := range spec.EphemeralContainers {
		refs = append(refs, ContainerRef{
			Container: corev1.Container(ec.EphemeralContainerCommon),
			Kind:      ContainerKindEphemeral,
		})
	}

	return refs
}

// ContainerNames returns the names of every container in the pod spec.
func ContainerNames(spec corev1.PodSpec) []string {
	refs := AllContainers(spec)
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Container.Name)
	}
	return names
}
