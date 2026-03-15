package userns

// MappingMode describes how container UIDs and GIDs relate to host UIDs
// and GIDs under the kubelet-managed user namespace feature.
type MappingMode string

const (
	// MappingIsolated means the pod runs in its own user namespace with a
	// kubelet-allocated, non-overlapping UID/GID range mapped to the host.
	// A process that appears to run as UID 0 inside the container maps to
	// an unprivileged, container-specific UID on the host.
	MappingIsolated MappingMode = "isolated"

	// MappingHostShared means the pod shares the host's user namespace, so
	// container UID 0 is host UID 0: a container-to-host escape of a
	// process running as root inside the container is also root outside
	// of it.
	MappingHostShared MappingMode = "host-shared"
)

// Mode returns the mapping mode implied by a pod's hostUsers setting.
// hostUsers defaults to true (host-shared) when unset, matching the
// upstream Kubernetes default prior to user namespaces being enabled by
// default.
func Mode(hostUsers *bool) MappingMode {
	if hostUsers != nil && !*hostUsers {
		return MappingIsolated
	}
	return MappingHostShared
}
