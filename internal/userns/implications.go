package userns

// Implications returns a human-readable explanation of what the given
// mapping mode means for UID mapping and container-escape blast radius.
func Implications(mode MappingMode) []string {
	switch mode {
	case MappingIsolated:
		return []string{
			"container UIDs and GIDs are remapped to an unprivileged, pod-specific range on the host",
			"a process running as UID 0 inside the container is not UID 0 on the host",
			"container-to-host privilege escalation via a kernel or runtime bug is significantly reduced in impact",
			"most privileged and hostPath-sensitive workloads are incompatible with an isolated user namespace",
		}
	case MappingHostShared:
		return []string{
			"container UIDs and GIDs map one-to-one onto host UIDs and GIDs",
			"a process running as UID 0 inside the container is UID 0 on the host",
			"a container escape yields host root, since there is no UID remapping boundary",
		}
	default:
		return nil
	}
}
