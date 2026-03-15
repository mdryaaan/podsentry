// Package userns inspects a Pod's hostUsers configuration and explains its
// UID/GID mapping implications, without needing a live cluster.
package userns

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaan/podsentry/internal/utils"
)

// Report is the outcome of inspecting a pod's user namespace configuration.
type Report struct {
	HostUsers    *bool
	Mode         MappingMode
	Implications []string
	Conflicts    []string
}

// Inspect analyzes the pod spec's hostUsers field and returns a report
// describing the resulting UID/GID mapping and any configuration that
// conflicts with running in an isolated user namespace.
func Inspect(spec corev1.PodSpec) Report {
	mode := Mode(spec.HostUsers)
	return Report{
		HostUsers:    spec.HostUsers,
		Mode:         mode,
		Implications: Implications(mode),
		Conflicts:    DetectConflicts(spec),
	}
}

// DetectConflicts returns descriptions of settings that are incompatible
// with running the pod in an isolated user namespace. Kubernetes requires
// hostUsers: true whenever a pod uses host namespaces, a privileged
// container, or a hostPath volume, since those all depend on the
// container's UID mapping one-to-one onto the host.
func DetectConflicts(spec corev1.PodSpec) []string {
	if Mode(spec.HostUsers) != MappingIsolated {
		return nil
	}

	var conflicts []string

	if spec.HostNetwork {
		conflicts = append(conflicts, "hostUsers is false but spec.hostNetwork is true")
	}
	if spec.HostPID {
		conflicts = append(conflicts, "hostUsers is false but spec.hostPID is true")
	}
	if spec.HostIPC {
		conflicts = append(conflicts, "hostUsers is false but spec.hostIPC is true")
	}

	for _, name := range utils.HostPathVolumes(spec) {
		conflicts = append(conflicts, "hostUsers is false but volume \""+name+"\" mounts a hostPath")
	}

	for _, ref := range utils.AllContainers(spec) {
		sc := ref.Container.SecurityContext
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			conflicts = append(conflicts, "hostUsers is false but container \""+ref.Container.Name+"\" is privileged")
		}
	}

	return conflicts
}
