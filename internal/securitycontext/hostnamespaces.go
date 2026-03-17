package securitycontext

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaan/podsentry/internal/utils"
)

// HostNamespaceReport summarizes a pod's use of host namespaces and host
// ports.
type HostNamespaceReport struct {
	HostNetwork bool
	HostPID     bool
	HostIPC     bool
	HostPorts   []int32
}

// AnalyzeHostNamespaces reports which host namespaces a pod shares and
// which host ports its containers bind.
func AnalyzeHostNamespaces(spec corev1.PodSpec) HostNamespaceReport {
	return HostNamespaceReport{
		HostNetwork: spec.HostNetwork,
		HostPID:     spec.HostPID,
		HostIPC:     spec.HostIPC,
		HostPorts:   utils.HostPorts(spec),
	}
}
