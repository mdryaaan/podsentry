package utils

import corev1 "k8s.io/api/core/v1"

// UsesHostNamespace reports whether the pod spec opts into any host
// namespace: network, PID or IPC.
func UsesHostNamespace(spec corev1.PodSpec) bool {
	return spec.HostNetwork || spec.HostPID || spec.HostIPC
}

// HostPorts returns every host port declared by any container in the pod,
// across init, app and ephemeral containers.
func HostPorts(spec corev1.PodSpec) []int32 {
	var ports []int32
	for _, ref := range AllContainers(spec) {
		for _, p := range ref.Container.Ports {
			if p.HostPort != 0 {
				ports = append(ports, p.HostPort)
			}
		}
	}
	return ports
}

// HostPathVolumes returns the names of volumes in the pod spec that mount
// a path from the host filesystem.
func HostPathVolumes(spec corev1.PodSpec) []string {
	var names []string
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			names = append(names, v.Name)
		}
	}
	return names
}

// PodSecurityContext returns the pod's SecurityContext, or an empty, non-nil
// value if none was set, so callers can dereference fields safely.
func PodSecurityContext(spec corev1.PodSpec) corev1.PodSecurityContext {
	if spec.SecurityContext == nil {
		return corev1.PodSecurityContext{}
	}
	return *spec.SecurityContext
}

// ContainerSecurityContext returns the container's SecurityContext, or an
// empty, non-nil value if none was set.
func ContainerSecurityContext(c corev1.Container) corev1.SecurityContext {
	if c.SecurityContext == nil {
		return corev1.SecurityContext{}
	}
	return *c.SecurityContext
}

// EffectiveRunAsNonRoot resolves runAsNonRoot for a container, falling back
// to the pod-level setting when the container does not override it.
func EffectiveRunAsNonRoot(pod corev1.PodSpec, c corev1.Container) *bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return c.SecurityContext.RunAsNonRoot
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.RunAsNonRoot
	}
	return nil
}

// EffectiveRunAsUser resolves runAsUser for a container, falling back to
// the pod-level setting when the container does not override it.
func EffectiveRunAsUser(pod corev1.PodSpec, c corev1.Container) *int64 {
	if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		return c.SecurityContext.RunAsUser
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.RunAsUser
	}
	return nil
}

// EffectiveSeccompProfile resolves the seccomp profile for a container,
// falling back to the pod-level profile when the container does not
// declare its own.
func EffectiveSeccompProfile(pod corev1.PodSpec, c corev1.Container) *corev1.SeccompProfile {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		return c.SecurityContext.SeccompProfile
	}
	if pod.SecurityContext != nil {
		return pod.SecurityContext.SeccompProfile
	}
	return nil
}
