// Package securitycontext audits container and pod SecurityContext
// settings independently of the Pod Security Standards: capabilities,
// privilege escalation, seccomp profiles and host namespace usage.
package securitycontext

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaaan/podsentry/internal/utils"
)

// ContainerAudit bundles every security context finding for a single
// container.
type ContainerAudit struct {
	Container    string
	Capabilities CapabilityReport
	Privilege    PrivilegeReport
	Seccomp      SeccompReport
	Warnings     []string
}

// PodAudit is the full security context audit for a pod, covering every
// container plus pod-wide host namespace usage.
type PodAudit struct {
	Containers    []ContainerAudit
	HostNamespace HostNamespaceReport
}

// Analyze runs every security context check against the pod spec.
func Analyze(spec corev1.PodSpec) PodAudit {
	audit := PodAudit{HostNamespace: AnalyzeHostNamespaces(spec)}

	for _, ref := range utils.AllContainers(spec) {
		c := ref.Container
		containerAudit := ContainerAudit{
			Container:    c.Name,
			Capabilities: AnalyzeCapabilities(c),
			Privilege:    AnalyzePrivilege(spec, c),
			Seccomp:      AnalyzeSeccomp(spec, c),
		}
		containerAudit.Warnings = warningsFor(containerAudit)
		audit.Containers = append(audit.Containers, containerAudit)
	}

	return audit
}

func warningsFor(a ContainerAudit) []string {
	var warnings []string

	if a.Privilege.Privileged {
		warnings = append(warnings, "container runs as privileged")
	}
	if a.Privilege.AllowPrivilegeEscalation == nil {
		warnings = append(warnings, "allowPrivilegeEscalation is unset, defaults to true")
	} else if *a.Privilege.AllowPrivilegeEscalation {
		warnings = append(warnings, "allowPrivilegeEscalation is true")
	}
	if a.Privilege.RunAsNonRoot == nil || !*a.Privilege.RunAsNonRoot {
		warnings = append(warnings, "runAsNonRoot is not set to true")
	}
	if a.Privilege.RunAsUser != nil && *a.Privilege.RunAsUser == 0 {
		warnings = append(warnings, "runAsUser is explicitly 0")
	}
	if !a.Capabilities.DropsAll {
		warnings = append(warnings, "capabilities.drop does not include ALL")
	}
	if len(a.Capabilities.DisallowedAdded) > 0 {
		warnings = append(warnings, "adds capabilities beyond the safe set")
	}
	if !a.Seccomp.Set {
		warnings = append(warnings, "no seccomp profile configured")
	} else if a.Seccomp.ProfileType == corev1.SeccompProfileTypeUnconfined {
		warnings = append(warnings, "seccomp profile is Unconfined")
	}

	return warnings
}
