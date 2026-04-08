package securitycontext

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaaan/podsentry/internal/utils"
)

// PrivilegeReport summarizes a single container's privilege-related
// security context settings.
type PrivilegeReport struct {
	Container                string
	Privileged               bool
	AllowPrivilegeEscalation *bool
	RunAsNonRoot             *bool
	RunAsUser                *int64
	RunAsGroup               *int64
}

// AnalyzePrivilege extracts the privilege-related settings for a container,
// resolving runAsNonRoot, runAsUser and runAsGroup against the pod-level
// defaults when the container does not override them.
func AnalyzePrivilege(spec corev1.PodSpec, c corev1.Container) PrivilegeReport {
	report := PrivilegeReport{
		Container:    c.Name,
		RunAsNonRoot: utils.EffectiveRunAsNonRoot(spec, c),
		RunAsUser:    utils.EffectiveRunAsUser(spec, c),
	}

	if c.SecurityContext != nil {
		if c.SecurityContext.Privileged != nil {
			report.Privileged = *c.SecurityContext.Privileged
		}
		report.AllowPrivilegeEscalation = c.SecurityContext.AllowPrivilegeEscalation
		if c.SecurityContext.RunAsGroup != nil {
			report.RunAsGroup = c.SecurityContext.RunAsGroup
		}
	}
	if report.RunAsGroup == nil && spec.SecurityContext != nil {
		report.RunAsGroup = spec.SecurityContext.RunAsGroup
	}

	return report
}
