package securitycontext

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaan/podsentry/internal/utils"
)

// SeccompReport summarizes the effective seccomp profile for a container.
type SeccompReport struct {
	Container        string
	ProfileType      corev1.SeccompProfileType
	LocalhostProfile string
	Set              bool
}

// AnalyzeSeccomp resolves the effective seccomp profile for a container,
// falling back to the pod-level profile when the container does not
// declare its own.
func AnalyzeSeccomp(spec corev1.PodSpec, c corev1.Container) SeccompReport {
	profile := utils.EffectiveSeccompProfile(spec, c)
	if profile == nil {
		return SeccompReport{Container: c.Name}
	}

	report := SeccompReport{Container: c.Name, ProfileType: profile.Type, Set: true}
	if profile.LocalhostProfile != nil {
		report.LocalhostProfile = *profile.LocalhostProfile
	}
	return report
}
