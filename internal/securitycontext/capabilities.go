package securitycontext

import corev1 "k8s.io/api/core/v1"

// CapabilityReport summarizes how a single container's Linux capabilities
// deviate from the safe baseline.
type CapabilityReport struct {
	Container       string
	DropsAll        bool
	Added           []string
	DisallowedAdded []string
}

var safeAddableCapabilities = map[string]bool{
	"NET_BIND_SERVICE": true,
}

// AnalyzeCapabilities inspects the container's capability configuration
// against the restricted-level safe set, where every capability must be
// dropped and only NET_BIND_SERVICE may be added back.
func AnalyzeCapabilities(c corev1.Container) CapabilityReport {
	report := CapabilityReport{Container: c.Name}

	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return report
	}

	caps := c.SecurityContext.Capabilities
	for _, d := range caps.Drop {
		if d == "ALL" {
			report.DropsAll = true
		}
	}

	for _, a := range caps.Add {
		report.Added = append(report.Added, string(a))
		if !safeAddableCapabilities[string(a)] {
			report.DisallowedAdded = append(report.DisallowedAdded, string(a))
		}
	}

	return report
}
