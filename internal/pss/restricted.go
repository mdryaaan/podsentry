package pss

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaaan/podsentry/internal/utils"
)

var restrictedAllowedVolumeTypes = map[string]bool{
	"configMap":             true,
	"csi":                   true,
	"downwardAPI":           true,
	"emptyDir":              true,
	"ephemeral":             true,
	"persistentVolumeClaim": true,
	"projected":             true,
	"secret":                true,
}

func volumeTypeName(v corev1.Volume) string {
	switch {
	case v.ConfigMap != nil:
		return "configMap"
	case v.CSI != nil:
		return "csi"
	case v.DownwardAPI != nil:
		return "downwardAPI"
	case v.EmptyDir != nil:
		return "emptyDir"
	case v.Ephemeral != nil:
		return "ephemeral"
	case v.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case v.Projected != nil:
		return "projected"
	case v.Secret != nil:
		return "secret"
	default:
		return "other"
	}
}

// RestrictedRules returns the rules enforced at the Restricted Pod Security
// Standard level. Restricted builds on Baseline and additionally closes
// off the most common paths to privilege escalation inside a container.
func RestrictedRules() []Rule {
	return []Rule{
		{
			ID:      "restricted-volume-types",
			Level:   LevelRestricted,
			Message: "volumes must be one of the restricted set of types",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, v := range spec.Volumes {
					name := volumeTypeName(v)
					if !restrictedAllowedVolumeTypes[name] {
						findings = append(findings, violation("restricted-volume-types", LevelRestricted, "", fmt.Sprintf("volume %q uses disallowed type %q", v.Name, name)))
					}
				}
				return findings
			},
		},
		{
			ID:      "restricted-privilege-escalation",
			Level:   LevelRestricted,
			Message: "containers must set allowPrivilegeEscalation: false",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					sc := ref.Container.SecurityContext
					if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
						findings = append(findings, violation("restricted-privilege-escalation", LevelRestricted, ref.Container.Name, "allowPrivilegeEscalation must be explicitly set to false"))
					}
				}
				return findings
			},
		},
		{
			ID:      "restricted-run-as-non-root",
			Level:   LevelRestricted,
			Message: "containers must run as a non-root user",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					nonRoot := utils.EffectiveRunAsNonRoot(spec, ref.Container)
					if nonRoot == nil || !*nonRoot {
						findings = append(findings, violation("restricted-run-as-non-root", LevelRestricted, ref.Container.Name, "runAsNonRoot must resolve to true at the pod or container level"))
					}
				}
				return findings
			},
		},
		{
			ID:      "restricted-run-as-user",
			Level:   LevelRestricted,
			Message: "containers must not explicitly run as UID 0",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					uid := utils.EffectiveRunAsUser(spec, ref.Container)
					if uid != nil && *uid == 0 {
						findings = append(findings, violation("restricted-run-as-user", LevelRestricted, ref.Container.Name, "runAsUser is explicitly set to 0"))
					}
				}
				return findings
			},
		},
		{
			ID:      "restricted-seccomp",
			Level:   LevelRestricted,
			Message: "containers must use a RuntimeDefault or Localhost seccomp profile",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					profile := utils.EffectiveSeccompProfile(spec, ref.Container)
					if profile == nil {
						findings = append(findings, violation("restricted-seccomp", LevelRestricted, ref.Container.Name, "no seccomp profile set at pod or container level"))
						continue
					}
					if profile.Type != corev1.SeccompProfileTypeRuntimeDefault && profile.Type != corev1.SeccompProfileTypeLocalhost {
						findings = append(findings, violation("restricted-seccomp", LevelRestricted, ref.Container.Name, fmt.Sprintf("seccomp profile type %s is not allowed", profile.Type)))
					}
				}
				return findings
			},
		},
		{
			ID:      "restricted-capabilities",
			Level:   LevelRestricted,
			Message: "containers must drop ALL capabilities and may only add back NET_BIND_SERVICE",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					sc := ref.Container.SecurityContext
					if sc == nil || sc.Capabilities == nil || !dropsAll(sc.Capabilities.Drop) {
						findings = append(findings, violation("restricted-capabilities", LevelRestricted, ref.Container.Name, "container must set capabilities.drop: [ALL]"))
						continue
					}
					for _, cap := range sc.Capabilities.Add {
						if cap != "NET_BIND_SERVICE" {
							findings = append(findings, violation("restricted-capabilities", LevelRestricted, ref.Container.Name, fmt.Sprintf("adds capability %s, only NET_BIND_SERVICE may be added back", cap)))
						}
					}
				}
				return findings
			},
		},
	}
}

func dropsAll(dropped []corev1.Capability) bool {
	for _, c := range dropped {
		if c == "ALL" {
			return true
		}
	}
	return false
}
