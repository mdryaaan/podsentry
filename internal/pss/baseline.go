package pss

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaan/podsentry/internal/utils"
)

// baselineAllowedCapabilities is the default capability set every
// container is granted by the container runtime. Baseline permits
// containers to add these back explicitly but nothing beyond them.
var baselineAllowedCapabilities = map[string]bool{
	"AUDIT_WRITE":      true,
	"CHOWN":            true,
	"DAC_OVERRIDE":     true,
	"FOWNER":           true,
	"FSETID":           true,
	"KILL":             true,
	"MKNOD":            true,
	"NET_BIND_SERVICE": true,
	"SETFCAP":          true,
	"SETGID":           true,
	"SETPCAP":          true,
	"SETUID":           true,
	"SYS_CHROOT":       true,
}

var baselineAllowedSysctls = map[string]bool{
	"kernel.shm_rmid_forced":              true,
	"net.ipv4.ip_local_port_range":        true,
	"net.ipv4.ip_unprivileged_port_start": true,
	"net.ipv4.tcp_syncookies":             true,
	"net.ipv4.ping_group_range":           true,
	"net.ipv4.ip_local_reserved_ports":    true,
}

var baselineAllowedSELinuxTypes = map[string]bool{
	"":                 true,
	"container_t":      true,
	"container_init_t": true,
	"container_kvm_t":  true,
}

// BaselineRules returns the rules enforced at the Baseline Pod Security
// Standard level, matching the upstream Kubernetes definition: it prevents
// known privilege escalations while remaining compatible with common
// containerized workloads.
func BaselineRules() []Rule {
	return []Rule{
		{
			ID:      "baseline-privileged-containers",
			Level:   LevelBaseline,
			Message: "containers must not run as privileged",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					sc := ref.Container.SecurityContext
					if sc != nil && sc.Privileged != nil && *sc.Privileged {
						findings = append(findings, violation("baseline-privileged-containers", LevelBaseline, ref.Container.Name, "container sets securityContext.privileged: true"))
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-host-namespaces",
			Level:   LevelBaseline,
			Message: "pod must not share the host network, PID or IPC namespace",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				if spec.HostNetwork {
					findings = append(findings, violation("baseline-host-namespaces", LevelBaseline, "", "spec.hostNetwork is true"))
				}
				if spec.HostPID {
					findings = append(findings, violation("baseline-host-namespaces", LevelBaseline, "", "spec.hostPID is true"))
				}
				if spec.HostIPC {
					findings = append(findings, violation("baseline-host-namespaces", LevelBaseline, "", "spec.hostIPC is true"))
				}
				return findings
			},
		},
		{
			ID:      "baseline-host-ports",
			Level:   LevelBaseline,
			Message: "containers must not bind a host port",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					for _, p := range ref.Container.Ports {
						if p.HostPort != 0 {
							findings = append(findings, violation("baseline-host-ports", LevelBaseline, ref.Container.Name, fmt.Sprintf("container declares hostPort %d", p.HostPort)))
						}
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-hostpath-volumes",
			Level:   LevelBaseline,
			Message: "pod must not mount a hostPath volume",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, name := range utils.HostPathVolumes(spec) {
					findings = append(findings, violation("baseline-hostpath-volumes", LevelBaseline, "", fmt.Sprintf("volume %q mounts a hostPath", name)))
				}
				return findings
			},
		},
		{
			ID:      "baseline-capabilities",
			Level:   LevelBaseline,
			Message: "containers must not add capabilities beyond the default safe set",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					sc := ref.Container.SecurityContext
					if sc == nil || sc.Capabilities == nil {
						continue
					}
					for _, cap := range sc.Capabilities.Add {
						if !baselineAllowedCapabilities[string(cap)] {
							findings = append(findings, violation("baseline-capabilities", LevelBaseline, ref.Container.Name, fmt.Sprintf("adds disallowed capability %s", cap)))
						}
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-proc-mount",
			Level:   LevelBaseline,
			Message: "containers must use the default /proc mount type",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				for _, ref := range utils.AllContainers(spec) {
					sc := ref.Container.SecurityContext
					if sc != nil && sc.ProcMount != nil && *sc.ProcMount != corev1.DefaultProcMount {
						findings = append(findings, violation("baseline-proc-mount", LevelBaseline, ref.Container.Name, fmt.Sprintf("procMount is %s, expected Default", *sc.ProcMount)))
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-selinux",
			Level:   LevelBaseline,
			Message: "SELinux type must be unset or a recognized container type, user and role must be unset",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				check := func(opts *corev1.SELinuxOptions, container string) {
					if opts == nil {
						return
					}
					if opts.User != "" || opts.Role != "" {
						findings = append(findings, violation("baseline-selinux", LevelBaseline, container, "seLinuxOptions sets user or role"))
					}
					if !baselineAllowedSELinuxTypes[opts.Type] {
						findings = append(findings, violation("baseline-selinux", LevelBaseline, container, fmt.Sprintf("seLinuxOptions.type %q is not allowed", opts.Type)))
					}
				}

				if spec.SecurityContext != nil {
					check(spec.SecurityContext.SELinuxOptions, "")
				}
				for _, ref := range utils.AllContainers(spec) {
					if ref.Container.SecurityContext != nil {
						check(ref.Container.SecurityContext.SELinuxOptions, ref.Container.Name)
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-sysctls",
			Level:   LevelBaseline,
			Message: "sysctls must be limited to the default safe set",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				if spec.SecurityContext == nil {
					return nil
				}
				for _, sc := range spec.SecurityContext.Sysctls {
					if !baselineAllowedSysctls[sc.Name] {
						findings = append(findings, violation("baseline-sysctls", LevelBaseline, "", fmt.Sprintf("sysctl %q is not in the default safe set", sc.Name)))
					}
				}
				return findings
			},
		},
		{
			ID:      "baseline-apparmor",
			Level:   LevelBaseline,
			Message: "AppArmor profile must not be unconfined",
			Check: func(spec corev1.PodSpec) []Finding {
				var findings []Finding
				if spec.SecurityContext != nil && spec.SecurityContext.AppArmorProfile != nil && spec.SecurityContext.AppArmorProfile.Type == corev1.AppArmorProfileTypeUnconfined {
					findings = append(findings, violation("baseline-apparmor", LevelBaseline, "", "pod securityContext.appArmorProfile.type is Unconfined"))
				}
				for _, ref := range utils.AllContainers(spec) {
					if ref.Container.SecurityContext != nil && ref.Container.SecurityContext.AppArmorProfile != nil && ref.Container.SecurityContext.AppArmorProfile.Type == corev1.AppArmorProfileTypeUnconfined {
						findings = append(findings, violation("baseline-apparmor", LevelBaseline, ref.Container.Name, "securityContext.appArmorProfile.type is Unconfined"))
					}
				}
				return findings
			},
		},
	}
}
