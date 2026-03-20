// Package report renders inspection results as colored tables for humans
// or JSON for CI pipelines.
package report

import (
	"github.com/mdryaan/podsentry/internal/pss"
	"github.com/mdryaan/podsentry/internal/securitycontext"
	"github.com/mdryaan/podsentry/internal/userns"
)

// PodReport is the full audit output for a single pod, combining whichever
// of the PSS, user namespace and security context sections were run.
type PodReport struct {
	Path    string         `json:"path"`
	PodName string         `json:"podName"`
	PSS     *PSSSection    `json:"pss,omitempty"`
	UserNS  *UserNSSection `json:"userNamespace,omitempty"`
	SecCtx  *SecCtxSection `json:"securityContext,omitempty"`
}

// PSSSection is the Pod Security Standards portion of a report.
type PSSSection struct {
	TargetLevel string        `json:"targetLevel"`
	Compliant   bool          `json:"compliant"`
	Findings    []pss.Finding `json:"findings,omitempty"`
}

// UserNSSection is the user namespace portion of a report.
type UserNSSection struct {
	HostUsers    *bool    `json:"hostUsers"`
	Mode         string   `json:"mode"`
	Implications []string `json:"implications,omitempty"`
	Conflicts    []string `json:"conflicts,omitempty"`
}

// SecCtxSection is the security context portion of a report.
type SecCtxSection struct {
	HostNetwork bool                             `json:"hostNetwork"`
	HostPID     bool                             `json:"hostPID"`
	HostIPC     bool                             `json:"hostIPC"`
	HostPorts   []int32                          `json:"hostPorts,omitempty"`
	Containers  []securitycontext.ContainerAudit `json:"containers"`
}

// BuildPSSSection converts a pss.Result into its report representation.
func BuildPSSSection(result pss.Result) *PSSSection {
	return &PSSSection{
		TargetLevel: result.TargetLevel.String(),
		Compliant:   result.Compliant,
		Findings:    result.Findings,
	}
}

// BuildUserNSSection converts a userns.Report into its report
// representation.
func BuildUserNSSection(r userns.Report) *UserNSSection {
	return &UserNSSection{
		HostUsers:    r.HostUsers,
		Mode:         string(r.Mode),
		Implications: r.Implications,
		Conflicts:    r.Conflicts,
	}
}

// BuildSecCtxSection converts a securitycontext.PodAudit into its report
// representation.
func BuildSecCtxSection(a securitycontext.PodAudit) *SecCtxSection {
	return &SecCtxSection{
		HostNetwork: a.HostNamespace.HostNetwork,
		HostPID:     a.HostNamespace.HostPID,
		HostIPC:     a.HostNamespace.HostIPC,
		HostPorts:   a.HostNamespace.HostPorts,
		Containers:  a.Containers,
	}
}

// HasFailures reports whether the report contains any PSS non-compliance,
// user namespace conflicts, or security context warnings, for CI exit-code
// gating.
func (r PodReport) HasFailures() bool {
	if r.PSS != nil && !r.PSS.Compliant {
		return true
	}
	if r.UserNS != nil && len(r.UserNS.Conflicts) > 0 {
		return true
	}
	if r.SecCtx != nil {
		for _, c := range r.SecCtx.Containers {
			if len(c.Warnings) > 0 {
				return true
			}
		}
	}
	return false
}
