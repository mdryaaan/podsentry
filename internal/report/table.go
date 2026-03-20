package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
)

func newTable(w io.Writer, headers []string) *tablewriter.Table {
	table := tablewriter.NewWriter(w)
	table.SetHeader(headers)
	table.SetAutoWrapText(false)
	table.SetRowLine(false)
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	return table
}

// RenderPSSTable writes a human-readable table summarizing PSS results for
// each pod.
func RenderPSSTable(w io.Writer, reports []PodReport) {
	table := newTable(w, []string{"POD", "PATH", "LEVEL", "STATUS", "FINDINGS"})

	for _, r := range reports {
		if r.PSS == nil {
			continue
		}
		table.Append([]string{
			r.PodName,
			r.Path,
			r.PSS.TargetLevel,
			StatusLabel(r.PSS.Compliant),
			fmt.Sprintf("%d", len(r.PSS.Findings)),
		})
	}
	table.Render()

	for _, r := range reports {
		if r.PSS == nil || r.PSS.Compliant {
			continue
		}
		fmt.Fprintf(w, "\n%s (%s)\n", r.PodName, r.Path)
		for _, f := range r.PSS.Findings {
			container := f.Container
			if container == "" {
				container = "-"
			}
			fmt.Fprintf(w, "  %s [%s/%s] %s: %s\n", WarnLabel(), f.Level, container, f.RuleID, f.Message)
		}
	}
}

// RenderUserNSTable writes a human-readable table summarizing hostUsers
// inspection results.
func RenderUserNSTable(w io.Writer, reports []PodReport) {
	table := newTable(w, []string{"POD", "PATH", "HOSTUSERS", "MODE", "CONFLICTS"})

	for _, r := range reports {
		if r.UserNS == nil {
			continue
		}
		hostUsers := "unset (default true)"
		if r.UserNS.HostUsers != nil {
			hostUsers = fmt.Sprintf("%t", *r.UserNS.HostUsers)
		}
		table.Append([]string{
			r.PodName,
			r.Path,
			hostUsers,
			r.UserNS.Mode,
			fmt.Sprintf("%d", len(r.UserNS.Conflicts)),
		})
	}
	table.Render()

	for _, r := range reports {
		if r.UserNS == nil {
			continue
		}
		fmt.Fprintf(w, "\n%s (%s)\n", r.PodName, r.Path)
		for _, line := range r.UserNS.Implications {
			fmt.Fprintf(w, "  %s %s\n", Dim("-"), line)
		}
		for _, c := range r.UserNS.Conflicts {
			fmt.Fprintf(w, "  %s %s\n", WarnLabel(), c)
		}
	}
}

// RenderSecCtxTable writes a human-readable table summarizing security
// context audit results.
func RenderSecCtxTable(w io.Writer, reports []PodReport) {
	table := newTable(w, []string{"POD", "CONTAINER", "PRIVILEGED", "ESCALATION", "NONROOT", "DROP ALL", "SECCOMP", "WARNINGS"})

	for _, r := range reports {
		if r.SecCtx == nil {
			continue
		}
		for _, c := range r.SecCtx.Containers {
			escalation := "unset"
			if c.Privilege.AllowPrivilegeEscalation != nil {
				escalation = fmt.Sprintf("%t", *c.Privilege.AllowPrivilegeEscalation)
			}
			nonRoot := "unset"
			if c.Privilege.RunAsNonRoot != nil {
				nonRoot = fmt.Sprintf("%t", *c.Privilege.RunAsNonRoot)
			}
			seccomp := "unset"
			if c.Seccomp.Set {
				seccomp = string(c.Seccomp.ProfileType)
			}
			table.Append([]string{
				r.PodName,
				c.Container,
				fmt.Sprintf("%t", c.Privilege.Privileged),
				escalation,
				nonRoot,
				fmt.Sprintf("%t", c.Capabilities.DropsAll),
				seccomp,
				fmt.Sprintf("%d", len(c.Warnings)),
			})
		}
	}
	table.Render()

	for _, r := range reports {
		if r.SecCtx == nil {
			continue
		}
		for _, c := range r.SecCtx.Containers {
			if len(c.Warnings) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n%s / %s\n", r.PodName, c.Container)
			for _, warning := range c.Warnings {
				fmt.Fprintf(w, "  %s %s\n", WarnLabel(), warning)
			}
		}
	}
}

// RenderSummary writes an aggregate pass/fail line for a batch of reports.
func RenderSummary(w io.Writer, s Summary) {
	fmt.Fprintf(w, "\n%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(w, "%d pods scanned, %d passed, %d failed\n", s.Total, s.Passed, s.Failed)
}
