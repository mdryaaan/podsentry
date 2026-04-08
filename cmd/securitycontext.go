package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/podsentry/internal/report"
	"github.com/mdryaaan/podsentry/internal/securitycontext"
)

var (
	secCtxRecursive bool
	secCtxExitCode  bool
)

var securityContextCmd = &cobra.Command{
	Use:   "securitycontext <path>",
	Short: "Audit Pod and container SecurityContext settings",
	Long: `Audits capabilities, privilege escalation, runAsNonRoot/runAsUser/runAsGroup,
seccomp profiles, and host namespace usage for one or more Pod manifests.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityContext,
}

func init() {
	securityContextCmd.Flags().BoolVarP(&secCtxRecursive, "recursive", "r", false, "recursively scan directories for pod manifests")
	securityContextCmd.Flags().BoolVar(&secCtxExitCode, "exit-code", false, "exit with a non-zero status if any container has warnings")
	rootCmd.AddCommand(securityContextCmd)
}

func runSecurityContext(cmd *cobra.Command, args []string) error {
	results, err := loadPods(args[0], secCtxRecursive)
	if err != nil {
		return err
	}

	var reports []report.PodReport
	for _, r := range results {
		audit := securitycontext.Analyze(r.Pod.Spec)
		reports = append(reports, report.PodReport{
			Path:    r.Path,
			PodName: podDisplayName(r.Pod),
			SecCtx:  report.BuildSecCtxSection(audit),
		})
	}

	if jsonOutput {
		if err := report.WriteJSON(os.Stdout, reports); err != nil {
			return err
		}
	} else {
		report.RenderSecCtxTable(os.Stdout, reports)
	}

	if secCtxExitCode {
		for _, r := range reports {
			if r.HasFailures() {
				os.Exit(1)
			}
		}
	}

	return nil
}
