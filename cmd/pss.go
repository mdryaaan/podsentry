package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/podsentry/internal/pss"
	"github.com/mdryaaan/podsentry/internal/report"
)

var (
	pssLevel     string
	pssRecursive bool
	pssExitCode  bool
)

var pssCmd = &cobra.Command{
	Use:   "pss <path>",
	Short: "Check Pods against the official Pod Security Standards",
	Long: `Evaluates one or more Pod manifests against the Kubernetes Pod Security
Standards: Privileged, Baseline or Restricted. A pod is compliant with a
level only if it satisfies every rule at that level and below.`,
	Args: cobra.ExactArgs(1),
	RunE: runPSS,
}

func init() {
	pssCmd.Flags().StringVar(&pssLevel, "level", "restricted", "target level: privileged, baseline or restricted")
	pssCmd.Flags().BoolVarP(&pssRecursive, "recursive", "r", false, "recursively scan directories for pod manifests")
	pssCmd.Flags().BoolVar(&pssExitCode, "exit-code", false, "exit with a non-zero status if any pod is non-compliant")
	rootCmd.AddCommand(pssCmd)
}

func runPSS(cmd *cobra.Command, args []string) error {
	level, err := pss.ParseLevel(pssLevel)
	if err != nil {
		return err
	}

	results, err := loadPods(args[0], pssRecursive)
	if err != nil {
		return err
	}

	var reports []report.PodReport
	for _, r := range results {
		result := pss.Evaluate(r.Pod.Spec, level)
		reports = append(reports, report.PodReport{
			Path:    r.Path,
			PodName: podDisplayName(r.Pod),
			PSS:     report.BuildPSSSection(result),
		})
	}

	if err := emitPSSReports(reports); err != nil {
		return err
	}

	if pssExitCode {
		summary := report.Summarize(reports)
		if summary.Failed > 0 {
			os.Exit(1)
		}
	}

	return nil
}

func emitPSSReports(reports []report.PodReport) error {
	if jsonOutput {
		return report.WriteJSON(os.Stdout, reports)
	}
	report.RenderPSSTable(os.Stdout, reports)
	report.RenderSummary(os.Stdout, report.Summarize(reports))
	return nil
}
