package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/podsentry/internal/pss"
	"github.com/mdryaaan/podsentry/internal/report"
	"github.com/mdryaaan/podsentry/internal/securitycontext"
	"github.com/mdryaaan/podsentry/internal/userns"
)

var (
	inspectLevel     string
	inspectRecursive bool
	inspectExitCode  bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <path>",
	Short: "Run a combined PSS, user namespace and SecurityContext report",
	Long: `Runs the Pod Security Standards check, the hostUsers inspection, and the
SecurityContext audit together and merges the results into a single report
per pod.`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().StringVar(&inspectLevel, "level", "restricted", "target PSS level: privileged, baseline or restricted")
	inspectCmd.Flags().BoolVarP(&inspectRecursive, "recursive", "r", false, "recursively scan directories for pod manifests")
	inspectCmd.Flags().BoolVar(&inspectExitCode, "exit-code", false, "exit with a non-zero status if any pod fails any check")
	rootCmd.AddCommand(inspectCmd)
}

func runInspect(cmd *cobra.Command, args []string) error {
	level, err := pss.ParseLevel(inspectLevel)
	if err != nil {
		return err
	}

	results, err := loadPods(args[0], inspectRecursive)
	if err != nil {
		return err
	}

	var reports []report.PodReport
	for _, r := range results {
		pssResult := pss.Evaluate(r.Pod.Spec, level)
		usernsResult := userns.Inspect(r.Pod.Spec)
		secCtxResult := securitycontext.Analyze(r.Pod.Spec)

		reports = append(reports, report.PodReport{
			Path:    r.Path,
			PodName: podDisplayName(r.Pod),
			PSS:     report.BuildPSSSection(pssResult),
			UserNS:  report.BuildUserNSSection(usernsResult),
			SecCtx:  report.BuildSecCtxSection(secCtxResult),
		})
	}

	if jsonOutput {
		if err := report.WriteJSON(os.Stdout, reports); err != nil {
			return err
		}
	} else {
		for _, r := range reports {
			fmt.Fprintf(os.Stdout, "\n=== %s (%s) ===\n", r.PodName, r.Path)
			report.RenderPSSTable(os.Stdout, []report.PodReport{r})
			report.RenderUserNSTable(os.Stdout, []report.PodReport{r})
			report.RenderSecCtxTable(os.Stdout, []report.PodReport{r})
		}
		report.RenderSummary(os.Stdout, report.Summarize(reports))
	}

	if inspectExitCode {
		summary := report.Summarize(reports)
		if summary.Failed > 0 {
			os.Exit(1)
		}
	}

	return nil
}
