package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/podsentry/internal/report"
	"github.com/mdryaaan/podsentry/internal/userns"
)

var (
	usernsRecursive bool
	usernsExitCode  bool
)

var usernsCmd = &cobra.Command{
	Use:   "userns <path>",
	Short: "Inspect Pod user namespace (hostUsers) configuration",
	Long: `Inspects the hostUsers field on one or more Pod manifests and explains the
resulting UID/GID mapping, including any settings that conflict with
running the pod in an isolated user namespace.`,
	Args: cobra.ExactArgs(1),
	RunE: runUserNS,
}

func init() {
	usernsCmd.Flags().BoolVarP(&usernsRecursive, "recursive", "r", false, "recursively scan directories for pod manifests")
	usernsCmd.Flags().BoolVar(&usernsExitCode, "exit-code", false, "exit with a non-zero status if any pod has a conflict")
	rootCmd.AddCommand(usernsCmd)
}

func runUserNS(cmd *cobra.Command, args []string) error {
	results, err := loadPods(args[0], usernsRecursive)
	if err != nil {
		return err
	}

	var reports []report.PodReport
	for _, r := range results {
		result := userns.Inspect(r.Pod.Spec)
		reports = append(reports, report.PodReport{
			Path:    r.Path,
			PodName: podDisplayName(r.Pod),
			UserNS:  report.BuildUserNSSection(result),
		})
	}

	if jsonOutput {
		if err := report.WriteJSON(os.Stdout, reports); err != nil {
			return err
		}
	} else {
		report.RenderUserNSTable(os.Stdout, reports)
	}

	if usernsExitCode {
		for _, r := range reports {
			if r.HasFailures() {
				os.Exit(1)
			}
		}
	}

	return nil
}
