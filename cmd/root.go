// Package cmd wires up the podsentry CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"

	"github.com/mdryaan/podsentry/internal/loader"
)

var jsonOutput bool

var rootCmd = &cobra.Command{
	Use:   "podsentry",
	Short: "Static security auditing for Kubernetes Pod specs",
	Long: `podsentry statically analyzes Kubernetes Pod YAML manifests for security
posture: Pod Security Standards compliance, user namespace configuration,
and SecurityContext hardening. It works entirely offline against files on
disk, no cluster or admission webhook required.`,
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output results as JSON instead of a table")
}

func loadPods(path string, recursive bool) ([]loader.Result, error) {
	results, issues, err := loader.Load(path, recursive)
	if err != nil {
		return nil, fmt.Errorf("loading pods from %q: %w", path, err)
	}

	for _, issue := range issues {
		fmt.Fprintf(os.Stderr, "skipping %s\n", issue.String())
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no pod manifests found at %q", path)
	}

	return results, nil
}

func podDisplayName(pod *corev1.Pod) string {
	if pod.Name != "" {
		return pod.Name
	}
	return "(unnamed)"
}
