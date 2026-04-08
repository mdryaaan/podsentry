package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/mdryaaan/podsentry/pkg/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print podsentry version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		info := version.Info{
			Version:   version.Version,
			Commit:    version.Commit,
			BuildDate: version.BuildDate,
			GoVersion: runtime.Version(),
			Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}
		fmt.Println(info.String())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
