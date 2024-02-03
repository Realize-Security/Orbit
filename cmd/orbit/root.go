package orbit

import (
	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use:   "orbit-cli",
		Short: "Analyser for DNS records",
		Long:  "Reads records from Zone files.",
	}
)

func Execute() error {
	return RootCmd.Execute()
}

func init() {
	RootCmd.PersistentFlags().StringP("file", "f", "", "Input file path.")
}
