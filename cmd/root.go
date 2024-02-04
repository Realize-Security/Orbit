package cmd

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
	RootCmd.PersistentFlags().BoolP("a-records", "a", false, "Print A and AAA records.")
	RootCmd.PersistentFlags().BoolP("cname", "c", false, "Print CNAME records.")
	RootCmd.PersistentFlags().BoolP("targets", "t", false, "Created an FQDN target list. Uses CNAME and A/AAA.")
	RootCmd.PersistentFlags().BoolP("ips", "i", false, "Created target list. Uses IPv4 and IPv6 values.")
}
