package cmd

import (
	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use:   "orbit-cli",
		Short: "Attack Surface Mapping Engine.",
	}
)

func Execute() error {
	return RootCmd.Execute()
}

func init() {
	RootCmd.PersistentFlags().String("iZ", "", "Input is .zone file or directory.")
	RootCmd.PersistentFlags().String("iI", "", "Input file containing IP addresses.")
	RootCmd.PersistentFlags().String("iU", "", "Input file containing URLs.")
	//RootCmd.PersistentFlags().BoolP("a-records", "a", false, "Print A and AAA records.")
	//RootCmd.PersistentFlags().BoolP("cnames", "c", false, "Print CNAME records.")
	//RootCmd.PersistentFlags().BoolP("targets", "t", false, "Created an FQDN target list. Uses CNAME and A/AAA.")
	//RootCmd.PersistentFlags().BoolP("ips", "i", false, "Created target list. Uses IPv4 and IPv6 values.")
}
