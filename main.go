package main

import (
	"fmt"
	"log"
	"orbit/cmd"
	"orbit/pkg/dns_zones"
	"orbit/pkg/reporting"
	"os"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("[!] Failed to parse initialise arguments: ", err.Error())
		log.Print("[!] Exiting...")
		os.Exit(1)
	}
	inputFile, _ := cmd.RootCmd.PersistentFlags().GetString("file")

	zones := dns_zones.DNSZones{}
	rep := reporting.Reporting{}
	results, err := zones.GetZoneData(inputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	listArecs, _ := cmd.RootCmd.PersistentFlags().GetBool("a-records")
	if listArecs {
		rep.ListAandAAARecords(results)
	}

	listCNAMEs, _ := cmd.RootCmd.PersistentFlags().GetBool("cname")
	if listCNAMEs {
		rep.ListCNames(results)
	}

	showFQDNs, _ := cmd.RootCmd.PersistentFlags().GetBool("targets")
	if showFQDNs {
		rep.GetFQDNTargets(results)
	}

	showIps, _ := cmd.RootCmd.PersistentFlags().GetBool("ips")
	if showIps {
		rep.GetIPAddressTargets(results)
	}

}
