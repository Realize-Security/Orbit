package main

import (
	"fmt"
	"log"
	"orbit/cmd"
	"orbit/pkg/ip_addresses"
	"orbit/pkg/reporting"
	"orbit/pkg/zone_files"
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

	zones := zone_files.DNSZones{}
	rep := reporting.Reporting{}
	ipa := ip_addresses.IPAddresses{}

	results, err := zones.GetZoneData(inputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	listArecords, _ := cmd.RootCmd.PersistentFlags().GetBool("a-records")
	if listArecords {
		for _, result := range results {
			rep.AandAAARecords(result)
		}
	}

	listCNAMEs, _ := cmd.RootCmd.PersistentFlags().GetBool("cnames")
	if listCNAMEs {
		for _, result := range results {
			rep.CNAMERecords(result)
		}
	}

	showFQDNs, _ := cmd.RootCmd.PersistentFlags().GetBool("targets")
	if showFQDNs {
		for _, result := range results {
			fqdns := rep.GetFQDNTargets(result)
			for _, f := range fqdns {
				fmt.Println(f)
			}
		}

	}

	showIps, _ := cmd.RootCmd.PersistentFlags().GetBool("ips")
	if showIps {
		for _, rec := range results {
			ips := ipa.IPAddressesFromZones(rec)
			if len(ips.IPv4) > 0 {
				for _, ip := range ips.IPv4 {
					fmt.Println(ip)
				}
			}
			if len(ips.IPv6) > 0 {
				for _, ip := range ips.IPv6 {
					fmt.Println(ip)
				}
			}
		}
	}

}
