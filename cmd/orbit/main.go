package main

import (
	"fmt"
	"log"
	"net"
	"orbit/cmd"
	"orbit/internal/file_management"
	"orbit/models"
	"orbit/pkg/dns_analysers"
	"orbit/pkg/ip_addresses"
	"orbit/pkg/reporting"
	"orbit/pkg/zone_files"
	"os"
)

var (
	zones = zone_files.DNSZones{}
	ipa   = ip_addresses.IPAddresses{}
	rep   = reporting.Reporting{}
	dna   = dns_analysers.DNSAnalyser{}
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("[!] Failed to parse initialise arguments: ", err.Error())
		log.Print("[!] Exiting...")
		os.Exit(1)
	}

	var assessment = models.ASMAssessment{}

	zf, _ := cmd.RootCmd.PersistentFlags().GetString("iZ")
	if zf != "" {
		zfResults, err := zones.GetZoneData(zf)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		assessment.Zones = zfResults
	}

	ips, _ := cmd.RootCmd.PersistentFlags().GetString("iI")
	if ips != "" {
		existingIps, err := file_management.ReadFileLines(ips)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		var ipMod models.IPCollection
		for _, ip := range existingIps {
			if i := net.ParseIP(ip); i != nil {
				if ipa.IsIPv4(i) {
					ipMod.IPv4 = append(ipMod.IPv4, i)
				} else {
					ipMod.IPv6 = append(ipMod.IPv6, i)
				}
			}
		}
		assessment.IPAddresses = ipMod
	}

	urlList, _ := cmd.RootCmd.PersistentFlags().GetString("iU")
	if urlList != "" {
		existingUrls, err := file_management.ReadFileLines(urlList)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, url := range existingUrls {
			assessment.Domains = append(assessment.Domains, url)
		}
	}

	for _, zone := range assessment.Zones {
		aliases := rep.CNAMERecords(&zone)
		if aliases != nil && len(aliases) > 0 {
			assessment.Aliases = append(assessment.Aliases, aliases)
		}

		o := zone.Origin
		if res, _ := dna.DNSSECEnabled(o); res {
			rep.AddMissingDNSSec(o, &assessment)
		}
		ip := net.ParseIP(o)
		if ip != nil {
			if !ipa.IPExistsIn(ip, &assessment) {
				ipa.AddIPtoAddresses(ip, &assessment)
			}
		} else {
			targets := rep.GetFQDNTargets(&zone)
			for _, t := range targets {
				rep.AddURLToAsmDomains(t, &assessment)
			}
		}
	}

	fmt.Println(assessment)

	//results, err := zones.GetZoneData(zf)
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}
	//listArecords, _ := cmd.RootCmd.PersistentFlags().GetBool("a-records")
	//if listArecords {
	//	for _, result := range results {
	//		rep.AandAAARecords(result)
	//	}
	//}
	//
	//listCNAMEs, _ := cmd.RootCmd.PersistentFlags().GetBool("cnames")
	//if listCNAMEs {
	//	for _, result := range results {
	//		rep.CNAMERecords(result)
	//	}
	//}
	//
	//showFQDNs, _ := cmd.RootCmd.PersistentFlags().GetBool("targets")
	//if showFQDNs {
	//	for _, result := range results {
	//		fqdns := rep.GetFQDNTargets(result)
	//		for _, f := range fqdns {
	//			fmt.Println(f)
	//		}
	//	}
	//
	//}

	//showIps, _ := cmd.RootCmd.PersistentFlags().GetBool("ips")
	//if showIps {
	//	for _, rec := range results {
	//		ips := ipa.IPAddressesFromZones(rec)
	//		if len(ips.IPv4) > 0 {
	//			for _, ip := range ips.IPv4 {
	//				fmt.Println(ip)
	//			}
	//		}
	//		if len(ips.IPv6) > 0 {
	//			for _, ip := range ips.IPv6 {
	//				fmt.Println(ip)
	//			}
	//		}
	//	}
	//}

}
